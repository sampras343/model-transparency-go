#!/usr/bin/env bash

# Copyright 2025 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# test-otel.sh — validate that OTel tracing spans are exported to Jaeger.
#
# Prerequisites:
#   - The binary must be built with: go build -tags=otel -o model-signing ./cmd/model-signing
#   - Jaeger must be running:
#       docker run --rm -d --name jaeger -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one:latest
#
# Usage:
#   ./test-otel.sh [/path/to/model-signing]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Resolve binary
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]]; then
	BINARY="$1"
else
	BINARY="${SCRIPT_DIR}/model-signing"
fi

if [[ ! -x "${BINARY}" ]]; then
	echo "Error: binary not found or not executable: ${BINARY}"
	echo "Build with:  go build -tags=otel -o ${BINARY} ./cmd/model-signing"
	exit 1
fi

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
for util in curl jq openssl; do
	if ! command -v "${util}" &>/dev/null; then
		echo "Error: required utility '${util}' not found in PATH"
		exit 1
	fi
done

JAEGER_URL="http://localhost:16686"
OTEL_SERVICE="model-signing"

echo "=== OTel Tracing Integration Tests ==="
echo

# ---------------------------------------------------------------------------
# Check Jaeger reachability
# ---------------------------------------------------------------------------
echo "Checking Jaeger reachability at ${JAEGER_URL}..."
if ! curl -sf "${JAEGER_URL}/api/services" > /dev/null 2>&1; then
	echo "Error: Jaeger is not reachable at ${JAEGER_URL}"
	echo "Start with: docker run --rm -d --name jaeger -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one:latest"
	exit 1
fi
echo "Jaeger is reachable"
echo

# ---------------------------------------------------------------------------
# Temp directory and cleanup
# ---------------------------------------------------------------------------
TMPDIR=$(mktemp -d) || exit 1
cleanup() {
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

KEYSDIR="${TMPDIR}/keys"
mkdir -p "${KEYSDIR}"

# ---------------------------------------------------------------------------
# Create test model
# ---------------------------------------------------------------------------
MODELDIR="${TMPDIR}/model"
mkdir -p "${MODELDIR}"
echo "layer-weights" > "${MODELDIR}/weights.bin"
echo "model-config"  > "${MODELDIR}/config.json"

# ---------------------------------------------------------------------------
# Generate ECDSA P-256 key pair
# ---------------------------------------------------------------------------
echo "[Setup] Generating ECDSA P-256 key pair..."
openssl ecparam -name prime256v1 -genkey -noout -out "${KEYSDIR}/key.pem" 2>/dev/null
openssl ec -in "${KEYSDIR}/key.pem" -pubout -out "${KEYSDIR}/key-pub.pem" 2>/dev/null
echo

# =========================================================================
# PHASE 1: Key-based Sign and Verify
# =========================================================================
echo "=========================================="
echo "PHASE 1: Key-based Sign and Verify"
echo "=========================================="
echo

KEY_SIGFILE="${TMPDIR}/key-method.sig"

echo "[Key] Signing model..."
if ! "${BINARY}" sign key \
	--signature "${KEY_SIGFILE}" \
	--private-key "${KEYSDIR}/key.pem" \
	"${MODELDIR}"; then
	echo "Error: key sign failed"
	exit 1
fi
echo "[Key] Sign succeeded"

echo "[Key] Verifying model..."
if ! "${BINARY}" verify key \
	--signature "${KEY_SIGFILE}" \
	--public-key "${KEYSDIR}/key-pub.pem" \
	"${MODELDIR}"; then
	echo "Error: key verify failed"
	exit 1
fi
echo "[Key] Verify succeeded"
echo

# =========================================================================
# PHASE 2: Certificate-based Sign and Verify
# =========================================================================
echo "=========================================="
echo "PHASE 2: Certificate-based Sign and Verify"
echo "=========================================="
echo

CERT_SIGFILE="${TMPDIR}/cert-method.sig"
CERT_DIR="${SCRIPT_DIR}/keys/certificate"

echo "[Certificate] Signing model..."
if ! "${BINARY}" sign certificate \
	--signature "${CERT_SIGFILE}" \
	--private-key "${CERT_DIR}/signing-key.pem" \
	--signing-certificate "${CERT_DIR}/signing-key-cert.pem" \
	--certificate-chain "${CERT_DIR}/int-ca-cert.pem" \
	"${MODELDIR}"; then
	echo "Error: certificate sign failed"
	exit 1
fi
echo "[Certificate] Sign succeeded"

echo "[Certificate] Verifying model..."
if ! "${BINARY}" verify certificate \
	--signature "${CERT_SIGFILE}" \
	--certificate-chain "${CERT_DIR}/ca-cert.pem" \
	"${MODELDIR}"; then
	echo "Error: certificate verify failed"
	exit 1
fi
echo "[Certificate] Verify succeeded"
echo

# =========================================================================
# PHASE 3: Validate Traces in Jaeger
# =========================================================================
echo "=========================================="
echo "PHASE 3: Validating Traces in Jaeger"
echo "=========================================="
echo

# ---------------------------------------------------------------------------
# Helper: query Jaeger with retries (spans may take a moment to be indexed)
# Usage: jaeger_query_with_retry <url> <jq_filter> <description> [max_attempts]
# ---------------------------------------------------------------------------
jaeger_query_with_retry() {
	local url="$1"
	local jq_filter="$2"
	local description="$3"
	local max_attempts="${4:-10}"

	for i in $(seq 1 "${max_attempts}"); do
		local result
		result=$(curl -sf "${url}" | jq -r "${jq_filter}" 2>/dev/null) || true
		if [[ -n "${result}" && "${result}" != "null" && "${result}" != "0" && "${result}" != "false" ]]; then
			echo "${result}"
			return 0
		fi
		if [[ "${i}" -lt "${max_attempts}" ]]; then
			sleep 2
		fi
	done
	echo "Error: ${description} — not found after ${max_attempts} attempts" >&2
	return 1
}

TRACES_URL="${JAEGER_URL}/api/traces?service=${OTEL_SERVICE}&limit=20"

# --- 1. Service registered ---
echo "[Validate] Checking service '${OTEL_SERVICE}' is registered..."
service_check=$(jaeger_query_with_retry \
	"${JAEGER_URL}/api/services" \
	".data | map(select(. == \"${OTEL_SERVICE}\")) | first" \
	"service '${OTEL_SERVICE}' not found in Jaeger")
if [[ "${service_check}" != "${OTEL_SERVICE}" ]]; then
	echo "Error: service '${OTEL_SERVICE}' not found in Jaeger"
	echo "Available services:"
	curl -sf "${JAEGER_URL}/api/services" | jq -r '.data[]'
	exit 1
fi
echo "  Service '${OTEL_SERVICE}': FOUND"

# --- 2. Sign span with method=key ---
echo "[Validate] Checking Sign span with method='key'..."
SIGN_KEY_FILTER='[.data[].spans[] | select(.operationName == "Sign") | select(.tags[] | select(.key == "model_signing.method" and .value == "key"))] | length'
sign_key_count=$(jaeger_query_with_retry "${TRACES_URL}" "${SIGN_KEY_FILTER}" "Sign span with method=key")
if [[ "${sign_key_count}" -lt 1 ]]; then
	echo "Error: No Sign span with model_signing.method=key found"
	exit 1
fi
echo "  Sign span (method=key): FOUND (${sign_key_count})"

# --- 3. Verify span with method=key ---
echo "[Validate] Checking Verify span with method='key'..."
VERIFY_KEY_FILTER='[.data[].spans[] | select(.operationName == "Verify") | select(.tags[] | select(.key == "model_signing.method" and .value == "key"))] | length'
verify_key_count=$(jaeger_query_with_retry "${TRACES_URL}" "${VERIFY_KEY_FILTER}" "Verify span with method=key")
if [[ "${verify_key_count}" -lt 1 ]]; then
	echo "Error: No Verify span with model_signing.method=key found"
	exit 1
fi
echo "  Verify span (method=key): FOUND (${verify_key_count})"

# --- 4. Sign span with method=certificate ---
echo "[Validate] Checking Sign span with method='certificate'..."
SIGN_CERT_FILTER='[.data[].spans[] | select(.operationName == "Sign") | select(.tags[] | select(.key == "model_signing.method" and .value == "certificate"))] | length'
sign_cert_count=$(jaeger_query_with_retry "${TRACES_URL}" "${SIGN_CERT_FILTER}" "Sign span with method=certificate")
if [[ "${sign_cert_count}" -lt 1 ]]; then
	echo "Error: No Sign span with model_signing.method=certificate found"
	exit 1
fi
echo "  Sign span (method=certificate): FOUND (${sign_cert_count})"

# --- 5. Verify span with method=certificate ---
echo "[Validate] Checking Verify span with method='certificate'..."
VERIFY_CERT_FILTER='[.data[].spans[] | select(.operationName == "Verify") | select(.tags[] | select(.key == "model_signing.method" and .value == "certificate"))] | length'
verify_cert_count=$(jaeger_query_with_retry "${TRACES_URL}" "${VERIFY_CERT_FILTER}" "Verify span with method=certificate")
if [[ "${verify_cert_count}" -lt 1 ]]; then
	echo "Error: No Verify span with model_signing.method=certificate found"
	exit 1
fi
echo "  Verify span (method=certificate): FOUND (${verify_cert_count})"

# --- 6. model_path attribute present on all spans ---
echo "[Validate] Checking model_path attribute on spans..."
MODEL_PATH_FILTER='[.data[].spans[] | select(.operationName == "Sign" or .operationName == "Verify") | select(.tags[] | select(.key == "model_signing.model_path"))] | length'
spans_with_path=$(jaeger_query_with_retry "${TRACES_URL}" "${MODEL_PATH_FILTER}" "spans with model_signing.model_path attribute")
if [[ "${spans_with_path}" -lt 4 ]]; then
	echo "Error: Expected at least 4 spans with model_signing.model_path, got ${spans_with_path}"
	exit 1
fi
echo "  model_signing.model_path attribute: PRESENT on ${spans_with_path} spans"

# =========================================================================
# Summary
# =========================================================================
echo
echo "=========================================="
echo "All OTel tracing tests PASSED"
echo "=========================================="
echo
echo "Summary:"
echo "  - Service '${OTEL_SERVICE}' registered in Jaeger"
echo "  - Sign spans:   key=${sign_key_count}, certificate=${sign_cert_count}"
echo "  - Verify spans:  key=${verify_key_count}, certificate=${verify_cert_count}"
echo "  - model_signing.model_path present on ${spans_with_path} spans"
echo

exit 0
