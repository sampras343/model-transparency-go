#!/usr/bin/env bash

# PKCS#11 signing and verification tests
# Tests both key-based and certificate-based PKCS#11 signing, including --json
# (file, inline, stdin) for sign pkcs11-key / sign pkcs11-certificate and chain.

set -e

DIR=$(dirname "$0")
source "${DIR}/functions"

# Ensure PKCS#11 dependencies are available
if ! ensure_pkcs11_deps; then
	echo "Skipping PKCS#11 tests: SoftHSM2 or p11tool not available"
	exit 0
fi

# Add the tests directory to PATH so softhsm_setup is found
PATH=$PATH:$(cd "${DIR}" && pwd)
TMPDIR=$(mktemp -d) || exit 1

cleanup() {
	softhsm_setup teardown &>/dev/null || true
	rm -rf "${TMPDIR}"
}
trap cleanup SIGTERM EXIT

echo ">>> Running PKCS#11 tests..."

# Setup SoftHSM2
if ! msg=$(softhsm_setup setup); then
	echo -e "Could not setup softhsm:\n${msg}"
	exit 77
fi
pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

# Determine project root (go up from scripts/tests)
PROJECT_ROOT=$(cd "${DIR}/../.." && pwd)

# Build the binary with pkcs11 tag if it doesn't exist
BINARY="${PROJECT_ROOT}/scripts/tests/model-signing"
if [ ! -f "${BINARY}" ]; then
	echo "Building model-signing binary with pkcs11 tag..."
	(cd "${PROJECT_ROOT}" && make build-test-binary-pkcs11) || exit 1
fi

# ===========================================
# Test 1: PKCS#11 Key-Based Signing
# ===========================================
echo ""
echo "Test 1: PKCS#11 Key-Based Signing"
echo "-----------------------------------"

model_sig_key=${TMPDIR}/model-key.sig
pub_key=${TMPDIR}/pubkey.pem
model_path=${TMPDIR}

# Get public key
if ! softhsm_setup getpubkey > "${pub_key}" 2>/dev/null; then
	echo "Could not get public key"
	exit 77
fi

# Create test files
echo "test file 1" > "${model_path}/file1.txt"
echo "test file 2" > "${model_path}/file2.txt"

echo "  Signing with PKCS#11 key..."
if ! "${BINARY}" sign pkcs11-key \
	--signature "${model_sig_key}" \
	--pkcs11-uri "${pkcs11uri}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 key signing failed"
	exit 1
fi

echo "  Verifying with public key..."
if ! "${BINARY}" verify key \
	--signature "${model_sig_key}" \
	--public-key "${pub_key}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Verification failed"
	exit 1
fi
echo "  PASSED"

# ===========================================
# Tests 1b–1e: PKCS#11 key signing via --json (file, inline, stdin) + negative
# ===========================================
echo ""
echo "Tests 1b–1e: PKCS#11 key signing with --json"
echo "-----------------------------------"
if ! command -v jq >/dev/null 2>&1; then
	echo "  SKIPPED: jq not in PATH (--json PKCS#11 key tests)"
else
	model_sig_json=${TMPDIR}/model-key-json.sig
	json_key_params=${TMPDIR}/pkcs11-key-params.json
	jq -n \
		--arg model "${model_path}" \
		--arg sig "${model_sig_json}" \
		--arg uri "${pkcs11uri}" \
		'{model: $model, signature: $sig, "pkcs11-uri": $uri}' >"${json_key_params}"

	echo "  1b: Signing with PKCS#11 key via --json file..."
	if ! "${BINARY}" sign pkcs11-key --json "${json_key_params}" >/dev/null 2>&1; then
		echo "  Error: PKCS#11 key signing (--json file) failed"
		exit 1
	fi
	echo "  Verifying (flags)..."
	if ! "${BINARY}" verify key \
		--signature "${model_sig_json}" \
		--public-key "${pub_key}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after --json file PKCS#11 key sign"
		exit 1
	fi
	echo "  1b PASSED"

	model_sig_inline=${TMPDIR}/model-key-json-inline.sig
	echo "  1c: Signing with PKCS#11 key via inline --json..."
	if ! "${BINARY}" sign pkcs11-key \
		--json "$(jq -n \
			--arg model "${model_path}" \
			--arg sig "${model_sig_inline}" \
			--arg uri "${pkcs11uri}" \
			'{model: $model, signature: $sig, "pkcs11-uri": $uri}')" >/dev/null 2>&1; then
		echo "  Error: PKCS#11 key signing (inline --json) failed"
		exit 1
	fi
	if ! "${BINARY}" verify key \
		--signature "${model_sig_inline}" \
		--public-key "${pub_key}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after inline --json PKCS#11 key sign"
		exit 1
	fi
	echo "  1c PASSED"

	model_sig_stdin=${TMPDIR}/model-key-json-stdin.sig
	echo "  1d: Signing with PKCS#11 key via --json stdin (-)..."
	if ! jq -n \
		--arg model "${model_path}" \
		--arg sig "${model_sig_stdin}" \
		--arg uri "${pkcs11uri}" \
		'{model: $model, signature: $sig, "pkcs11-uri": $uri}' |
		"${BINARY}" sign pkcs11-key --json - >/dev/null 2>&1; then
		echo "  Error: PKCS#11 key signing (--json stdin) failed"
		exit 1
	fi
	if ! "${BINARY}" verify key \
		--signature "${model_sig_stdin}" \
		--public-key "${pub_key}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after --json stdin PKCS#11 key sign"
		exit 1
	fi
	echo "  1d PASSED"

	echo "  1e: expect failure — key-only flag in pkcs11-key --json..."
	if "${BINARY}" sign pkcs11-key \
		--json "$(jq -n --arg uri "${pkcs11uri}" '{"private-key": "/bogus.pem", "pkcs11-uri": $uri}')" \
		2>/dev/null; then
		echo "  Error: expected non-zero exit for private-key on sign pkcs11-key"
		exit 1
	fi
	echo "  1e PASSED"
fi

# ===========================================
# Test 2: PKCS#11 Self-Signed Certificate Signing
# ===========================================

# Check if certtool is available for certificate tests
if ! command -v certtool &>/dev/null; then
	echo ""
	echo "Test 2: PKCS#11 Self-Signed Certificate Signing"
	echo "-----------------------------------"
	echo "  SKIPPED: certtool not available"
	echo ""
	echo "=========================================="
	echo "PKCS#11 key signing tests PASSED!"
	echo "=========================================="
	exit 0
fi

echo ""
echo "Test 2: PKCS#11 Self-Signed Certificate Signing"
echo "-----------------------------------"

model_sig_cert=${TMPDIR}/model-cert.sig
cert_file=${TMPDIR}/pkcs11-cert.pem

# Export GNUTLS_PIN for automatic authentication
export GNUTLS_PIN=1234

echo "  Generating certificate from PKCS#11 key..."
if ! certtool --generate-self-signed \
	--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
	--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
	--outfile "${cert_file}" \
	--template <(cat <<'EOF'
cn = PKCS11 Test CA
organization = Model Signing Test
organizational_unit = Testing
country = US
state = California
expiration_days = 365
ca
signing_key
cert_signing_key
EOF
) >/dev/null 2>&1; then
	echo "  Error: Certificate generation failed"
	exit 1
fi

echo "  Signing with PKCS#11 certificate..."
if ! "${BINARY}" sign pkcs11-certificate \
	--signature "${model_sig_cert}" \
	--pkcs11-uri "${pkcs11uri}" \
	--signing-certificate "${cert_file}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 certificate signing failed"
	exit 1
fi

echo "  Verifying with certificate..."
if ! "${BINARY}" verify certificate \
	--signature "${model_sig_cert}" \
	--certificate-chain "${cert_file}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Verification failed"
	exit 1
fi
echo "  PASSED"

# ===========================================
# Tests 2b–2e: PKCS#11 certificate signing via --json (file, inline, stdin) + negative
# ===========================================
echo ""
echo "Tests 2b–2e: PKCS#11 certificate signing with --json"
echo "-----------------------------------"
if ! command -v jq >/dev/null 2>&1; then
	echo "  SKIPPED: jq not in PATH (--json PKCS#11 certificate tests)"
else
	model_sig_cert_json=${TMPDIR}/model-cert-json.sig
	json_cert_params=${TMPDIR}/pkcs11-cert-params.json
	jq -n \
		--arg model "${model_path}" \
		--arg sig "${model_sig_cert_json}" \
		--arg uri "${pkcs11uri}" \
		--arg cert "${cert_file}" \
		'{model: $model, signature: $sig, "pkcs11-uri": $uri, "signing-certificate": $cert}' >"${json_cert_params}"

	echo "  2b: Signing with PKCS#11 certificate via --json file..."
	if ! "${BINARY}" sign pkcs11-certificate --json "${json_cert_params}" >/dev/null 2>&1; then
		echo "  Error: PKCS#11 certificate signing (--json file) failed"
		exit 1
	fi
	if ! "${BINARY}" verify certificate \
		--signature "${model_sig_cert_json}" \
		--certificate-chain "${cert_file}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after --json file PKCS#11 certificate sign"
		exit 1
	fi
	echo "  2b PASSED"

	model_sig_cert_inline=${TMPDIR}/model-cert-json-inline.sig
	echo "  2c: Signing with PKCS#11 certificate via inline --json..."
	if ! "${BINARY}" sign pkcs11-certificate \
		--json "$(jq -n \
			--arg model "${model_path}" \
			--arg sig "${model_sig_cert_inline}" \
			--arg uri "${pkcs11uri}" \
			--arg cert "${cert_file}" \
			'{model: $model, signature: $sig, "pkcs11-uri": $uri, "signing-certificate": $cert}')" >/dev/null 2>&1; then
		echo "  Error: PKCS#11 certificate signing (inline --json) failed"
		exit 1
	fi
	if ! "${BINARY}" verify certificate \
		--signature "${model_sig_cert_inline}" \
		--certificate-chain "${cert_file}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after inline --json PKCS#11 certificate sign"
		exit 1
	fi
	echo "  2c PASSED"

	model_sig_cert_stdin=${TMPDIR}/model-cert-json-stdin.sig
	echo "  2d: Signing with PKCS#11 certificate via --json stdin (-)..."
	if ! jq -n \
		--arg model "${model_path}" \
		--arg sig "${model_sig_cert_stdin}" \
		--arg uri "${pkcs11uri}" \
		--arg cert "${cert_file}" \
		'{model: $model, signature: $sig, "pkcs11-uri": $uri, "signing-certificate": $cert}' |
		"${BINARY}" sign pkcs11-certificate --json - >/dev/null 2>&1; then
		echo "  Error: PKCS#11 certificate signing (--json stdin) failed"
		exit 1
	fi
	if ! "${BINARY}" verify certificate \
		--signature "${model_sig_cert_stdin}" \
		--certificate-chain "${cert_file}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after --json stdin PKCS#11 certificate sign"
		exit 1
	fi
	echo "  2d PASSED"

	echo "  2e: expect failure — key-only flag in pkcs11-certificate --json..."
	if "${BINARY}" sign pkcs11-certificate \
		--json "$(jq -n \
			--arg uri "${pkcs11uri}" \
			--arg cert "${cert_file}" \
			'{"private-key": "/bogus.pem", "pkcs11-uri": $uri, "signing-certificate": $cert}')" \
		2>/dev/null; then
		echo "  Error: expected non-zero exit for private-key on sign pkcs11-certificate"
		exit 1
	fi
	echo "  2e PASSED"
fi

# ===========================================
# Test 3: PKCS#11 Certificate Chain Signing
# ===========================================
echo ""
echo "Test 3: PKCS#11 Certificate Chain Signing (CA + Leaf)"
echo "-----------------------------------"

model_sig_chain=${TMPDIR}/model-chain.sig
ca_key=${TMPDIR}/ca-key.pem
ca_cert=${TMPDIR}/ca-cert.pem
leaf_cert=${TMPDIR}/leaf-cert.pem

echo "  Generating CA key and self-signed CA certificate..."
if ! certtool --generate-privkey --outfile "${ca_key}" >/dev/null 2>&1; then
	echo "  Error: CA key generation failed"
	exit 1
fi

if ! certtool --generate-self-signed \
	--load-privkey "${ca_key}" \
	--outfile "${ca_cert}" \
	--template <(cat <<'EOF'
cn = PKCS11 Test CA
organization = Model Signing Test
country = US
expiration_days = 365
ca
cert_signing_key
EOF
) >/dev/null 2>&1; then
	echo "  Error: CA certificate generation failed"
	exit 1
fi

echo "  Generating leaf signing certificate issued by CA..."
if ! certtool --generate-certificate \
	--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
	--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
	--load-ca-certificate "${ca_cert}" \
	--load-ca-privkey "${ca_key}" \
	--outfile "${leaf_cert}" \
	--template <(cat <<'EOF'
cn = PKCS11 Test Signing Cert
organization = Model Signing Test
country = US
expiration_days = 365
signing_key
EOF
) >/dev/null 2>&1; then
	echo "  Error: Leaf certificate generation failed"
	exit 1
fi

echo "  Signing with PKCS#11 leaf certificate and chain..."
if ! "${BINARY}" sign pkcs11-certificate \
	--signature "${model_sig_chain}" \
	--pkcs11-uri "${pkcs11uri}" \
	--signing-certificate "${leaf_cert}" \
	--certificate-chain "${ca_cert}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 certificate chain signing failed"
	exit 1
fi

echo "  Verifying with CA certificate chain..."
if ! "${BINARY}" verify certificate \
	--signature "${model_sig_chain}" \
	--certificate-chain "${ca_cert}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Certificate chain verification failed"
	exit 1
fi
	echo "  PASSED"

# ===========================================
# Test 3b: PKCS#11 chain signing via --json file
# ===========================================
echo ""
echo "Test 3b: PKCS#11 chain signing with --json file"
echo "-----------------------------------"
if ! command -v jq >/dev/null 2>&1; then
	echo "  SKIPPED: jq not in PATH (--json PKCS#11 chain test)"
else
	model_sig_chain_json=${TMPDIR}/model-chain-json.sig
	json_chain_params=${TMPDIR}/pkcs11-chain-params.json
	jq -n \
		--arg model "${model_path}" \
		--arg sig "${model_sig_chain_json}" \
		--arg uri "${pkcs11uri}" \
		--arg leaf "${leaf_cert}" \
		--arg ca "${ca_cert}" \
		'{model: $model, signature: $sig, "pkcs11-uri": $uri, "signing-certificate": $leaf, "certificate-chain": $ca}' >"${json_chain_params}"

	echo "  Signing with PKCS#11 leaf + chain via --json file..."
	if ! "${BINARY}" sign pkcs11-certificate --json "${json_chain_params}" >/dev/null 2>&1; then
		echo "  Error: PKCS#11 chain signing (--json file) failed"
		exit 1
	fi
	if ! "${BINARY}" verify certificate \
		--signature "${model_sig_chain_json}" \
		--certificate-chain "${ca_cert}" \
		"${model_path}" >/dev/null 2>&1; then
		echo "  Error: Verification failed after --json PKCS#11 chain sign"
		exit 1
	fi
	echo "  PASSED"
fi

# ===========================================
# Summary
# ===========================================
echo ""
echo "=========================================="
echo "All PKCS#11 tests PASSED!"
echo "=========================================="
echo ""

exit 0
