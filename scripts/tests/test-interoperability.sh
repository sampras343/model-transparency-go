#!/usr/bin/env bash

# Cross-language interoperability tests between Go and Python implementations
#
# This script tests:
# 1. Go binary creates signatures -> Python library verifies them
# 2. Python library creates signatures -> Go binary verifies them
#
# All three signing methods are tested: key, certificate, sigstore

set -e

DIR=${PWD}/$(dirname "$0")
source "${DIR}/functions"
TMPDIR=$(mktemp -d) || exit 1
MODELDIR="${TMPDIR}/model"
VENV="${TMPDIR}/venv"

# Signature files
GO_SIG_KEY="${TMPDIR}/go-signed-key.sig"
GO_SIG_CERT="${TMPDIR}/go-signed-certificate.sig"
GO_SIG_SIGSTORE="${TMPDIR}/go-signed-sigstore.sig"
PY_SIG_KEY="${TMPDIR}/py-signed-key.sig"
PY_SIG_CERT="${TMPDIR}/py-signed-certificate.sig"
PY_SIG_SIGSTORE="${TMPDIR}/py-signed-sigstore.sig"

# OIDC token for sigstore
TOKENPROJ="${TMPDIR}/tokenproj"
TOKEN_FILE="${TOKENPROJ}/oidc-token.txt"

# PKCS#11 files
GO_SIG_PKCS11="${TMPDIR}/go-signed-pkcs11.sig"
PKCS11_PUBKEY="${TMPDIR}/pkcs11-pubkey.pem"

cleanup() {
	# Cleanup SoftHSM2 if it was set up
	if [ -f "${DIR}/softhsm_setup" ]; then
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
	fi
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

# Create test model
mkdir -p "${MODELDIR}" "${TOKENPROJ}"
echo "file-1-content" > "${MODELDIR}/file1.txt"
echo "file-2-content" > "${MODELDIR}/file2.txt"

echo "=== Cross-Language Interoperability Tests ==="
echo

# Setup Python environment
echo "Setting up Python environment..."
python3 -m venv "${VENV}" || exit 1
source "${VENV}/bin/activate"

# Install model-signing from PyPI (pinned to 1.1.1 for compatibility)
if ! pip install --quiet model-signing==1.1.1; then
	echo "Error: Failed to install model-signing Python package"
	exit 1
fi

echo -n "Python model_signing version: "
model_signing --version

echo -n "Go model-signing binary: "
${DIR}/model-signing version 2>/dev/null || echo "(version not available)"

echo

echo "=========================================="
echo "PART 1: Go signs -> Python verifies"
echo "=========================================="
echo

# --- Key method ---
echo "[Go->Python] Testing 'key' method"

echo "  Go: Signing with key..."
if ! ${DIR}/model-signing \
	sign key \
	--signature "${GO_SIG_KEY}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Go 'sign key' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify key \
	--signature "${GO_SIG_KEY}" \
	--public_key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify key' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

# --- Certificate method ---
echo "[Go->Python] Testing 'certificate' method"

echo "  Go: Signing with certificate..."
if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${GO_SIG_CERT}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Go 'sign certificate' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify certificate \
	--signature "${GO_SIG_CERT}" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify certificate' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

# --- PKCS#11 method ---
echo "[Go->Python] Testing 'pkcs11' method"

# Check if SoftHSM2 is available
if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
	echo "  SKIPPED: SoftHSM2 or p11tool not available"
else
	echo "  Setting up SoftHSM2..."
	if ! msg=$("${DIR}/softhsm_setup" setup); then
		echo "  Error: Could not setup SoftHSM2"
		echo "  ${msg}"
		exit 1
	fi
	
	pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')
	
	# Get public key from PKCS#11 token
	if ! msg=$("${DIR}/softhsm_setup" getpubkey > "${PKCS11_PUBKEY}"); then
		echo "  Error: Could not get PKCS#11 public key"
		exit 1
	fi
	
	echo "  Go: Signing with PKCS#11..."
	if ! ${DIR}/model-signing \
		sign pkcs11-key \
		--signature "${GO_SIG_PKCS11}" \
		--pkcs11-uri "${pkcs11uri}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Go 'sign pkcs11-key' failed"
		exit 1
	fi
	
	echo "  Python: Verifying signature..."
	if ! model_signing \
		verify key \
		--signature "${GO_SIG_PKCS11}" \
		--public_key "${PKCS11_PUBKEY}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Python 'verify key' failed on PKCS#11-created signature"
		exit 1
	fi
	echo "  PASSED"
fi
echo

# --- Sigstore method ---
echo "[Go->Python] Testing 'sigstore' method"

SIGSTORE_IDENTITY="https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"

echo "  Go: Signing with sigstore (with OIDC token retry)..."
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity-token" \
	${DIR}/model-signing \
	sign sigstore \
	--use-staging \
	--signature "${GO_SIG_SIGSTORE}" \
	"${MODELDIR}"; then
	echo "  Error: Go 'sign sigstore' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify sigstore \
	--use_staging \
	--signature "${GO_SIG_SIGSTORE}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity_provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify sigstore' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

echo "=========================================="
echo "PART 2: Python signs -> Go verifies"
echo "=========================================="
echo

# --- Key method ---
echo "[Python->Go] Testing 'key' method"

echo "  Python: Signing with key..."
if ! model_signing \
	sign key \
	--signature "${PY_SIG_KEY}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'sign key' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify key \
	--signature "${PY_SIG_KEY}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify key' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# --- Certificate method ---
echo "[Python->Go] Testing 'certificate' method"

echo "  Python: Signing with certificate..."
if ! model_signing \
	sign certificate \
	--signature "${PY_SIG_CERT}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--signing_certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate_chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'sign certificate' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify certificate \
	--signature "${PY_SIG_CERT}" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify certificate' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# --- Sigstore method ---
echo "[Python->Go] Testing 'sigstore' method"

echo "  Python: Signing with sigstore (with OIDC token retry)..."
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity_token" \
	model_signing \
	sign sigstore \
	--signature "${PY_SIG_SIGSTORE}" \
	"${MODELDIR}"; then
	echo "  Error: Python 'sign sigstore' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify sigstore \
	--signature "${PY_SIG_SIGSTORE}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity-provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify sigstore' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# Deactivate venv
deactivate

echo "=========================================="
echo "All interoperability tests PASSED!"
echo "=========================================="

exit 0
