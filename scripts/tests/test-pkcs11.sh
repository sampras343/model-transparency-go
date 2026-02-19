#!/usr/bin/env bash

# PKCS#11 signing and verification tests
# Tests both key-based and certificate-based PKCS#11 signing

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

# Build the binary if it doesn't exist
if [ ! -f "${PROJECT_ROOT}/build/model-signing" ]; then
	echo "Building model-signing binary..."
	(cd "${PROJECT_ROOT}" && make build) || exit 1
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
if ! "${PROJECT_ROOT}/build/model-signing" sign pkcs11-key \
	--signature "${model_sig_key}" \
	--pkcs11-uri "${pkcs11uri}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 key signing failed"
	exit 1
fi

echo "  Verifying with public key..."
if ! "${PROJECT_ROOT}/build/model-signing" verify key \
	--signature "${model_sig_key}" \
	--public-key "${pub_key}"  \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Verification failed"
	exit 1
fi
echo "  PASSED"

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
if ! "${PROJECT_ROOT}/build/model-signing" sign pkcs11-certificate \
	--signature "${model_sig_cert}" \
	--pkcs11-uri "${pkcs11uri}" \
	--signing-certificate "${cert_file}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 certificate signing failed"
	exit 1
fi

echo "  Verifying with certificate..."
if ! "${PROJECT_ROOT}/build/model-signing" verify certificate \
	--signature "${model_sig_cert}" \
	--certificate-chain "${cert_file}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Verification failed"
	exit 1
fi
echo "  PASSED"

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
if ! "${PROJECT_ROOT}/build/model-signing" sign pkcs11-certificate \
	--signature "${model_sig_chain}" \
	--pkcs11-uri "${pkcs11uri}" \
	--signing-certificate "${leaf_cert}" \
	--certificate-chain "${ca_cert}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: PKCS#11 certificate chain signing failed"
	exit 1
fi

echo "  Verifying with CA certificate chain..."
if ! "${PROJECT_ROOT}/build/model-signing" verify certificate \
	--signature "${model_sig_chain}" \
	--certificate-chain "${ca_cert}" \
	"${model_path}" >/dev/null 2>&1; then
	echo "  Error: Certificate chain verification failed"
	exit 1
fi
echo "  PASSED"

# ===========================================
# Summary
# ===========================================
echo ""
echo "=========================================="
echo "All PKCS#11 tests PASSED!"
echo "=========================================="
echo ""

exit 0
