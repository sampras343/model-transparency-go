#!/usr/bin/env bash

# Test script for hybrid certificate signing/verification
#
# Tests two paths:
# 1. Single certificate (sigstore-go compatible) - uses VerificationMaterial.Certificate
# 2. Certificate chain (custom) - uses VerificationMaterial.X509CertificateChain
#
# The hybrid implementation prefers sigstore-go when possible and falls back
# to custom implementation with a warning when certificate chains are used.

set -e

DIR=${PWD}/$(dirname "$0")

# Generate single-level certificates if they don't exist
generate_single_certs_if_needed() {
    local cert_dir="${DIR}/keys/single-cert"

    # Check if certificates already exist
    if [ -f "${cert_dir}/signing-cert-p256.pem" ] && \
       [ -f "${cert_dir}/signing-cert-p384.pem" ] && \
       [ -f "${cert_dir}/signing-cert-rsa.pem" ]; then
        echo "Single-level certificates already exist, skipping generation"
        return 0
    fi

    echo "Generating single-level certificates for testing..."
    mkdir -p "${cert_dir}"

    # Generate ECDSA P-256 key and self-signed certificate
    openssl ecparam -name prime256v1 -genkey -noout -out "${cert_dir}/signing-key-p256.pem" 2>/dev/null
    openssl req -new -x509 \
        -key "${cert_dir}/signing-key-p256.pem" \
        -out "${cert_dir}/signing-cert-p256.pem" \
        -days 3650 \
        -subj "/CN=single-level-test-p256" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=codeSigning" 2>/dev/null
    echo "  Created P-256 key and certificate"

    # Generate ECDSA P-384 key and self-signed certificate
    openssl ecparam -name secp384r1 -genkey -noout -out "${cert_dir}/signing-key-p384.pem" 2>/dev/null
    openssl req -new -x509 \
        -key "${cert_dir}/signing-key-p384.pem" \
        -out "${cert_dir}/signing-cert-p384.pem" \
        -days 3650 \
        -subj "/CN=single-level-test-p384" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=codeSigning" 2>/dev/null
    echo "  Created P-384 key and certificate"

    # Generate RSA 2048 key and self-signed certificate
    openssl genrsa -out "${cert_dir}/signing-key-rsa.pem" 2048 2>/dev/null
    openssl req -new -x509 \
        -key "${cert_dir}/signing-key-rsa.pem" \
        -out "${cert_dir}/signing-cert-rsa.pem" \
        -days 3650 \
        -subj "/CN=single-level-test-rsa" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=codeSigning" 2>/dev/null
    echo "  Created RSA-2048 key and certificate"

    echo "Done generating single-level certificates"
    echo ""
}

# Generate certificates before running tests
generate_single_certs_if_needed
TMPDIR=$(mktemp -d) || exit 1
MODEL_DIR="${TMPDIR}/model"
mkdir -p "${MODEL_DIR}"
signfile1="${MODEL_DIR}/signme-1"
signfile2="${MODEL_DIR}/signme-2"
sigfile_single="${TMPDIR}/model-single.sig"
sigfile_chain="${TMPDIR}/model-chain.sig"

echo "signme-1" > "${signfile1}"
echo "signme-2" > "${signfile2}"

cleanup()
{
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

source "${DIR}/functions"

echo "========================================"
echo "Testing Hybrid Certificate Implementation"
echo "========================================"
echo ""

# ============================================
# Test 1: Single certificate (sigstore-go path)
# ============================================
echo "Test 1: Single certificate signing (sigstore-go compatible path)"
echo "----------------------------------------------------------------"

# Test with P-256 key
echo ""
echo "1a. Testing with ECDSA P-256 key..."

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_single}" \
	--private-key ${DIR}/keys/single-cert/signing-key-p256.pem \
	--signing-certificate ${DIR}/keys/single-cert/signing-cert-p256.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'sign certificate' with single P-256 cert failed"
	exit 1
fi

# Verify bundle format is single certificate
if ! check_bundle_format "${sigfile_single}" "single"; then
	echo "Error: Bundle format check failed for P-256"
	exit 1
fi

# Verify signature
if ! ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_single}" \
	--certificate-chain ${DIR}/keys/single-cert/signing-cert-p256.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'verify certificate' with single P-256 cert failed"
	exit 1
fi
echo "  P-256 single certificate: PASSED"

# Test with P-384 key
echo ""
echo "1b. Testing with ECDSA P-384 key..."

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_single}" \
	--private-key ${DIR}/keys/single-cert/signing-key-p384.pem \
	--signing-certificate ${DIR}/keys/single-cert/signing-cert-p384.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'sign certificate' with single P-384 cert failed"
	exit 1
fi

if ! check_bundle_format "${sigfile_single}" "single"; then
	echo "Error: Bundle format check failed for P-384"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_single}" \
	--certificate-chain ${DIR}/keys/single-cert/signing-cert-p384.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'verify certificate' with single P-384 cert failed"
	exit 1
fi
echo "  P-384 single certificate: PASSED"

# Test with RSA key
echo ""
echo "1c. Testing with RSA-2048 key..."

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_single}" \
	--private-key ${DIR}/keys/single-cert/signing-key-rsa.pem \
	--signing-certificate ${DIR}/keys/single-cert/signing-cert-rsa.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'sign certificate' with single RSA cert failed"
	exit 1
fi

if ! check_bundle_format "${sigfile_single}" "single"; then
	echo "Error: Bundle format check failed for RSA"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_single}" \
	--certificate-chain ${DIR}/keys/single-cert/signing-cert-rsa.pem \
	"${MODEL_DIR}" 2>&1 | grep -v "^$"; then
	echo "Error: 'verify certificate' with single RSA cert failed"
	exit 1
fi
echo "  RSA-2048 single certificate: PASSED"

echo ""
echo "Test 1 Summary: All single certificate tests PASSED"

# ============================================
# Test 2: Certificate chain (custom path)
# ============================================
echo ""
echo "Test 2: Certificate chain signing (custom path with warning)"
echo "-------------------------------------------------------------"

echo ""
echo "2a. Testing with certificate chain (should show warning)..."

# Capture output to verify warning is shown
output=$(${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_chain}" \
	--private-key ${DIR}/keys/certificate/signing-key.pem \
	--signing-certificate ${DIR}/keys/certificate/signing-key-cert.pem \
	--certificate-chain ${DIR}/keys/certificate/int-ca-cert.pem \
	"${MODEL_DIR}" 2>&1)

if [ $? -ne 0 ]; then
	echo "Error: 'sign certificate' with chain failed"
	echo "${output}"
	exit 1
fi

# Check that warning was shown
if ! echo "${output}" | grep -q "WARNING.*X509CertificateChain"; then
	echo "Error: Expected warning about X509CertificateChain but none was shown"
	echo "Output: ${output}"
	exit 1
fi
echo "  Warning message verified during signing"

# Verify bundle format is certificate chain
if ! check_bundle_format "${sigfile_chain}" "chain"; then
	echo "Error: Bundle format check failed for chain"
	exit 1
fi

# Verify with root CA
output=$(${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_chain}" \
	--certificate-chain ${DIR}/keys/certificate/ca-cert.pem \
	"${MODEL_DIR}" 2>&1)

if [ $? -ne 0 ]; then
	echo "Error: 'verify certificate' with chain failed"
	echo "${output}"
	exit 1
fi

# Check that warning was shown during verification
if ! echo "${output}" | grep -q "WARNING.*X509CertificateChain"; then
	echo "Error: Expected warning about X509CertificateChain during verification but none was shown"
	echo "Output: ${output}"
	exit 1
fi
echo "  Warning message verified during verification"
echo "  Certificate chain: PASSED"

echo ""
echo "Test 2 Summary: Certificate chain tests PASSED"

# ============================================
# Test 3: Cross-verification (negative tests)
# ============================================
echo ""
echo "Test 3: Cross-verification tests"
echo "---------------------------------"

echo ""
echo "3a. Verify single-cert bundle with wrong trust anchor (should fail)..."

# Create a different self-signed cert to use as wrong trust anchor
wrong_cert="${TMPDIR}/wrong-cert.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "${TMPDIR}/wrong-key.pem" 2>/dev/null
openssl req -new -x509 \
    -key "${TMPDIR}/wrong-key.pem" \
    -out "${wrong_cert}" \
    -days 1 \
    -subj "/CN=wrong-cert" \
    -addext "keyUsage=critical,digitalSignature" 2>/dev/null

# Sign with P-256 cert
${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_single}" \
	--private-key ${DIR}/keys/single-cert/signing-key-p256.pem \
	--signing-certificate ${DIR}/keys/single-cert/signing-cert-p256.pem \
	"${MODEL_DIR}" 2>&1 > /dev/null

# Try to verify with wrong cert (should fail)
if ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_single}" \
	--certificate-chain "${wrong_cert}" \
	"${MODEL_DIR}" 2>&1 > /dev/null; then
	echo "Error: Verification should have failed with wrong trust anchor"
	exit 1
fi
echo "  Verification correctly failed with wrong trust anchor: PASSED"

echo ""
echo "3b. Verify chain bundle with wrong trust anchor (should fail)..."

# Sign with chain
${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_chain}" \
	--private-key ${DIR}/keys/certificate/signing-key.pem \
	--signing-certificate ${DIR}/keys/certificate/signing-key-cert.pem \
	--certificate-chain ${DIR}/keys/certificate/int-ca-cert.pem \
	"${MODEL_DIR}" 2>&1 > /dev/null

# Try to verify with a completely unrelated certificate (should fail)
if ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_chain}" \
	--certificate-chain "${wrong_cert}" \
	"${MODEL_DIR}" 2>&1 > /dev/null; then
	echo "Error: Verification should have failed with wrong trust anchor for chain"
	exit 1
fi
echo "  Verification correctly failed with wrong trust anchor for chain: PASSED"

echo ""
echo "Test 3 Summary: Cross-verification tests PASSED"

# ============================================
# Test 4: Verify correct files are signed
# ============================================
echo ""
echo "Test 4: Verify signed files content"
echo "------------------------------------"

# Check files in single cert signature
res=$(get_signed_files "${sigfile_single}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files in single cert signature"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
echo "  Single cert signature contains correct files: PASSED"

# Check files in chain signature
res=$(get_signed_files "${sigfile_chain}")
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files in chain signature"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
echo "  Chain signature contains correct files: PASSED"

echo ""
echo "Test 4 Summary: Signed files verification PASSED"

# ============================================
# Summary
# ============================================
echo ""
echo "========================================"
echo "All hybrid certificate tests PASSED!"
echo "========================================"
echo ""
echo "Summary:"
echo "  - Single certificate (sigstore-go path): Working"
echo "  - Certificate chain (custom path): Working with warnings"
echo "  - Cross-verification: Correctly rejects invalid certs"
echo "  - File content: Correctly signed"
