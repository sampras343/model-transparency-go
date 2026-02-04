#!/usr/bin/env bash

# Generate single-level (self-signed) certificates for testing
# the sigstore-go compatible certificate path.
#
# These certificates have no chain - they are self-signed and can be
# used directly as trust anchors.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Generating single-level (self-signed) certificates..."

# Generate ECDSA P-256 key and self-signed certificate
openssl ecparam -name prime256v1 -genkey -noout -out signing-key-p256.pem

openssl req -new -x509 \
    -key signing-key-p256.pem \
    -out signing-cert-p256.pem \
    -days 3650 \
    -subj "/CN=single-level-test-p256" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"

echo "  Created P-256 key and certificate"

# Generate ECDSA P-384 key and self-signed certificate
openssl ecparam -name secp384r1 -genkey -noout -out signing-key-p384.pem

openssl req -new -x509 \
    -key signing-key-p384.pem \
    -out signing-cert-p384.pem \
    -days 3650 \
    -subj "/CN=single-level-test-p384" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"

echo "  Created P-384 key and certificate"

# Generate RSA 2048 key and self-signed certificate
openssl genrsa -out signing-key-rsa.pem 2048

openssl req -new -x509 \
    -key signing-key-rsa.pem \
    -out signing-cert-rsa.pem \
    -days 3650 \
    -subj "/CN=single-level-test-rsa" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"

echo "  Created RSA-2048 key and certificate"

echo "Done. Generated single-level certificates for testing."
echo ""
echo "Files created:"
ls -la *.pem
