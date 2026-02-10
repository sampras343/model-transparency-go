#!/usr/bin/env bash

# PKCS#11 signing and verification test
# Tests signing with PKCS#11 URI and verifying with public key

set -e

DIR=$(dirname "$0")

# Check if SoftHSM2 is available
if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
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

if ! msg=$(softhsm_setup setup); then
	echo -e "Could not setup softhsm:\n${msg}"
	exit 77
fi
pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

model_sig=${TMPDIR}/model.sig
pub_key=${TMPDIR}/pubkey.pem
model_path=${TMPDIR}

if ! msg=$(softhsm_setup getpubkey > "${pub_key}"); then
	echo -e "Could not get public key:\n${msg}"
	exit 77
fi

# Create some test files in the model directory
echo "test file 1" > "${model_path}/file1.txt"
echo "test file 2" > "${model_path}/file2.txt"

# Determine project root (go up from scripts/tests)
PROJECT_ROOT=$(cd "${DIR}/../.." && pwd)

# Build the binary if it doesn't exist
if [ ! -f "${PROJECT_ROOT}/build/model-signing" ]; then
	echo "Building model-signing binary..."
	(cd "${PROJECT_ROOT}" && make build) || exit 1
fi

# Test signing with PKCS#11
echo "Testing PKCS#11 signing..."
if ! "${PROJECT_ROOT}/build/model-signing" sign pkcs11-key \
	--signature "${model_sig}" \
	--pkcs11-uri "${pkcs11uri}" \
	"${model_path}"; then
	echo "Could not sign with PKCS#11."
	exit 1
fi

echo "Signature created successfully: ${model_sig}"

# Test verification with key
echo "Testing verification..."
if ! "${PROJECT_ROOT}/build/model-signing" verify key \
	--signature "${model_sig}" \
	--public-key "${pub_key}"  \
	"${model_path}"; then
	echo "Could not verify signature."
	exit 1
fi

echo "✓ PKCS#11 sign and verify test passed!"
exit 0
