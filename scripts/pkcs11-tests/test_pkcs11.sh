#!/usr/bin/env bash

DIR=$(dirname "$0")

PATH=$PATH:${PWD}/${DIR}
TMPDIR=$(mktemp -d) || exit 1

cleanup() {
	softhsm_setup teardown &>/dev/null
	rm -rf "${TMPDIR}"
}
trap cleanup SIGTERM EXIT

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

# Build the binary if it doesn't exist
if [ ! -f "./build/model-signing" ]; then
	echo "Building model-signing binary..."
	make build || exit 1
fi

# Test signing with PKCS#11
echo "Testing PKCS#11 signing..."
if ! ./build/model-signing sign pkcs11-key \
	--signature "${model_sig}" \
	--pkcs11-uri "${pkcs11uri}" \
	"${model_path}"; then
	echo "Could not sign with PKCS#11."
	exit 1
fi

echo "Signature created successfully: ${model_sig}"

# Test verification with key
echo "Testing verification..."
if ! ./build/model-signing verify key \
	--signature "${model_sig}" \
	--public-key "${pub_key}"  \
	"${model_path}"; then
	echo "Could not verify signature."
	exit 1
fi

echo "✓ PKCS#11 sign and verify test passed!"
exit 0
