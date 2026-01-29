#!/usr/bin/env bash

echo "Testing 'verify key'"
if ! ./model-signing \
	verify key \
	--signature ./v0.3.1-elliptic-key/model.sig \
	--public-key ./keys/certificate/signing-key-pub.pem \
	./v0.3.1-elliptic-key/signme-1; then
	echo "Error: 'verify key' failed on v0.3.1"
	exit 1
fi
