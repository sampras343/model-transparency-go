#!/usr/bin/env bash

echo "Testing 'verify key'"
if ! ./model-signing \
	verify key \
	--signature ./v1.0.0-elliptic-key/model.sig \
	--public-key ./keys/certificate/signing-key-pub.pem \
	./v1.0.0-elliptic-key/signme-1; then
	echo "Error: 'verify key' failed on v1.0.0"
	exit 1
fi
