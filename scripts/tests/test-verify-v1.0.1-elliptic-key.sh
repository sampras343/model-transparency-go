#!/usr/bin/env bash

echo "Testing 'verify key'"
if ! ./model-signing \
	verify key \
	--signature ./v1.0.1-elliptic-key/model.sig \
	--public-key ./keys/certificate/signing-key-pub.pem \
	--ignore-paths "./v1.0.1-elliptic-key/ignore-me" \
	./v1.0.1-elliptic-key ; then
	echo "Error: 'verify key' failed on v1.0.1"
	exit 1
fi

exit 0
