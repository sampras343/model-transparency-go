#!/usr/bin/env bash

echo "Testing 'verify certificate'"
if ! ./model-signing \
	verify certificate \
	--ignore-paths "ignore-me" \
	--signature ./v1.1.0-certificate/model.sig \
	--certificate-chain ./keys/certificate/ca-cert.pem \
	./v1.1.0-certificate/; then
	echo "Error: 'verify certificate' failed on v1.1.0"
	exit 1
fi

exit 0
