#!/usr/bin/env bash

echo "Testing 'verify sigstore'"
if ! ./model-signing \
	verify sigstore \
	--identity stefanb@us.ibm.com \
	--identity-provider https://sigstore.verify.ibm.com/oauth2 \
	--signature ./v0.3.1-sigstore/model.sig \
	./v0.3.1-sigstore/; then
	echo "Error: 'verify sigstore' failed on v0.3.1"
	exit 1
fi

exit 0