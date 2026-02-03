#!/usr/bin/env bash
# Convenience wrapper for scripts/pkcs11-tests/softhsm_setup
# For automated testing, use scripts/pkcs11-tests/test_pkcs11.sh directly

DIR=$(dirname "$0")
SETUP_SCRIPT="${DIR}/scripts/pkcs11-tests/softhsm_setup"

if [ ! -f "$SETUP_SCRIPT" ]; then
    echo "Error: $SETUP_SCRIPT not found"
    exit 1
fi

# Run setup
"$SETUP_SCRIPT" setup
