#!/usr/bin/env bash

# Cross-language interoperability tests between Go and Python implementations
#
# This script tests:
# 1. Go binary creates signatures -> Python library verifies them
# 2. Python library creates signatures -> Go binary verifies them
#
# Signing methods tested:
# - key: Full bidirectional interoperability (Go <-> Python)
# - certificate: Full bidirectional interoperability (Go <-> Python)
# - sigstore: Full bidirectional interoperability (Go <-> Python)
# - pkcs11-key: Full bidirectional interoperability (Go <-> Python, requires Python pkcs11 extra)
# - pkcs11-certificate: Full bidirectional interoperability (Go <-> Python, requires Python pkcs11 extra)
# - pkcs11-certificate-chain: CA + leaf cert chain interoperability (Go <-> Python, requires Python pkcs11 extra)

set -e

DIR=${PWD}/$(dirname "$0")
source "${DIR}/functions"
TMPDIR=$(mktemp -d) || exit 1
MODELDIR="${TMPDIR}/model"
VENV="${TMPDIR}/venv"

# Signature files
GO_SIG_KEY="${TMPDIR}/go-signed-key.sig"
GO_SIG_CERT="${TMPDIR}/go-signed-certificate.sig"
GO_SIG_SIGSTORE="${TMPDIR}/go-signed-sigstore.sig"
PY_SIG_KEY="${TMPDIR}/py-signed-key.sig"
PY_SIG_CERT="${TMPDIR}/py-signed-certificate.sig"
PY_SIG_SIGSTORE="${TMPDIR}/py-signed-sigstore.sig"

# OIDC token for sigstore
TOKENPROJ="${TMPDIR}/tokenproj"
TOKEN_FILE="${TOKENPROJ}/oidc-token.txt"

# PKCS#11 files
GO_SIG_PKCS11="${TMPDIR}/go-signed-pkcs11.sig"
GO_SIG_PKCS11_CERT="${TMPDIR}/go-signed-pkcs11-certificate.sig"
PKCS11_PUBKEY="${TMPDIR}/pkcs11-pubkey.pem"
PKCS11_CERT="${TMPDIR}/pkcs11-certificate.pem"
GO_SIG_PKCS11_CHAIN="${TMPDIR}/go-signed-pkcs11-chain.sig"
PY_SIG_PKCS11_CHAIN="${TMPDIR}/py-signed-pkcs11-chain.sig"
PKCS11_CA_KEY="${TMPDIR}/pkcs11-ca-key.pem"
PKCS11_CA_CERT="${TMPDIR}/pkcs11-ca-cert.pem"
PKCS11_LEAF_CERT="${TMPDIR}/pkcs11-leaf-cert.pem"

cleanup() {
	# Cleanup SoftHSM2 if it was set up
	if [ -f "${DIR}/softhsm_setup" ]; then
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
	fi
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

# Create test model
mkdir -p "${MODELDIR}" "${TOKENPROJ}"
echo "file-1-content" > "${MODELDIR}/file1.txt"
echo "file-2-content" > "${MODELDIR}/file2.txt"

echo "=== Cross-Language Interoperability Tests ==="
echo

# Setup Python environment
echo "Setting up Python environment..."
python3 -m venv "${VENV}" || exit 1
source "${VENV}/bin/activate"

# Install model-signing from PyPI with PKCS#11 support (pinned to 1.1.1 for compatibility)
if ! pip install --quiet 'model-signing[pkcs11]==1.1.1'; then
	echo "Error: Failed to install model-signing Python package"
	exit 1
fi

echo -n "Python model_signing version: "
model_signing --version

echo -n "Go model-signing binary: "
${DIR}/model-signing version 2>/dev/null || echo "(version not available)"

echo

echo "=========================================="
echo "PART 1: Go signs -> Python verifies"
echo "=========================================="
echo

# --- Key method ---
echo "[Go->Python] Testing 'key' method"

echo "  Go: Signing with key..."
if ! ${DIR}/model-signing \
	sign key \
	--signature "${GO_SIG_KEY}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Go 'sign key' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify key \
	--signature "${GO_SIG_KEY}" \
	--public_key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify key' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

# --- Certificate method ---
echo "[Go->Python] Testing 'certificate' method"

echo "  Go: Signing with certificate..."
if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${GO_SIG_CERT}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Go 'sign certificate' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify certificate \
	--signature "${GO_SIG_CERT}" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify certificate' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

# --- PKCS#11 key method ---
echo "[Go->Python] Testing 'pkcs11-key' method"

# Check if SoftHSM2 is available
if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
	echo "  SKIPPED: SoftHSM2 or p11tool not available"
else
	echo "  Setting up SoftHSM2..."
	if ! msg=$("${DIR}/softhsm_setup" setup); then
		echo "  Error: Could not setup SoftHSM2"
		echo "  ${msg}"
		exit 1
	fi
	
	pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')
	
	# Get public key from PKCS#11 token
	if ! msg=$("${DIR}/softhsm_setup" getpubkey > "${PKCS11_PUBKEY}"); then
		echo "  Error: Could not get PKCS#11 public key"
		exit 1
	fi
	
	echo "  Go: Signing with PKCS#11..."
	if ! ${DIR}/model-signing \
		sign pkcs11-key \
		--signature "${GO_SIG_PKCS11}" \
		--pkcs11-uri "${pkcs11uri}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Go 'sign pkcs11-key' failed"
		exit 1
	fi
	
	echo "  Python: Verifying signature..."
	if ! model_signing \
		verify key \
		--signature "${GO_SIG_PKCS11}" \
		--public_key "${PKCS11_PUBKEY}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Python 'verify key' failed on PKCS#11-created signature"
		exit 1
	fi
	echo "  PASSED"
	echo
	
	# --- PKCS#11 Certificate method ---
	echo "[Go->Python] Testing 'pkcs11-certificate' method"
	
	echo "  Generating certificate from PKCS#11 key..."
	# Export GNUTLS_PIN for automatic authentication
	export GNUTLS_PIN=1234
	
	# Generate self-signed CA certificate
	if ! certtool --generate-self-signed \
		--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
		--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
		--outfile "${PKCS11_CERT}" \
		--template <(cat <<EOF
cn = "PKCS11 Interop Test CA"
organization = "Model Signing Interop Test"
unit = "Testing"
state = "California"
country = US
expiration_days = 365
ca
signing_key
cert_signing_key
EOF
	) >/dev/null 2>&1; then
		echo "  Error: Certificate generation failed"
		exit 1
	fi
	
	echo "  Go: Signing with PKCS#11 certificate..."
	output=$(${DIR}/model-signing \
		sign pkcs11-certificate \
		--signature "${GO_SIG_PKCS11_CERT}" \
		--pkcs11-uri "${pkcs11uri}" \
		--signing-certificate "${PKCS11_CERT}" \
		"${MODELDIR}" 2>&1)
	if [ $? -ne 0 ]; then
		echo "  Error: Go 'sign pkcs11-certificate' failed"
		echo "${output}"
		exit 1
	fi
	
	echo "  Go: Verifying signature (Go self-test)..."
	if ! ${DIR}/model-signing \
		verify certificate \
		--signature "${GO_SIG_PKCS11_CERT}" \
		--certificate-chain "${PKCS11_CERT}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Go 'verify certificate' failed on PKCS#11 certificate signature"
		exit 1
	fi
	
	echo "  Python: Verifying signature..."
	if ! model_signing \
		verify certificate \
		--signature "${GO_SIG_PKCS11_CERT}" \
		--certificate_chain "${PKCS11_CERT}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Python 'verify certificate' failed on PKCS#11 certificate signature"
		exit 1
	fi
	echo "  PASSED"
	echo

	# --- PKCS#11 Certificate Chain method (CA + Leaf) ---
	echo "[Go->Python] Testing 'pkcs11-certificate-chain' method (CA + Leaf)"

	echo "  Generating CA key and self-signed CA certificate..."
	if ! certtool --generate-privkey --outfile "${PKCS11_CA_KEY}" >/dev/null 2>&1; then
		echo "  Error: CA key generation failed"
		exit 1
	fi

	if ! certtool --generate-self-signed \
		--load-privkey "${PKCS11_CA_KEY}" \
		--outfile "${PKCS11_CA_CERT}" \
		--template <(cat <<'EOF'
cn = PKCS11 Interop Test CA
organization = Model Signing Interop Test
country = US
expiration_days = 365
ca
cert_signing_key
EOF
	) >/dev/null 2>&1; then
		echo "  Error: CA certificate generation failed"
		exit 1
	fi

	echo "  Generating leaf signing certificate issued by CA..."
	if ! certtool --generate-certificate \
		--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
		--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
		--load-ca-certificate "${PKCS11_CA_CERT}" \
		--load-ca-privkey "${PKCS11_CA_KEY}" \
		--outfile "${PKCS11_LEAF_CERT}" \
		--template <(cat <<'EOF'
cn = PKCS11 Interop Test Signing Cert
organization = Model Signing Interop Test
country = US
expiration_days = 365
signing_key
EOF
	) >/dev/null 2>&1; then
		echo "  Error: Leaf certificate generation failed"
		exit 1
	fi

	echo "  Go: Signing with PKCS#11 leaf certificate and chain..."
	output=$(${DIR}/model-signing \
		sign pkcs11-certificate \
		--signature "${GO_SIG_PKCS11_CHAIN}" \
		--pkcs11-uri "${pkcs11uri}" \
		--signing-certificate "${PKCS11_LEAF_CERT}" \
		--certificate-chain "${PKCS11_CA_CERT}" \
		"${MODELDIR}" 2>&1)
	if [ $? -ne 0 ]; then
		echo "  Error: Go 'sign pkcs11-certificate' with chain failed"
		echo "${output}"
		exit 1
	fi

	echo "  Go: Verifying signature (Go self-test)..."
	if ! ${DIR}/model-signing \
		verify certificate \
		--signature "${GO_SIG_PKCS11_CHAIN}" \
		--certificate-chain "${PKCS11_CA_CERT}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Go 'verify certificate' failed on PKCS#11 chain signature"
		exit 1
	fi

	echo "  Python: Verifying signature..."
	if ! model_signing \
		verify certificate \
		--signature "${GO_SIG_PKCS11_CHAIN}" \
		--certificate_chain "${PKCS11_CA_CERT}" \
		"${MODELDIR}" >/dev/null 2>&1; then
		echo "  Error: Python 'verify certificate' failed on PKCS#11 chain signature"
		exit 1
	fi
	echo "  PASSED"
fi
echo

# --- Sigstore method ---
echo "[Go->Python] Testing 'sigstore' method"

SIGSTORE_IDENTITY="https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"

echo "  Go: Signing with sigstore (with OIDC token retry)..."
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity-token" \
	${DIR}/model-signing \
	sign sigstore \
	--use-staging \
	--signature "${GO_SIG_SIGSTORE}" \
	"${MODELDIR}"; then
	echo "  Error: Go 'sign sigstore' failed"
	exit 1
fi

echo "  Python: Verifying signature..."
if ! model_signing \
	verify sigstore \
	--use_staging \
	--signature "${GO_SIG_SIGSTORE}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity_provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'verify sigstore' failed on Go-created signature"
	exit 1
fi
echo "  PASSED"
echo

echo "=========================================="
echo "PART 2: Python signs -> Go verifies"
echo "=========================================="
echo

# --- Key method ---
echo "[Python->Go] Testing 'key' method"

echo "  Python: Signing with key..."
if ! model_signing \
	sign key \
	--signature "${PY_SIG_KEY}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'sign key' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify key \
	--signature "${PY_SIG_KEY}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify key' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# --- Certificate method ---
echo "[Python->Go] Testing 'certificate' method"

echo "  Python: Signing with certificate..."
if ! model_signing \
	sign certificate \
	--signature "${PY_SIG_CERT}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--signing_certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate_chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Python 'sign certificate' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify certificate \
	--signature "${PY_SIG_CERT}" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify certificate' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# --- Sigstore method ---
echo "[Python->Go] Testing 'sigstore' method"

echo "  Python: Signing with sigstore (with OIDC token retry)..."
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity_token" \
	model_signing \
	sign sigstore \
	--signature "${PY_SIG_SIGSTORE}" \
	"${MODELDIR}"; then
	echo "  Error: Python 'sign sigstore' failed"
	exit 1
fi

echo "  Go: Verifying signature..."
if ! out=$(${DIR}/model-signing \
	verify sigstore \
	--signature "${PY_SIG_SIGSTORE}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity-provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Go 'verify sigstore' failed on Python-created signature"
	echo "  ${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "  Error: Go verification did not succeed"
	echo "  ${out}"
	exit 1
fi
echo "  PASSED"
echo

# --- PKCS#11 key method ---
echo "[Python->Go] Testing 'pkcs11-key' method"

# Check if SoftHSM2 is available
if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
	echo "  SKIPPED: SoftHSM2 or p11tool not available"
else
	echo "  Setting up SoftHSM2..."
	# Note: SoftHSM2 was already set up in PART 1, but it may have been torn down
	# Set it up again if needed
	if ! msg=$("${DIR}/softhsm_setup" setup 2>&1); then
		echo "  Error: Could not setup SoftHSM2"
		echo "  ${msg}"
		exit 1
	fi

	PY_SIG_PKCS11="${TMPDIR}/py-signed-pkcs11.sig"
	pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

	# Get public key from PKCS#11 token
	if ! "${DIR}/softhsm_setup" getpubkey > "${PKCS11_PUBKEY}" 2>/dev/null; then
		echo "  Error: Could not get PKCS#11 public key"
		exit 1
	fi

	echo "  Python: Signing with PKCS#11..."
	output=$(model_signing \
		sign pkcs11-key \
		--signature "${PY_SIG_PKCS11}" \
		--pkcs11_uri "${pkcs11uri}" \
		"${MODELDIR}" 2>&1)
	if [ $? -ne 0 ]; then
		echo "  Error: Python 'sign pkcs11-key' failed"
		echo "${output}"
		exit 1
	fi

	echo "  Go: Verifying signature..."
	if ! out=$(${DIR}/model-signing \
		verify key \
		--signature "${PY_SIG_PKCS11}" \
		--public-key "${PKCS11_PUBKEY}" \
		"${MODELDIR}" 2>&1); then
		echo "  Error: Go 'verify key' failed on Python PKCS#11 signature"
		echo "  ${out}"
		exit 1
	fi
	if ! grep -q "succeeded" <<< "${out}"; then
		echo "  Error: Go verification did not succeed"
		echo "  ${out}"
		exit 1
	fi
	echo "  PASSED"
fi
echo

# --- PKCS#11 certificate method ---
# SKIPPED: Python model-signing sign_pkcs11.py CertSigner has two bugs that
# prevent pkcs11-certificate signing from working:
#   - Empty certificate_chain crashes with MalformedFraming
#     https://github.com/sigstore/model-transparency/issues/613
#   - Missing base64.b64encode() on DER bytes in _get_verification_material
#     https://github.com/sigstore/model-transparency/issues/614
# Go->Python direction is tested in PART 1. Re-enable when upstream fixes land.
echo "[Python->Go] Testing 'pkcs11-certificate' method"
echo "  SKIPPED: Python model-signing has bugs in pkcs11 certificate signing"
echo "           https://github.com/sigstore/model-transparency/issues/613"
echo "           https://github.com/sigstore/model-transparency/issues/614"
echo

# echo "[Python->Go] Testing 'pkcs11-certificate' method"

# # Check if SoftHSM2 is available
# if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
# 	echo "  SKIPPED: SoftHSM2 or p11tool not available"
# else
# 	echo "  Setting up SoftHSM2..."
# 	# Note: SoftHSM2 was already set up in PART 1, but it may have been torn down
# 	# Set it up again if needed
# 	if ! msg=$("${DIR}/softhsm_setup" setup 2>&1); then
# 		echo "  Error: Could not setup SoftHSM2"
# 		echo "  ${msg}"
# 		exit 1
# 	fi

# 	PY_SIG_PKCS11_CERT="${TMPDIR}/py-signed-pkcs11-certificate.sig"
# 	pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

# 	# Export GNUTLS_PIN for automatic authentication
# 	export GNUTLS_PIN=1234

# 	echo "  Generating certificate from PKCS#11 key..."
# 	# Generate self-signed CA certificate
# 	if ! certtool --generate-self-signed \
# 		--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
# 		--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
# 		--outfile "${PKCS11_CERT}" \
# 		--template <(cat <<EOF
# cn = "PKCS11 Python Interop Test CA"
# organization = "Model Signing Interop Test"
# unit = "Testing"
# state = "California"
# country = US
# expiration_days = 365
# ca
# signing_key
# cert_signing_key
# EOF
# 	) >/dev/null 2>&1; then
# 		echo "  Error: Certificate generation failed"
# 		exit 1
# 	fi

# 	echo "  Python: Signing with PKCS#11 certificate..."
# 	if ! model_signing \
# 		sign pkcs11-certificate \
# 		--signature "${PY_SIG_PKCS11_CERT}" \
# 		--pkcs11_uri "${pkcs11uri}" \
# 		--signing_certificate "${PKCS11_CERT}" \
# 		"${MODELDIR}" >/dev/null 2>&1; then
# 		echo "  Error: Python 'sign pkcs11-certificate' failed"
# 		exit 1
# 	fi

# 	echo "  Go: Verifying signature..."
# 	if ! out=$(${DIR}/model-signing \
# 		verify certificate \
# 		--signature "${PY_SIG_PKCS11_CERT}" \
# 		--certificate-chain "${PKCS11_CERT}" \
# 		"${MODELDIR}" 2>&1); then
# 		echo "  Error: Go 'verify certificate' failed on Python PKCS#11 certificate signature"
# 		echo "  ${out}"
# 		exit 1
# 	fi
# 	if ! grep -q "succeeded" <<< "${out}"; then
# 		echo "  Error: Go verification did not succeed"
# 		echo "  ${out}"
# 		exit 1
# 	fi
# 	echo "  PASSED"
# fi
# echo

# --- PKCS#11 certificate chain method (CA + Leaf) ---
# SKIPPED: Same upstream bugs as pkcs11-certificate above.
#   https://github.com/sigstore/model-transparency/issues/613
#   https://github.com/sigstore/model-transparency/issues/614
# Re-enable when upstream fixes land.
echo "[Python->Go] Testing 'pkcs11-certificate-chain' method (CA + Leaf)"
echo "  SKIPPED: Python model-signing has bugs in pkcs11 certificate signing"
echo "           https://github.com/sigstore/model-transparency/issues/613"
echo "           https://github.com/sigstore/model-transparency/issues/614"
echo

# # --- PKCS#11 certificate chain method (CA + Leaf) ---
# echo "[Python->Go] Testing 'pkcs11-certificate-chain' method (CA + Leaf)"

# # Check if SoftHSM2 and certtool are available
# if ! command -v softhsm2-util &>/dev/null || ! command -v p11tool &>/dev/null; then
# 	echo "  SKIPPED: SoftHSM2 or p11tool not available"
# elif ! command -v certtool &>/dev/null; then
# 	echo "  SKIPPED: certtool not available"
# else
# 	echo "  Setting up SoftHSM2..."
# 	if ! msg=$("${DIR}/softhsm_setup" setup 2>&1); then
# 		echo "  Error: Could not setup SoftHSM2"
# 		echo "  ${msg}"
# 		exit 1
# 	fi

# 	pkcs11uri=$(echo "${msg}" | sed -n 's|^keyuri: \(.*\)|\1|p')

# 	# Export GNUTLS_PIN for automatic authentication
# 	export GNUTLS_PIN=1234

# 	echo "  Generating CA key and self-signed CA certificate..."
# 	if ! certtool --generate-privkey --outfile "${PKCS11_CA_KEY}" >/dev/null 2>&1; then
# 		echo "  Error: CA key generation failed"
# 		exit 1
# 	fi

# 	if ! certtool --generate-self-signed \
# 		--load-privkey "${PKCS11_CA_KEY}" \
# 		--outfile "${PKCS11_CA_CERT}" \
# 		--template <(cat <<'EOF'
# cn = PKCS11 Python Interop Test CA
# organization = Model Signing Interop Test
# country = US
# expiration_days = 365
# ca
# cert_signing_key
# EOF
# 	) >/dev/null 2>&1; then
# 		echo "  Error: CA certificate generation failed"
# 		exit 1
# 	fi

# 	echo "  Generating leaf signing certificate issued by CA..."
# 	if ! certtool --generate-certificate \
# 		--load-privkey "pkcs11:token=model-signing-test;object=mykey;type=private" \
# 		--load-pubkey "pkcs11:token=model-signing-test;object=mykey;type=public" \
# 		--load-ca-certificate "${PKCS11_CA_CERT}" \
# 		--load-ca-privkey "${PKCS11_CA_KEY}" \
# 		--outfile "${PKCS11_LEAF_CERT}" \
# 		--template <(cat <<'EOF'
# cn = PKCS11 Python Interop Test Signing Cert
# organization = Model Signing Interop Test
# country = US
# expiration_days = 365
# signing_key
# EOF
# 	) >/dev/null 2>&1; then
# 		echo "  Error: Leaf certificate generation failed"
# 		exit 1
# 	fi

# 	echo "  Python: Signing with PKCS#11 leaf certificate and chain..."
# 	output=$(model_signing \
# 		sign pkcs11-certificate \
# 		--signature "${PY_SIG_PKCS11_CHAIN}" \
# 		--pkcs11_uri "${pkcs11uri}" \
# 		--signing_certificate "${PKCS11_LEAF_CERT}" \
# 		--certificate_chain "${PKCS11_CA_CERT}" \
# 		"${MODELDIR}" 2>&1)
# 	if [ $? -ne 0 ]; then
# 		echo "  Error: Python 'sign pkcs11-certificate' with chain failed"
# 		echo "  ${output}"
# 		exit 1
# 	fi

# 	echo "  Go: Verifying signature..."
# 	if ! out=$(${DIR}/model-signing \
# 		verify certificate \
# 		--signature "${PY_SIG_PKCS11_CHAIN}" \
# 		--certificate-chain "${PKCS11_CA_CERT}" \
# 		"${MODELDIR}" 2>&1); then
# 		echo "  Error: Go 'verify certificate' failed on Python PKCS#11 chain signature"
# 		echo "  ${out}"
# 		exit 1
# 	fi
# 	if ! grep -q "succeeded" <<< "${out}"; then
# 		echo "  Error: Go verification did not succeed"
# 		echo "  ${out}"
# 		exit 1
# 	fi

# 	echo "  Python: Verifying signature (Python self-test)..."
# 	if ! model_signing \
# 		verify certificate \
# 		--signature "${PY_SIG_PKCS11_CHAIN}" \
# 		--certificate_chain "${PKCS11_CA_CERT}" \
# 		"${MODELDIR}" >/dev/null 2>&1; then
# 		echo "  Error: Python 'verify certificate' failed on Python PKCS#11 chain signature"
# 		exit 1
# 	fi
# 	echo "  PASSED"
# fi
# echo

# Deactivate venv
deactivate

echo "=========================================="
echo "All interoperability tests PASSED!"
echo "=========================================="

exit 0
