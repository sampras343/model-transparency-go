#!/usr/bin/env bash

# This script tests cross-signing and cross-verification between OCI manifests
# and local directories across all strategies (key, certificate, sigstore):
#
# 1. Installs ORAS CLI and Python model_signing package
# 2. Creates model files and pushes them as an OCI artifact to a local registry
# 3. Retrieves the OCI manifest
# 4. Go-only: sign with manifest → verify with directory, and vice versa
# 5. Cross-language: Go signs manifest → Python verifies directory, and vice versa
# 6. Runs negative tests (tampered model detection)

set -euo pipefail

DIR=${PWD}/$(dirname "$0")
source "${DIR}/functions"

TMPDIR=$(mktemp -d) || exit 1
MODELDIR="${TMPDIR}/model"
VENV="${TMPDIR}/venv"
REGISTRY_CONTAINER=""

cleanup()
{
	if [ -n "${REGISTRY_CONTAINER}" ]; then
		docker rm -f "${REGISTRY_CONTAINER}" >/dev/null 2>&1 || true
	fi
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

# ============================================================
# Setup: Install ORAS
# ============================================================
echo "=== Installing ORAS CLI ==="

if ! command -v oras &>/dev/null; then
	ORAS_VERSION="1.2.2"
	curl -sLO "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz"
	tar -xzf "oras_${ORAS_VERSION}_linux_amd64.tar.gz" -C /usr/local/bin oras
	rm -f "oras_${ORAS_VERSION}_linux_amd64.tar.gz"
fi
oras version

# ============================================================
# Setup: Install Python model_signing
# ============================================================
echo
echo "=== Setting up Python environment ==="

python3 -m venv "${VENV}" || exit 1
source "${VENV}/bin/activate"

if ! pip install --quiet model-signing==1.1.1; then
	echo "Error: Failed to install model-signing Python package"
	exit 1
fi

echo -n "Python model_signing version: "
model_signing --version

# ============================================================
# Setup: Create model files
# ============================================================
echo
echo "=== Creating model files ==="

mkdir -p "${MODELDIR}"
echo "model-weights-data" > "${MODELDIR}/model.safetensors"
echo "tokenizer-config" > "${MODELDIR}/tokenizer.json"

echo "Created model files in ${MODELDIR}"
ls -la "${MODELDIR}"

# ============================================================
# Setup: Start local OCI registry and push artifact
# ============================================================
echo
echo "=== Starting local OCI registry ==="

REGISTRY_CONTAINER=$(docker run -d -p 0:5000 registry:2)
REGISTRY_PORT=$(docker inspect --format='{{(index (index .NetworkSettings.Ports "5000/tcp") 0).HostPort}}' "${REGISTRY_CONTAINER}")
REGISTRY="localhost:${REGISTRY_PORT}"

for i in $(seq 1 30); do
	if curl -sf "http://${REGISTRY}/v2/" >/dev/null 2>&1; then
		break
	fi
	if [ "${i}" -eq 30 ]; then
		echo "Error: Registry failed to start"
		exit 1
	fi
	sleep 1
done
echo "Registry ready at ${REGISTRY}"

echo
echo "=== Pushing model files as OCI artifact ==="

IMAGE_REF="${REGISTRY}/test/tiny-model:v1"

pushd "${MODELDIR}" >/dev/null
oras push --plain-http "${IMAGE_REF}" \
	model.safetensors:application/octet-stream \
	tokenizer.json:application/octet-stream
popd >/dev/null

MANIFEST="${TMPDIR}/oci-manifest.json"
echo "Retrieving OCI manifest..."
oras manifest fetch --plain-http "${IMAGE_REF}" > "${MANIFEST}"

echo "OCI manifest:"
jq . "${MANIFEST}"

# ============================================================
# KEY strategy: cross-verification tests
# ============================================================

sigfile_key_manifest="${TMPDIR}/model.sig-key-manifest"
sigfile_key_dir="${TMPDIR}/model.sig-key-dir"

echo
echo "=== KEY strategy: cross-verification tests ==="

# Sign with OCI manifest, verify with local directory
echo
echo "Test 1: Sign OCI manifest → Verify local directory (key)"

${DIR}/model-signing \
	sign key \
	--signature "${sigfile_key_manifest}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--ignore-paths config.json \
	"${MANIFEST}"

${DIR}/model-signing \
	verify key \
	--signature "${sigfile_key_manifest}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}"

echo "  PASSED"

# Sign with local directory, verify with OCI manifest
echo
echo "Test 2: Sign local directory → Verify OCI manifest (key)"

${DIR}/model-signing \
	sign key \
	--signature "${sigfile_key_dir}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify key \
	--signature "${sigfile_key_dir}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# ============================================================
# CERTIFICATE strategy: cross-verification tests
# ============================================================

sigfile_cert_manifest="${TMPDIR}/model.sig-cert-manifest"
sigfile_cert_dir="${TMPDIR}/model.sig-cert-dir"

echo
echo "=== CERTIFICATE strategy: cross-verification tests ==="

# Sign with OCI manifest, verify with local directory
echo
echo "Test 3: Sign OCI manifest → Verify local directory (certificate)"

${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_cert_manifest}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	--ignore-paths config.json \
	"${MANIFEST}"

${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_cert_manifest}" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}"

echo "  PASSED"

# Sign with local directory, verify with OCI manifest
echo
echo "Test 4: Sign local directory → Verify OCI manifest (certificate)"

${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_cert_dir}" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_cert_dir}" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# ============================================================
# SIGSTORE strategy: cross-verification tests
# ============================================================

sigfile_sigstore_manifest="${TMPDIR}/model.sig-sigstore-manifest"
sigfile_sigstore_dir="${TMPDIR}/model.sig-sigstore-dir"

TOKENPROJ="${TMPDIR}/tokenproj"
mkdir -p "${TOKENPROJ}"
token_file="${TOKENPROJ}/oidc-token.txt"

SIGSTORE_IDENTITY="https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"

echo
echo "=== SIGSTORE strategy: cross-verification tests ==="

# Sign with OCI manifest, verify with local directory
echo
echo "Test 5: Sign OCI manifest → Verify local directory (sigstore)"

sigstore_sign_with_retry "${TOKENPROJ}" "${token_file}" "--identity-token" \
	${DIR}/model-signing \
	sign sigstore \
	--use-staging \
	--signature "${sigfile_sigstore_manifest}" \
	--ignore-paths config.json \
	"${MANIFEST}"

${DIR}/model-signing \
	verify sigstore \
	--use-staging \
	--signature "${sigfile_sigstore_manifest}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity-provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}"

echo "  PASSED"

# Sign with local directory, verify with OCI manifest
echo
echo "Test 6: Sign local directory → Verify OCI manifest (sigstore)"

sigstore_sign_with_retry "${TOKENPROJ}" "${token_file}" "--identity-token" \
	${DIR}/model-signing \
	sign sigstore \
	--use-staging \
	--signature "${sigfile_sigstore_dir}" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify sigstore \
	--use-staging \
	--signature "${sigfile_sigstore_dir}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity-provider "${SIGSTORE_ISSUER}" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# ============================================================
# CROSS-LANGUAGE: Go signs OCI manifest → Python verifies directory
# ============================================================
echo
echo "=== CROSS-LANGUAGE: Go signs OCI manifest → Python verifies directory ==="

# Key
echo
echo "Test 7: Go signs OCI manifest → Python verifies directory (key)"

# Reuse sigfile_key_manifest from Test 1 (Go signed OCI manifest with --ignore-paths config.json)
model_signing \
	verify key \
	--signature "${sigfile_key_manifest}" \
	--public_key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}"

echo "  PASSED"

# Certificate
echo
echo "Test 8: Go signs OCI manifest → Python verifies directory (certificate)"

# Reuse sigfile_cert_manifest from Test 3
model_signing \
	verify certificate \
	--signature "${sigfile_cert_manifest}" \
	--certificate_chain "${DIR}/keys/certificate/ca-cert.pem" \
	"${MODELDIR}"

echo "  PASSED"

# Sigstore — use production (not staging) for cross-language compatibility
sigfile_go_sigstore_prod="${TMPDIR}/model.sig-go-sigstore-prod"

echo
echo "Test 9: Go signs OCI manifest → Python verifies directory (sigstore)"

sigstore_sign_with_retry "${TOKENPROJ}" "${token_file}" "--identity-token" \
	${DIR}/model-signing \
	sign sigstore \
	--signature "${sigfile_go_sigstore_prod}" \
	--ignore-paths config.json \
	"${MANIFEST}"

model_signing \
	verify sigstore \
	--signature "${sigfile_go_sigstore_prod}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity_provider "${SIGSTORE_ISSUER}" \
	"${MODELDIR}"

echo "  PASSED"

# ============================================================
# CROSS-LANGUAGE: Python signs directory → Go verifies OCI manifest
# ============================================================

py_sig_key="${TMPDIR}/model.sig-py-key"
py_sig_cert="${TMPDIR}/model.sig-py-cert"
py_sig_sigstore="${TMPDIR}/model.sig-py-sigstore"

echo
echo "=== CROSS-LANGUAGE: Python signs directory → Go verifies OCI manifest ==="

# Key
echo
echo "Test 10: Python signs directory → Go verifies OCI manifest (key)"

model_signing \
	sign key \
	--signature "${py_sig_key}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify key \
	--signature "${py_sig_key}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# Certificate
echo
echo "Test 11: Python signs directory → Go verifies OCI manifest (certificate)"

model_signing \
	sign certificate \
	--signature "${py_sig_cert}" \
	--private_key "${DIR}/keys/certificate/signing-key.pem" \
	--signing_certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate_chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify certificate \
	--signature "${py_sig_cert}" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# Sigstore
echo
echo "Test 12: Python signs directory → Go verifies OCI manifest (sigstore)"

sigstore_sign_with_retry "${TOKENPROJ}" "${token_file}" "--identity_token" \
	model_signing \
	sign sigstore \
	--signature "${py_sig_sigstore}" \
	"${MODELDIR}"

${DIR}/model-signing \
	verify sigstore \
	--signature "${py_sig_sigstore}" \
	--identity "${SIGSTORE_IDENTITY}" \
	--identity-provider "${SIGSTORE_ISSUER}" \
	--ignore-unsigned-files \
	"${MANIFEST}"

echo "  PASSED"

# ============================================================
# Negative tests
# ============================================================
echo
echo "=== Negative tests ==="

echo
echo "Test 13: Verification fails after tampering with model file"

echo "tampered-data" >> "${MODELDIR}/model.safetensors"

if ${DIR}/model-signing \
	verify key \
	--signature "${sigfile_key_manifest}" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	"${MODELDIR}" 2>/dev/null; then
	echo "Error: 'verify key' should have failed after tampering"
	exit 1
fi

echo "  PASSED (verification correctly failed)"

# Deactivate venv
deactivate

echo
echo "All OCI manifest cross-verification tests passed!"
exit 0
