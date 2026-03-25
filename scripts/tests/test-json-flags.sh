#!/usr/bin/env bash
# Integration tests for global --json: inline object, stdin (-), and filesystem path.

set -euo pipefail

DIR=${PWD}/$(dirname "$0")
BINARY="${DIR}/model-signing"
KEYDIR="${DIR}/keys/certificate"

source "${DIR}/functions"

MODELDIR=$(mktemp -d) || exit 1
WORKDIR=$(mktemp -d) || exit 1
signfile1="${MODELDIR}/signme-1"
signfile2="${MODELDIR}/signme-2"
ignorefile="${MODELDIR}/ignore"
sigfile="${WORKDIR}/model.sig"
params_json="${WORKDIR}/params.json"
params_alt="${WORKDIR}/params.conf"
verify_json="${WORKDIR}/verify.json"
bad_not_object="${WORKDIR}/bad-not-object.any"

echo "signme-1" >"${signfile1}"
echo "signme-2" >"${signfile2}"
echo "ignore" >"${ignorefile}"

cleanup() {
	rm -rf "${MODELDIR}" "${WORKDIR}"
}
trap cleanup EXIT QUIT

if [[ ! -x "${BINARY}" ]]; then
	echo "Error: missing executable ${BINARY} (run make build-test-binary from repo root)"
	exit 1
fi

for util in jq git; do
	if ! type -P "${util}" >/dev/null; then
		echo "Could not find '${util}' in PATH."
		exit 1
	fi
done

echo ">>> --json file path (sign key + verify key)"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigfile}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "ignore-paths": $ign}' >"${params_json}"

if ! "${BINARY}" sign key --json "${params_json}"; then
	echo "Error: sign key with --json file failed"
	exit 1
fi

jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigfile}" \
	--arg pub "${KEYDIR}/signing-key-pub.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "public-key": $pub, "ignore-paths": $ign}' >"${verify_json}"

if ! "${BINARY}" verify key --json "${verify_json}"; then
	echo "Error: verify key with --json file failed"
	exit 1
fi

echo ">>> --json stdin (-) (sign key)"
if ! jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigfile}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "ignore-paths": $ign}' |
	"${BINARY}" sign key --json -; then
	echo "Error: sign key with --json - (stdin) failed"
	exit 1
fi

echo ">>> verify key (inline --json string)"
if ! "${BINARY}" verify key \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${sigfile}" \
		--arg pub "${KEYDIR}/signing-key-pub.pem" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "public-key": $pub, "ignore-paths": $ign}')"; then
	echo "Error: verify key with inline --json failed"
	exit 1
fi

echo ">>> verify key (--json stdin -)"
if ! jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigfile}" \
	--arg pub "${KEYDIR}/signing-key-pub.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "public-key": $pub, "ignore-paths": $ign}' |
	"${BINARY}" verify key --json -; then
	echo "Error: verify key with --json - (stdin) failed"
	exit 1
fi

echo ">>> --json non-.json extension (same payload)"
cp "${params_json}" "${params_alt}"
if ! "${BINARY}" sign key --json "${params_alt}" --signature "${sigfile}.alt"; then
	echo "Error: sign key with .conf --json file failed"
	exit 1
fi

echo ">>> merge: --json file then inline overrides signature path"
sig_override="${WORKDIR}/override.sig"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigfile}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "ignore-paths": $ign}' >"${params_json}"
if ! "${BINARY}" sign key --json "${params_json}" --json "$(jq -n --arg s "${sig_override}" '{"signature": $s}')"; then
	echo "Error: merged --json (file + inline) failed"
	exit 1
fi
if [[ ! -f "${sig_override}" ]]; then
	echo "Error: expected signature at override path from second --json"
	exit 1
fi

echo ">>> CLI flag overrides --json (bogus signature in file, correct on CLI)"
bogus_sig="${WORKDIR}/bogus.sig"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${bogus_sig}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "ignore-paths": $ign}' >"${params_json}"
if ! "${BINARY}" sign key --json "${params_json}" --signature "${sigfile}"; then
	echo "Error: sign key with CLI override of signature failed"
	exit 1
fi
if [[ ! -f "${sigfile}" ]]; then
	echo "Error: expected CLI --signature to win over JSON file"
	exit 1
fi

echo ">>> expect failure: --json missing file"
if "${BINARY}" sign key --json "${WORKDIR}/does-not-exist-$$.json" 2>/dev/null; then
	echo "Error: expected non-zero exit for missing --json file"
	exit 1
fi

echo ">>> expect failure: --json path is a directory"
if "${BINARY}" sign key --json "${MODELDIR}" 2>/dev/null; then
	echo "Error: expected non-zero exit when --json points at a directory"
	exit 1
fi

echo ">>> expect failure: file content is not a JSON object"
echo '[1,2,3]' >"${bad_not_object}"
if "${BINARY}" sign key --json "${bad_not_object}" 2>/dev/null; then
	echo "Error: expected non-zero exit for non-object JSON file"
	exit 1
fi

echo ">>> expect failure: certificate-only flag in sign key --json"
if "${BINARY}" sign key \
	--json "$(jq -n --arg sc "${KEYDIR}/signing-key-cert.pem" '{"signing-certificate": $sc}')" \
	2>/dev/null; then
	echo "Error: expected non-zero exit for signing-certificate on sign key"
	exit 1
fi

echo ">>> expect failure: key-verify-only flag in sign certificate --json"
if "${BINARY}" sign certificate \
	--json "$(jq -n --arg pub "${KEYDIR}/signing-key-pub.pem" '{"public-key": $pub}')" \
	2>/dev/null; then
	echo "Error: expected non-zero exit for public-key on sign certificate"
	exit 1
fi

echo ">>> expect failure: certificate-only flag in verify key --json"
if "${BINARY}" verify key \
	--json "$(jq -n --arg cc "${KEYDIR}/ca-cert.pem" '{"certificate-chain": $cc}')" \
	"${MODELDIR}" \
	2>/dev/null; then
	echo "Error: expected non-zero exit for certificate-chain on verify key"
	exit 1
fi

echo ">>> expect failure: key-verify-only flag in verify certificate --json"
if "${BINARY}" verify certificate \
	--json "$(jq -n --arg pub "${KEYDIR}/signing-key-pub.pem" '{"public-key": $pub}')" \
	"${MODELDIR}" \
	2>/dev/null; then
	echo "Error: expected non-zero exit for public-key on verify certificate"
	exit 1
fi

cert_sig_file="${WORKDIR}/model.sig-cert-file"
cert_sig_inline="${WORKDIR}/model.sig-cert-inline"
cert_sig_stdin="${WORKDIR}/model.sig-cert-stdin"
sign_cert_json="${WORKDIR}/sign-certificate.json"
verify_cert_json="${WORKDIR}/verify-certificate.json"

echo ">>> sign certificate (--json file)"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${cert_sig_file}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg sc "${KEYDIR}/signing-key-cert.pem" \
	--arg cc "${KEYDIR}/int-ca-cert.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "signing-certificate": $sc, "certificate-chain": $cc, "ignore-paths": $ign}' >"${sign_cert_json}"

if ! "${BINARY}" sign certificate --json "${sign_cert_json}"; then
	echo "Error: sign certificate with --json file failed"
	exit 1
fi

echo ">>> verify certificate (--json file)"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${cert_sig_file}" \
	--arg cc "${KEYDIR}/ca-cert.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "certificate-chain": $cc, "ignore-paths": $ign}' >"${verify_cert_json}"

if ! "${BINARY}" verify certificate --json "${verify_cert_json}"; then
	echo "Error: verify certificate with --json file failed"
	exit 1
fi

echo ">>> sign certificate (inline --json string)"
if ! "${BINARY}" sign certificate \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${cert_sig_inline}" \
		--arg pk "${KEYDIR}/signing-key.pem" \
		--arg sc "${KEYDIR}/signing-key-cert.pem" \
		--arg cc "${KEYDIR}/int-ca-cert.pem" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "private-key": $pk, "signing-certificate": $sc, "certificate-chain": $cc, "ignore-paths": $ign}')"; then
	echo "Error: sign certificate with inline --json failed"
	exit 1
fi

echo ">>> verify certificate (inline --json string)"
if ! "${BINARY}" verify certificate \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${cert_sig_inline}" \
		--arg cc "${KEYDIR}/ca-cert.pem" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "certificate-chain": $cc, "ignore-paths": $ign}')"; then
	echo "Error: verify certificate with inline --json failed"
	exit 1
fi

echo ">>> sign certificate (--json stdin -)"
if ! jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${cert_sig_stdin}" \
	--arg pk "${KEYDIR}/signing-key.pem" \
	--arg sc "${KEYDIR}/signing-key-cert.pem" \
	--arg cc "${KEYDIR}/int-ca-cert.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "private-key": $pk, "signing-certificate": $sc, "certificate-chain": $cc, "ignore-paths": $ign}' |
	"${BINARY}" sign certificate --json -; then
	echo "Error: sign certificate with --json - (stdin) failed"
	exit 1
fi

echo ">>> verify certificate (--json stdin -)"
if ! jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${cert_sig_stdin}" \
	--arg cc "${KEYDIR}/ca-cert.pem" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, "certificate-chain": $cc, "ignore-paths": $ign}' |
	"${BINARY}" verify certificate --json -; then
	echo "Error: verify certificate with --json - (stdin) failed"
	exit 1
fi

# OIDC beacon + staging (same identity/issuer pattern as test-otel.sh / test-sign-verify-allversions.sh).
SIGSTORE_IDENTITY="https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"
TOKENPROJ="${WORKDIR}/tokenproj-sigstore"
TOKEN_FILE="${TOKENPROJ}/oidc-token.txt"
sigstore_sig="${WORKDIR}/model.sig-sigstore-json"
sigstore_sig_inline="${WORKDIR}/model.sig-sigstore-inline"
sigstore_sig_stdin="${WORKDIR}/model.sig-sigstore-stdin"
verify_sigstore_json="${WORKDIR}/verify-sigstore.json"

# sigstore_sign_with_retry appends the token to "$@"; stdin must go to the binary, not the wrapper shell.
_sign_sigstore_json_on_stdin() {
	jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${sigstore_sig_stdin}" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "ignore-paths": $ign, "use-staging": true}' |
		"${BINARY}" sign sigstore --json - "$@"
}

echo ">>> sign sigstore (inline --json string, bundle for verify --json file)"
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity-token" \
	"${BINARY}" sign sigstore \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${sigstore_sig}" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "ignore-paths": $ign, "use-staging": true}')"; then
	echo "Error: sign sigstore (first inline bundle) failed"
	exit 1
fi

echo ">>> verify sigstore (--json file)"
jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigstore_sig}" \
	--arg id "${SIGSTORE_IDENTITY}" \
	--arg prov "${SIGSTORE_ISSUER}" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, identity: $id, "identity-provider": $prov, "ignore-paths": $ign, "use-staging": true}' >"${verify_sigstore_json}"

if ! "${BINARY}" verify sigstore --json "${verify_sigstore_json}"; then
	echo "Error: verify sigstore with --json file failed"
	exit 1
fi

echo ">>> sign sigstore (inline --json string)"
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity-token" \
	"${BINARY}" sign sigstore \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${sigstore_sig_inline}" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, "ignore-paths": $ign, "use-staging": true}')"; then
	echo "Error: sign sigstore with inline --json failed"
	exit 1
fi

echo ">>> verify sigstore (inline --json string)"
if ! "${BINARY}" verify sigstore \
	--json "$(jq -n \
		--arg model "${MODELDIR}" \
		--arg sig "${sigstore_sig_inline}" \
		--arg id "${SIGSTORE_IDENTITY}" \
		--arg prov "${SIGSTORE_ISSUER}" \
		--arg ign "${ignorefile}" \
		'{model: $model, signature: $sig, identity: $id, "identity-provider": $prov, "ignore-paths": $ign, "use-staging": true}')"; then
	echo "Error: verify sigstore with inline --json failed"
	exit 1
fi

echo ">>> sign sigstore (--json stdin -)"
if ! sigstore_sign_with_retry "${TOKENPROJ}" "${TOKEN_FILE}" "--identity-token" \
	_sign_sigstore_json_on_stdin; then
	echo "Error: sign sigstore with --json - (stdin) failed"
	exit 1
fi

echo ">>> verify sigstore (--json stdin -)"
if ! jq -n \
	--arg model "${MODELDIR}" \
	--arg sig "${sigstore_sig_stdin}" \
	--arg id "${SIGSTORE_IDENTITY}" \
	--arg prov "${SIGSTORE_ISSUER}" \
	--arg ign "${ignorefile}" \
	'{model: $model, signature: $sig, identity: $id, "identity-provider": $prov, "ignore-paths": $ign, "use-staging": true}' |
	"${BINARY}" verify sigstore --json -; then
	echo "Error: verify sigstore with --json - (stdin) failed"
	exit 1
fi

echo "All --json integration checks passed."
