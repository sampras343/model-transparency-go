#!/usr/bin/env bash

# This script tests the Go model-signing binary:
# 1. Signs a model using key, certificate, and sigstore methods
# 2. Verifies the signatures
# 3. Verifies pre-created signatures from older versions

DIR=${PWD}/$(dirname "$0")
TMPDIR=$(mktemp -d) || exit 1
MODELDIR="${TMPDIR}/model"

signfile1="${MODELDIR}/signme-1"
signfile2="${MODELDIR}/signme-2"
ignorefile="${MODELDIR}/ignore"

cleanup()
{
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

mkdir "${MODELDIR}" || exit 1
echo "signme-1" > "${signfile1}"
echo "signme-2" > "${signfile2}"
echo "ignore" > "${ignorefile}"

sigfile_key="${TMPDIR}/model.sig-key"
sigfile_certificate="${TMPDIR}/model.sig-certificate"
sigfile_sigstore="${TMPDIR}/model.sig-sigstore"

TOKENPROJ="${TMPDIR}/tokenproj"
mkdir -p "${TOKENPROJ}" || exit 1
token_file="${TOKENPROJ}/oidc-token.txt"

# Print version info
echo -n "Using model-signing binary: "
${DIR}/model-signing version 2>/dev/null || echo "(version command not available)"

echo

# Sign with key method
echo "Signing with 'key' method"

if ! ${DIR}/model-signing \
	sign key \
	--signature "${sigfile_key}" \
	--private-key ${DIR}/keys/certificate/signing-key.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f "${sigfile_key}"; then
	echo "Error: 'sign key' failed"
	exit 1
fi

# Sign with certificate method
echo "Signing with 'certificate' method"

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile_certificate}" \
	--private-key ${DIR}/keys/certificate/signing-key.pem \
	--signing-certificate ${DIR}/keys/certificate/signing-key-cert.pem \
	--certificate-chain ${DIR}/keys/certificate/int-ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f "${sigfile_certificate}"; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

# Sign with sigstore method
echo "Getting OIDC test-token for sigstore signing"
if ! out=$(git clone \
	--single-branch \
	--branch current-token \
	--depth 1 \
	https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon \
	"${TOKENPROJ}" 2>&1);
then
	echo "git clone failed"
	echo "${out}"
	exit 1
fi

echo "Signing with 'sigstore' method"
if ! ${DIR}/model-signing \
	sign sigstore \
	--signature "${sigfile_sigstore}" \
	--identity-token "$(cat "${token_file}")" \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" || \
  test ! -f ${sigfile_sigstore}; then
	echo "Error: 'sign sigstore' failed"
	exit 1
fi

# Verify the signatures we just created
echo
echo "=== Verifying freshly created signatures ==="

echo "Testing 'verify key' method"
if ! out=$(${DIR}/model-signing \
	verify key \
	--signature "${sigfile_key}" \
	--public-key ${DIR}/keys/certificate/signing-key-pub.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" 2>&1); then
	echo "Error: 'verify key' failed"
	echo "${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "verification failed:"
	echo "${out}"
	exit 1
fi

echo "Testing 'verify certificate' method"
if ! out=$(${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile_certificate}" \
	--certificate-chain ${DIR}/keys/certificate/ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" 2>&1); then
	echo "Error: 'verify certificate' failed"
	echo "${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "verification failed:"
	echo "${out}"
	exit 1
fi

echo "Testing 'verify sigstore' method"
if ! out=$(${DIR}/model-signing \
	verify sigstore \
	--signature "${sigfile_sigstore}" \
	--identity https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
	--identity-provider https://token.actions.githubusercontent.com \
	--ignore-paths "${ignorefile}" \
	"${MODELDIR}" 2>&1); then
	echo "Error: 'verify sigstore' failed"
	echo "${out}"
	exit 1
fi
if ! grep -q "succeeded" <<< "${out}"; then
	echo "verification failed:"
	echo "${out}"
	exit 1
fi

# Check against pre-created signatures from older versions
echo
echo "=== Verifying pre-created signatures from older versions ==="

# v represents version of the library that created a signature in the past
for v in v1.1.0 v1.0.1 v1.0.0 v0.3.1 v0.2.0; do

	# key method
	modeldir=${DIR}/${v}-elliptic-key
	modeldir_sign=${modeldir}

	# Build ignore args only if ignore-me exists
	ignore_args=()
	if [ -e "${modeldir}/ignore-me" ]; then
		ignore_args=(--ignore-paths "${modeldir}/ignore-me")
	fi

	case "${v}" in
	v0.3.1|v1.0.0)
		# These versions signed only a single file
		modeldir_sign="${modeldir}/signme-1"
		;&  # fallthrough
	*)
		if [ -d "${modeldir}" ]; then
			echo "Testing 'verify key' method with signature created by ${v}"
			if ! out=$(${DIR}/model-signing \
				verify key \
				--signature "${modeldir}/model.sig" \
				--public-key ${DIR}/keys/certificate/signing-key-pub.pem \
				"${ignore_args[@]}" \
				"${modeldir_sign}" 2>&1); then
				echo "Error: 'verify key' failed on ${modeldir}"
				echo "${out}"
				exit 1
			fi
			if ! grep -q "succeeded" <<< "${out}"; then
				echo "verification failed on ${modeldir}:"
				echo "${out}"
				exit 1
			fi
		fi
		;;
	esac

	# certificate method
	modeldir=${DIR}/${v}-certificate

	# Build ignore args only if ignore-me exists
	ignore_args=()
	if [ -e "${modeldir}/ignore-me" ]; then
		ignore_args=(--ignore-paths "${modeldir}/ignore-me")
	fi

	if [ -d "${modeldir}" ]; then
		echo "Testing 'verify certificate' method with signature created by ${v}"
		if ! out=$(${DIR}/model-signing \
			verify certificate \
			--signature "${modeldir}/model.sig" \
			--certificate-chain ${DIR}/keys/certificate/ca-cert.pem \
			"${ignore_args[@]}" \
			"${modeldir}" 2>&1); then
			echo "Error: 'verify certificate' failed on ${modeldir}"
			echo "${out}"
			exit 1
		fi
		if ! grep -q "succeeded" <<< "${out}"; then
			echo "verification failed on ${modeldir}:"
			echo "${out}"
			exit 1
		fi
	fi

	# sigstore method
	modeldir=${DIR}/${v}-sigstore

	# Build ignore args only if ignore-me exists
	ignore_args=()
	if [ -e "${modeldir}/ignore-me" ]; then
		ignore_args=(--ignore-paths "${modeldir}/ignore-me")
	fi

	if [ -d "${modeldir}" ]; then
		echo "Testing 'verify sigstore' method with signature created by ${v}"
		if ! out=$(${DIR}/model-signing \
			verify sigstore \
			--signature "${modeldir}/model.sig" \
			--identity-provider https://sigstore.verify.ibm.com/oauth2 \
			--identity stefanb@us.ibm.com \
			"${ignore_args[@]}" \
			"${modeldir}" 2>&1); then
			echo "Error: 'verify sigstore' failed on ${modeldir}"
			echo "${out}"
			exit 1
		fi
		if ! grep -q "succeeded" <<< "${out}"; then
			echo "verification failed on ${modeldir}:"
			echo "${out}"
			exit 1
		fi
	fi
done

echo
echo "All tests passed!"
exit 0
