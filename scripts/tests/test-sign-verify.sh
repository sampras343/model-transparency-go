#!/usr/bin/env bash

DIR=${PWD}/$(dirname "$0")
TMPDIR=$(mktemp -d) || exit 1
signfile1="${TMPDIR}/signme-1"
signfile2="${TMPDIR}/signme-2"
ignorefile="${TMPDIR}/ignore"
sigfile="${TMPDIR}/model.sig"
echo "signme-1" > "${signfile1}"
echo "signme-2" > "${signfile2}"
echo "ignore" > "${ignorefile}"

cleanup()
{
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

source "${DIR}/functions"

echo "Testing 'sign/verify key'"

if ! ${DIR}/model-signing \
	sign key \
	--signature "${sigfile}" \
	--private-key ./keys/certificate/signing-key.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign key' failed"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify key \
	--signature "${sigfile}" \
	--public-key ./keys/certificate/signing-key-pub.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify key' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi

echo
echo "Testing 'sign/verify' certificate"

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "${sigfile}" \
	--private-key ./keys/certificate/signing-key.pem \
	--signing-certificate ./keys/certificate/signing-key-cert.pem \
	--certificate-chain ./keys/certificate/int-ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify certificate \
	--signature "${sigfile}" \
	--certificate-chain ./keys/certificate/ca-cert.pem \
	--ignore-paths "${ignorefile}" \
	"${TMPDIR}"; then
	echo "Error: 'verify certificate' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

# Enter the model directory and sign and verify there
pushd "${TMPDIR}" &>/dev/null || exit 1

echo
echo "Testing 'sign key' when in model directory"

if ! ${DIR}/model-signing \
	sign key \
	--signature "$(basename "${sigfile}")" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'sign key' failed"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify key \
	--signature "$(basename "${sigfile}")" \
	--public-key "${DIR}/keys/certificate/signing-key-pub.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify key' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Testing 'sign/verify' certificate when in model directory"

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "$(basename "${sigfile}")" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

if ! ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify certificate' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Creating a symlink, that is not part of the signature, to make signature verification fail (1)"

echo "foo" > symlinked
ln -s symlinked symlink

if ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file (symlink) was created"
	exit 1
fi

# This should pass without having to pass --allow-symlinks since the symlink
# will be ignored
echo
echo "Pass signature verification by ignoring any unsigned files or symlinks"
if ! ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--ignore-unsigned-files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore-unsigned-files while passing --allow-symlinks"
	exit 1
fi


rm -f symlinked symlink

echo
echo "Testing 'sign/verify' certificate when in subdir of model directory and using '..'"

rm -f "$(basename "${sigfile}")"
mkdir subdir

# Create a symlink'ed file
echo "foo" > subdir/symlinked
ln -s subdir/symlinked symlink

pushd subdir 1>/dev/null || exit 1

if ! ${DIR}/model-signing \
	sign certificate \
	--signature "../$(basename "${sigfile}")" \
	--private-key "${DIR}/keys/certificate/signing-key.pem" \
	--signing-certificate "${DIR}/keys/certificate/signing-key-cert.pem" \
	--certificate-chain "${DIR}/keys/certificate/int-ca-cert.pem" \
	--ignore-paths "../$(basename "${ignorefile}")" \
	--allow-symlinks \
	.. ; then
	echo "Error: 'sign certificate' failed"
	exit 1
fi

popd 1>/dev/null || exit 1   # exit subdir

if ! ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow-symlinks \
	. ; then
	echo "Error: 'verify certificate' failed"
	exit 1
fi

# Check which files are part of signature
res=$(get_signed_files "${sigfile}")
exp='["signme-1","signme-2","subdir/symlinked","symlink"]'
if [ "${res}" != "${exp}" ]; then
	echo "Error: Unexpected files were signed"
	echo "Expected: ${exp}"
	echo "Actual  : ${res}"
	exit 1
fi
check_model_name "${sigfile}" "$(basename "${TMPDIR}")"

echo
echo "Creating a symlink, that is not part of the signature, to make signature verification fail (2)"

# Create another symlinked file
ln -s subdir/symlinked symlink2

echo
echo "Fail signature verification by NOT ignoring any unsigned (symlinks)"
if ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow-symlinks \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file (symlink) was created"
	exit 1
fi

echo
echo "Pass signature verification by ignoring any unsigned files"
if ! ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow-symlinks \
	--ignore-unsigned-files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore-unsigned-files to ignore symlink"
	exit 1
fi

rm symlink2

# Create a simple new file
echo
echo "Creating a regular file that is not part of the signature"
touch newfile

echo
echo "Fail signature verification by NOT ignoring any unsigned files (symlinks)"
if ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow-symlinks \
	. ; then
	echo "Error: 'verify certificate' succeeded after new file was created"
	exit 1
fi

echo
echo "Pass signature verification by ignoring any unsigned files"
if ! ${DIR}/model-signing \
	verify certificate \
	--signature "$(basename "${sigfile}")" \
	--certificate-chain "${DIR}/keys/certificate/ca-cert.pem" \
	--ignore-paths "$(basename "${ignorefile}")" \
	--allow-symlinks \
	--ignore-unsigned-files \
	. ; then
	echo "Error: 'verify certificate' failed with --ignore-unsigned-files to ignore regular file"
	exit 1
fi

popd 1>/dev/null || exit 1

# PKCS#11 tests (skip if SoftHSM2 not available)
if command -v softhsm2-util &>/dev/null && command -v p11tool &>/dev/null; then
	echo
	echo "Testing 'sign/verify' with PKCS#11"
	
	# Create a fresh directory for PKCS#11 tests
	pkcs11_tmpdir=$(mktemp -d) || exit 1
	pkcs11_signfile1="${pkcs11_tmpdir}/signme-1"
	pkcs11_signfile2="${pkcs11_tmpdir}/signme-2"
	pkcs11_ignorefile="${pkcs11_tmpdir}/ignore"
	pkcs11_sigfile="${pkcs11_tmpdir}/model.sig"
	echo "signme-1" > "${pkcs11_signfile1}"
	echo "signme-2" > "${pkcs11_signfile2}"
	echo "ignore" > "${pkcs11_ignorefile}"
	
	# Setup SoftHSM2
	if ! setup_output=$("${DIR}/softhsm_setup" setup 2>&1); then
		echo "Error: Could not setup SoftHSM2"
		echo "${setup_output}"
		rm -rf "${pkcs11_tmpdir}"
		exit 1
	fi
	
	pkcs11uri=$(echo "${setup_output}" | sed -n 's|^keyuri: \(.*\)|\1|p')
	pkcs11_pubkey=$(mktemp) || exit 1
	
	# Get public key
	if ! "${DIR}/softhsm_setup" getpubkey > "${pkcs11_pubkey}"; then
		echo "Error: Could not get PKCS#11 public key"
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
		rm -rf "${pkcs11_tmpdir}"
		rm -f "${pkcs11_pubkey}"
		exit 1
	fi
	
	# Sign with PKCS#11
	if ! ${DIR}/model-signing \
		sign pkcs11-key \
		--signature "${pkcs11_sigfile}" \
		--pkcs11-uri "${pkcs11uri}" \
		--ignore-paths "${pkcs11_ignorefile}" \
		"${pkcs11_tmpdir}"; then
		echo "Error: 'sign pkcs11-key' failed"
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
		rm -rf "${pkcs11_tmpdir}"
		rm -f "${pkcs11_pubkey}"
		exit 1
	fi
	
	# Verify with public key
	if ! ${DIR}/model-signing \
		verify key \
		--signature "${pkcs11_sigfile}" \
		--public-key "${pkcs11_pubkey}" \
		--ignore-paths "${pkcs11_ignorefile}" \
		"${pkcs11_tmpdir}"; then
		echo "Error: 'verify key' failed on PKCS#11 signature"
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
		rm -rf "${pkcs11_tmpdir}"
		rm -f "${pkcs11_pubkey}"
		exit 1
	fi
	
	# Check which files are part of signature
	res=$(get_signed_files "${pkcs11_sigfile}")
	exp='["signme-1","signme-2"]'
	if [ "${res}" != "${exp}" ]; then
		echo "Error: Unexpected files were signed"
		echo "Expected: ${exp}"
		echo "Actual  : ${res}"
		"${DIR}/softhsm_setup" teardown &>/dev/null || true
		rm -rf "${pkcs11_tmpdir}"
		rm -f "${pkcs11_pubkey}"
		exit 1
	fi
	
	# Cleanup SoftHSM2 and temp directory
	"${DIR}/softhsm_setup" teardown &>/dev/null || true
	rm -rf "${pkcs11_tmpdir}"
	rm -f "${pkcs11_pubkey}"
	
	echo "PKCS#11 tests passed"
else
	echo
	echo "Skipping PKCS#11 tests (SoftHSM2 or p11tool not available)"
fi
