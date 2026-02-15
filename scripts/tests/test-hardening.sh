#!/usr/bin/env bash

# Hardening tests for model-signing
#
# This script tests:
# 1. Key type variations (RSA, ECDSA P-256, P-384, Ed25519)
# 2. Signature tampering detection
# 3. Model tampering detection
# 4. Edge case models
# 5. Certificate chain variations
# 6. Flag Combinations

set -e

DIR=${PWD}/$(dirname "$0")
TMPDIR=$(mktemp -d) || exit 1
KEYSDIR="${TMPDIR}/keys"

cleanup() {
	rm -rf "${TMPDIR}"
}
trap cleanup EXIT QUIT

mkdir -p "${KEYSDIR}"

echo "=== Hardening Tests for model-signing ==="
echo

generate_rsa_key() {
	local name="$1"
	local bits="${2:-2048}"
	openssl genrsa -out "${KEYSDIR}/${name}.pem" "${bits}" 2>/dev/null
	openssl rsa -in "${KEYSDIR}/${name}.pem" -pubout -out "${KEYSDIR}/${name}-pub.pem" 2>/dev/null
}

generate_ecdsa_key() {
	local name="$1"
	local curve="$2"
	openssl ecparam -name "${curve}" -genkey -noout -out "${KEYSDIR}/${name}.pem" 2>/dev/null
	openssl ec -in "${KEYSDIR}/${name}.pem" -pubout -out "${KEYSDIR}/${name}-pub.pem" 2>/dev/null
}

generate_ed25519_key() {
	local name="$1"
	openssl genpkey -algorithm Ed25519 -out "${KEYSDIR}/${name}.pem" 2>/dev/null
	openssl pkey -in "${KEYSDIR}/${name}.pem" -pubout -out "${KEYSDIR}/${name}-pub.pem" 2>/dev/null
}

create_test_model() {
	local modeldir="$1"
	mkdir -p "${modeldir}"
	echo "file1-content" > "${modeldir}/file1.txt"
	echo "file2-content" > "${modeldir}/file2.txt"
}

echo "=========================================="
echo "PART 1: Key Type Variations"
echo "=========================================="
echo

MODELDIR="${TMPDIR}/model-keytypes"
create_test_model "${MODELDIR}"

# --- RSA 2048 ---
echo "[Key Types] Testing RSA 2048..."
generate_rsa_key "rsa2048" 2048
SIGFILE="${TMPDIR}/rsa2048.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/rsa2048.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with RSA 2048 failed"
	exit 1
fi

if ! out=$(${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/rsa2048-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Verify with RSA 2048 failed"
	echo "  ${out}"
	exit 1
fi
echo "  RSA 2048: PASSED"

# --- RSA 4096 ---
echo "[Key Types] Testing RSA 4096..."
generate_rsa_key "rsa4096" 4096
SIGFILE="${TMPDIR}/rsa4096.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/rsa4096.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with RSA 4096 failed"
	exit 1
fi

if ! out=$(${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/rsa4096-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Verify with RSA 4096 failed"
	echo "  ${out}"
	exit 1
fi
echo "  RSA 4096: PASSED"

# --- ECDSA P-256 ---
echo "[Key Types] Testing ECDSA P-256..."
generate_ecdsa_key "ecdsa-p256" "prime256v1"
SIGFILE="${TMPDIR}/ecdsa-p256.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/ecdsa-p256.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with ECDSA P-256 failed"
	exit 1
fi

if ! out=$(${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/ecdsa-p256-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Verify with ECDSA P-256 failed"
	echo "  ${out}"
	exit 1
fi
echo "  ECDSA P-256: PASSED"

# --- ECDSA P-384 ---
echo "[Key Types] Testing ECDSA P-384..."
generate_ecdsa_key "ecdsa-p384" "secp384r1"
SIGFILE="${TMPDIR}/ecdsa-p384.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/ecdsa-p384.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with ECDSA P-384 failed"
	exit 1
fi

if ! out=$(${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/ecdsa-p384-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Verify with ECDSA P-384 failed"
	echo "  ${out}"
	exit 1
fi
echo "  ECDSA P-384: PASSED"

# --- ECDSA P-521 (unsupported by sigstore protobuf specs — should be rejected) ---
echo "[Key Types] Testing ECDSA P-521 rejection (unsupported curve)..."
generate_ecdsa_key "ecdsa-p521" "secp521r1"
SIGFILE="${TMPDIR}/ecdsa-p521.sig"

if ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/ecdsa-p521.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with ECDSA P-521 should have been rejected"
	exit 1
fi
echo "  ECDSA P-521 rejected: PASSED"

# --- Ed25519 ---
echo "[Key Types] Testing Ed25519..."
generate_ed25519_key "ed25519"
SIGFILE="${TMPDIR}/ed25519.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/ed25519.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with Ed25519 failed"
	exit 1
fi

if ! out=$(${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/ed25519-pub.pem" \
	"${MODELDIR}" 2>&1); then
	echo "  Error: Verify with Ed25519 failed"
	echo "  ${out}"
	exit 1
fi
echo "  Ed25519: PASSED"

echo

echo "=========================================="
echo "PART 2: Signature Tampering Detection"
echo "=========================================="
echo

MODELDIR="${TMPDIR}/model-tampering"
create_test_model "${MODELDIR}"

# Create a valid signature first
generate_ecdsa_key "tamper-key" "prime256v1"
generate_ecdsa_key "wrong-key" "prime256v1"
SIGFILE="${TMPDIR}/tamper-test.sig"

${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/tamper-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1

# --- Wrong public key ---
echo "[Tampering] Testing wrong public key detection..."
if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/wrong-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed with wrong public key"
	exit 1
fi
echo "  Wrong public key rejected: PASSED"

# --- Truncated signature ---
echo "[Tampering] Testing truncated signature detection..."
TRUNCATED_SIG="${TMPDIR}/truncated.sig"
head -c 100 "${SIGFILE}" > "${TRUNCATED_SIG}"

if ${DIR}/model-signing verify key \
	--signature "${TRUNCATED_SIG}" \
	--public-key "${KEYSDIR}/tamper-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed with truncated signature"
	exit 1
fi
echo "  Truncated signature rejected: PASSED"

# --- Modified signature (flip a byte) ---
echo "[Tampering] Testing modified signature detection..."
MODIFIED_SIG="${TMPDIR}/modified.sig"
cp "${SIGFILE}" "${MODIFIED_SIG}"
# Modify a byte in the middle of the file
python3 -c "
import sys
with open('${MODIFIED_SIG}', 'r+b') as f:
    f.seek(100)
    b = f.read(1)
    f.seek(100)
    f.write(bytes([(b[0] ^ 0xFF)]))
" 2>/dev/null || {
	# Fallback if python not available
	dd if=/dev/urandom of="${MODIFIED_SIG}" bs=1 count=1 seek=100 conv=notrunc 2>/dev/null
}

if ${DIR}/model-signing verify key \
	--signature "${MODIFIED_SIG}" \
	--public-key "${KEYSDIR}/tamper-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed with modified signature"
	exit 1
fi
echo "  Modified signature rejected: PASSED"

# --- Empty signature file ---
echo "[Tampering] Testing empty signature detection..."
EMPTY_SIG="${TMPDIR}/empty.sig"
touch "${EMPTY_SIG}"

if ${DIR}/model-signing verify key \
	--signature "${EMPTY_SIG}" \
	--public-key "${KEYSDIR}/tamper-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed with empty signature"
	exit 1
fi
echo "  Empty signature rejected: PASSED"

echo

echo "=========================================="
echo "PART 3: Model Tampering Detection"
echo "=========================================="
echo

MODELDIR="${TMPDIR}/model-integrity"
create_test_model "${MODELDIR}"

generate_ecdsa_key "integrity-key" "prime256v1"
SIGFILE="${TMPDIR}/integrity-test.sig"

${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/integrity-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1

# Verify the original works
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Original signature should verify"
	exit 1
fi
echo "  Original signature verifies: PASSED"

# --- File added ---
echo "[Model Tampering] Testing file added detection..."
echo "new-file-content" > "${MODELDIR}/newfile.txt"

if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed after file added"
	exit 1
fi
echo "  File added detected: PASSED"

rm "${MODELDIR}/newfile.txt"

# --- File removed ---
echo "[Model Tampering] Testing file removed detection..."
mv "${MODELDIR}/file2.txt" "${TMPDIR}/file2.txt.bak"

if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed after file removed"
	exit 1
fi
echo "  File removed detected: PASSED"

mv "${TMPDIR}/file2.txt.bak" "${MODELDIR}/file2.txt"

# --- File content modified ---
echo "[Model Tampering] Testing file content modified detection..."
echo "modified-content" > "${MODELDIR}/file1.txt"

if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed after file modified"
	exit 1
fi
echo "  File content modified detected: PASSED"

echo "file1-content" > "${MODELDIR}/file1.txt"

# --- File renamed ---
echo "[Model Tampering] Testing file renamed detection..."
mv "${MODELDIR}/file1.txt" "${MODELDIR}/file1-renamed.txt"

if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed after file renamed"
	exit 1
fi
echo "  File renamed detected: PASSED"

mv "${MODELDIR}/file1-renamed.txt" "${MODELDIR}/file1.txt"

# Verify restoration works
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/integrity-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Restored model should verify"
	exit 1
fi
echo "  Model restoration verifies: PASSED"

echo

echo "=========================================="
echo "PART 4: Edge Case Models"
echo "=========================================="
echo

generate_ecdsa_key "edge-key" "prime256v1"

# --- Single file model ---
echo "[Edge Cases] Testing single file model..."
MODELDIR="${TMPDIR}/model-single"
mkdir -p "${MODELDIR}"
echo "single-file" > "${MODELDIR}/only-file.txt"
SIGFILE="${TMPDIR}/single.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign single file model failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify single file model failed"
	exit 1
fi
echo "  Single file model: PASSED"

# --- Deep nested directories ---
echo "[Edge Cases] Testing deep nested directories (10 levels)..."
MODELDIR="${TMPDIR}/model-deep"
DEEPPATH="${MODELDIR}/l1/l2/l3/l4/l5/l6/l7/l8/l9/l10"
mkdir -p "${DEEPPATH}"
echo "deep-file" > "${DEEPPATH}/deep.txt"
echo "root-file" > "${MODELDIR}/root.txt"
SIGFILE="${TMPDIR}/deep.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign deep nested model failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify deep nested model failed"
	exit 1
fi
echo "  Deep nested directories: PASSED"

# --- Files with spaces in names ---
echo "[Edge Cases] Testing files with spaces in names..."
MODELDIR="${TMPDIR}/model-spaces"
mkdir -p "${MODELDIR}"
echo "space file" > "${MODELDIR}/file with spaces.txt"
echo "another" > "${MODELDIR}/another file.txt"
SIGFILE="${TMPDIR}/spaces.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with spaces failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with spaces failed"
	exit 1
fi
echo "  Files with spaces: PASSED"

# --- Files with special characters ---
echo "[Edge Cases] Testing files with special characters..."
MODELDIR="${TMPDIR}/model-special"
mkdir -p "${MODELDIR}"
echo "special1" > "${MODELDIR}/file-with-dash.txt"
echo "special2" > "${MODELDIR}/file_with_underscore.txt"
echo "special3" > "${MODELDIR}/file.multiple.dots.txt"
echo "special4" > "${MODELDIR}/file@symbol.txt"
SIGFILE="${TMPDIR}/special.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with special chars failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with special chars failed"
	exit 1
fi
echo "  Files with special characters: PASSED"

# --- Hidden files (dotfiles) ---
echo "[Edge Cases] Testing hidden files (dotfiles)..."
MODELDIR="${TMPDIR}/model-hidden"
mkdir -p "${MODELDIR}"
echo "visible" > "${MODELDIR}/visible.txt"
echo "hidden" > "${MODELDIR}/.hidden"
echo "hidden2" > "${MODELDIR}/.hidden-file.txt"
SIGFILE="${TMPDIR}/hidden.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with hidden files failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with hidden files failed"
	exit 1
fi
echo "  Hidden files (dotfiles): PASSED"

# --- Empty files ---
echo "[Edge Cases] Testing empty files..."
MODELDIR="${TMPDIR}/model-empty-files"
mkdir -p "${MODELDIR}"
touch "${MODELDIR}/empty1.txt"
touch "${MODELDIR}/empty2.bin"
echo "non-empty" > "${MODELDIR}/nonempty.txt"
SIGFILE="${TMPDIR}/empty-files.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with empty files failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with empty files failed"
	exit 1
fi
echo "  Empty files: PASSED"

# --- Many small files ---
echo "[Edge Cases] Testing many small files (100 files)..."
MODELDIR="${TMPDIR}/model-many"
mkdir -p "${MODELDIR}"
for i in $(seq 1 100); do
	echo "content-${i}" > "${MODELDIR}/file-${i}.txt"
done
SIGFILE="${TMPDIR}/many.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with many files failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with many files failed"
	exit 1
fi
echo "  Many small files (100): PASSED"

# --- Unicode filenames ---
echo "[Edge Cases] Testing unicode filenames..."
MODELDIR="${TMPDIR}/model-unicode"
mkdir -p "${MODELDIR}"
echo "chinese" > "${MODELDIR}/文件.txt" 2>/dev/null || true
echo "japanese" > "${MODELDIR}/ファイル.txt" 2>/dev/null || true
echo "emoji" > "${MODELDIR}/file_🎉.txt" 2>/dev/null || true
echo "normal" > "${MODELDIR}/normal.txt"
SIGFILE="${TMPDIR}/unicode.sig"

if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/edge-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign model with unicode filenames failed"
	exit 1
fi

if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/edge-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify model with unicode filenames failed"
	exit 1
fi
echo "  Unicode filenames: PASSED"

echo

echo "=========================================="
echo "PART 5: Certificate Chain Variations"
echo "=========================================="
echo

MODELDIR="${TMPDIR}/model-certs"
create_test_model "${MODELDIR}"

CERTSDIR="${KEYSDIR}/certs"
mkdir -p "${CERTSDIR}"

# --- Self-signed certificate ---
echo "[Cert Chain] Testing self-signed certificate..."

# Generate self-signed cert with required extensions
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/self-signed-key.pem" \
	-out "${CERTSDIR}/self-signed-cert.pem" \
	-days 1 -nodes \
	-subj "/CN=Self-Signed Test" \
	-addext "keyUsage=digitalSignature" \
	-addext "extendedKeyUsage=codeSigning" 2>/dev/null

SIGFILE="${TMPDIR}/self-signed.sig"

if ! ${DIR}/model-signing sign certificate \
	--signature "${SIGFILE}" \
	--private-key "${CERTSDIR}/self-signed-key.pem" \
	--signing-certificate "${CERTSDIR}/self-signed-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with self-signed cert failed"
	exit 1
fi

if ! ${DIR}/model-signing verify certificate \
	--signature "${SIGFILE}" \
	--certificate-chain "${CERTSDIR}/self-signed-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify with self-signed cert failed"
	exit 1
fi
echo "  Self-signed certificate: PASSED"

# --- 2-level chain (Root -> Leaf) ---
echo "[Cert Chain] Testing 2-level chain (Root -> Leaf)..."

# Generate root CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/root-ca-key.pem" \
	-out "${CERTSDIR}/root-ca-cert.pem" \
	-days 1 -nodes \
	-subj "/CN=Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Generate leaf cert signed by root
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/leaf-key.pem" \
	-out "${CERTSDIR}/leaf-csr.pem" \
	-nodes \
	-subj "/CN=Leaf Cert" 2>/dev/null

openssl x509 -req -in "${CERTSDIR}/leaf-csr.pem" \
	-CA "${CERTSDIR}/root-ca-cert.pem" \
	-CAkey "${CERTSDIR}/root-ca-key.pem" \
	-CAcreateserial \
	-out "${CERTSDIR}/leaf-cert.pem" \
	-days 1 \
	-extfile <(echo -e "keyUsage=digitalSignature\nextendedKeyUsage=codeSigning") 2>/dev/null

SIGFILE="${TMPDIR}/2level.sig"

if ! ${DIR}/model-signing sign certificate \
	--signature "${SIGFILE}" \
	--private-key "${CERTSDIR}/leaf-key.pem" \
	--signing-certificate "${CERTSDIR}/leaf-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with 2-level chain failed"
	exit 1
fi

if ! ${DIR}/model-signing verify certificate \
	--signature "${SIGFILE}" \
	--certificate-chain "${CERTSDIR}/root-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify with 2-level chain failed"
	exit 1
fi
echo "  2-level chain (Root -> Leaf): PASSED"

# --- 3-level chain (Root -> Intermediate -> Leaf) ---
echo "[Cert Chain] Testing 3-level chain (Root -> Intermediate -> Leaf)..."

# Generate intermediate CA
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/int-ca-key.pem" \
	-out "${CERTSDIR}/int-ca-csr.pem" \
	-nodes \
	-subj "/CN=Intermediate CA" 2>/dev/null

openssl x509 -req -in "${CERTSDIR}/int-ca-csr.pem" \
	-CA "${CERTSDIR}/root-ca-cert.pem" \
	-CAkey "${CERTSDIR}/root-ca-key.pem" \
	-CAcreateserial \
	-out "${CERTSDIR}/int-ca-cert.pem" \
	-days 1 \
	-extfile <(echo -e "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") 2>/dev/null

# Generate leaf cert signed by intermediate
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/leaf3-key.pem" \
	-out "${CERTSDIR}/leaf3-csr.pem" \
	-nodes \
	-subj "/CN=Leaf3 Cert" 2>/dev/null

openssl x509 -req -in "${CERTSDIR}/leaf3-csr.pem" \
	-CA "${CERTSDIR}/int-ca-cert.pem" \
	-CAkey "${CERTSDIR}/int-ca-key.pem" \
	-CAcreateserial \
	-out "${CERTSDIR}/leaf3-cert.pem" \
	-days 1 \
	-extfile <(echo -e "keyUsage=digitalSignature\nextendedKeyUsage=codeSigning") 2>/dev/null

SIGFILE="${TMPDIR}/3level.sig"

if ! ${DIR}/model-signing sign certificate \
	--signature "${SIGFILE}" \
	--private-key "${CERTSDIR}/leaf3-key.pem" \
	--signing-certificate "${CERTSDIR}/leaf3-cert.pem" \
	--certificate-chain "${CERTSDIR}/int-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign with 3-level chain failed"
	exit 1
fi

if ! ${DIR}/model-signing verify certificate \
	--signature "${SIGFILE}" \
	--certificate-chain "${CERTSDIR}/root-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify with 3-level chain failed"
	exit 1
fi
echo "  3-level chain (Root -> Int -> Leaf): PASSED"

# --- Wrong CA certificate (should fail) ---
echo "[Cert Chain] Testing wrong CA certificate detection..."

# Generate a different root CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "${CERTSDIR}/wrong-ca-key.pem" \
	-out "${CERTSDIR}/wrong-ca-cert.pem" \
	-days 1 -nodes \
	-subj "/CN=Wrong CA" 2>/dev/null

if ${DIR}/model-signing verify certificate \
	--signature "${SIGFILE}" \
	--certificate-chain "${CERTSDIR}/wrong-ca-cert.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should have failed with wrong CA"
	exit 1
fi
echo "  Wrong CA certificate rejected: PASSED"

echo

echo "=========================================="
echo "PART 6: Flag Combinations"
echo "=========================================="
echo

MODELDIR="${TMPDIR}/model-flags"
mkdir -p "${MODELDIR}"
echo "file1-content" > "${MODELDIR}/file1.txt"
echo "file2-content" > "${MODELDIR}/file2.txt"
echo "ignore-me" > "${MODELDIR}/ignore-me.txt"

generate_ecdsa_key "flags-key" "prime256v1"

# --- Test --ignore-paths ---
echo "[Flags] Testing --ignore-paths..."
SIGFILE="${TMPDIR}/ignore-paths.sig"

# Sign without ignore-paths
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign failed"
	exit 1
fi

# Add a file that should be ignored
echo "new-ignored" > "${MODELDIR}/should-ignore.txt"

# Verify should fail without --ignore-paths
if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should fail with extra file"
	exit 1
fi

# Verify should pass with --ignore-paths
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--ignore-paths "${MODELDIR}/should-ignore.txt" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should pass with --ignore-paths"
	exit 1
fi
echo "  --ignore-paths: PASSED"

rm "${MODELDIR}/should-ignore.txt"

# --- Test --ignore-unsigned-files ---
echo "[Flags] Testing --ignore-unsigned-files..."
SIGFILE="${TMPDIR}/ignore-unsigned.sig"

# Sign the model
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign failed"
	exit 1
fi

# Add multiple unsigned files
echo "unsigned1" > "${MODELDIR}/unsigned1.txt"
echo "unsigned2" > "${MODELDIR}/unsigned2.txt"
mkdir -p "${MODELDIR}/unsigned-dir"
echo "unsigned3" > "${MODELDIR}/unsigned-dir/unsigned3.txt"

# Verify should fail without flag
if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should fail with unsigned files"
	exit 1
fi

# Verify should pass with --ignore-unsigned-files
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--ignore-unsigned-files \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should pass with --ignore-unsigned-files"
	exit 1
fi
echo "  --ignore-unsigned-files: PASSED"

rm -rf "${MODELDIR}/unsigned1.txt" "${MODELDIR}/unsigned2.txt" "${MODELDIR}/unsigned-dir"

# --- Test --allow-symlinks ---
echo "[Flags] Testing --allow-symlinks..."
SIGFILE="${TMPDIR}/symlinks.sig"
SIGFILE_NO_SYMLINK="${TMPDIR}/symlinks-no.sig"

# Create a symlink
echo "target-content" > "${MODELDIR}/target.txt"
ln -s target.txt "${MODELDIR}/link.txt"

# Sign without --allow-symlinks succeeds but skips symlinks
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE_NO_SYMLINK}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign should succeed (symlinks are skipped by default)"
	exit 1
fi

# Sign with --allow-symlinks includes symlinks in signature
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	--allow-symlinks \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign should succeed with --allow-symlinks"
	exit 1
fi

# Verify signature that includes symlinks requires --allow-symlinks
# Without the flag, verification fails because symlink is in signature but skipped
if ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify should fail when signature includes symlink but flag not passed"
	exit 1
fi

# Verify with --allow-symlinks should succeed
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--allow-symlinks \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify should succeed with --allow-symlinks"
	exit 1
fi

# Verify signature without symlinks also works (symlinks skipped during verify)
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE_NO_SYMLINK}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify should succeed when symlinks are skipped"
	exit 1
fi
echo "  --allow-symlinks: PASSED"

rm "${MODELDIR}/link.txt"

# --- Test combined flags: --ignore-paths + --ignore-unsigned-files ---
echo "[Flags] Testing --ignore-paths + --ignore-unsigned-files..."
SIGFILE="${TMPDIR}/combined1.sig"

# Sign with --ignore-paths
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign failed"
	exit 1
fi

# Add both an unsigned file and modify an ignored file
echo "new-unsigned" > "${MODELDIR}/new-unsigned.txt"
echo "modified-ignore" > "${MODELDIR}/ignore-me.txt"

# Verify with both flags should pass
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	--ignore-unsigned-files \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should pass with combined flags"
	exit 1
fi
echo "  --ignore-paths + --ignore-unsigned-files: PASSED"

rm "${MODELDIR}/new-unsigned.txt"
echo "ignore-me" > "${MODELDIR}/ignore-me.txt"

# --- Test combined flags: --allow-symlinks + --ignore-unsigned-files ---
echo "[Flags] Testing --allow-symlinks + --ignore-unsigned-files..."
SIGFILE="${TMPDIR}/combined2.sig"

# Create symlink for signing
ln -s target.txt "${MODELDIR}/link.txt"

# Sign with --allow-symlinks
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	--allow-symlinks \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign failed"
	exit 1
fi

# Add an unsigned symlink
echo "new-target" > "${MODELDIR}/new-target.txt"
ln -s new-target.txt "${MODELDIR}/new-link.txt"

# Verify with both flags should pass
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--allow-symlinks \
	--ignore-unsigned-files \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should pass with --allow-symlinks + --ignore-unsigned-files"
	exit 1
fi
echo "  --allow-symlinks + --ignore-unsigned-files: PASSED"

rm "${MODELDIR}/link.txt" "${MODELDIR}/new-link.txt" "${MODELDIR}/new-target.txt"

# --- Test all three flags combined ---
echo "[Flags] Testing --ignore-paths + --allow-symlinks + --ignore-unsigned-files..."
SIGFILE="${TMPDIR}/combined3.sig"

# Create model with symlink
ln -s target.txt "${MODELDIR}/link.txt"

# Sign with --ignore-paths and --allow-symlinks
if ! ${DIR}/model-signing sign key \
	--signature "${SIGFILE}" \
	--private-key "${KEYSDIR}/flags-key.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	--allow-symlinks \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign failed"
	exit 1
fi

# Add unsigned file, modify ignored file, add unsigned symlink
echo "modified-ignore" > "${MODELDIR}/ignore-me.txt"
echo "new-unsigned" > "${MODELDIR}/new-unsigned.txt"
echo "new-target" > "${MODELDIR}/new-target.txt"
ln -s new-target.txt "${MODELDIR}/new-link.txt"

# Verify with all flags should pass
if ! ${DIR}/model-signing verify key \
	--signature "${SIGFILE}" \
	--public-key "${KEYSDIR}/flags-key-pub.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	--allow-symlinks \
	--ignore-unsigned-files \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verification should pass with all three flags"
	exit 1
fi
echo "  All three flags combined: PASSED"

rm "${MODELDIR}/link.txt" "${MODELDIR}/new-link.txt" "${MODELDIR}/new-target.txt" "${MODELDIR}/new-unsigned.txt"
echo "ignore-me" > "${MODELDIR}/ignore-me.txt"

# --- Test certificate method with flags ---
echo "[Flags] Testing certificate method with flag combinations..."
SIGFILE="${TMPDIR}/cert-flags.sig"

# Recreate model with symlink
ln -s target.txt "${MODELDIR}/link.txt"

# Sign with certificate and flags
if ! ${DIR}/model-signing sign certificate \
	--signature "${SIGFILE}" \
	--private-key "${CERTSDIR}/self-signed-key.pem" \
	--signing-certificate "${CERTSDIR}/self-signed-cert.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	--allow-symlinks \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Sign certificate with flags failed"
	exit 1
fi

# Add unsigned file
echo "new-unsigned" > "${MODELDIR}/new-unsigned.txt"

# Verify with certificate and flags
if ! ${DIR}/model-signing verify certificate \
	--signature "${SIGFILE}" \
	--certificate-chain "${CERTSDIR}/self-signed-cert.pem" \
	--ignore-paths "${MODELDIR}/ignore-me.txt" \
	--allow-symlinks \
	--ignore-unsigned-files \
	"${MODELDIR}" >/dev/null 2>&1; then
	echo "  Error: Verify certificate with flags failed"
	exit 1
fi
echo "  Certificate method with flags: PASSED"

echo

echo "=========================================="
echo "All hardening tests PASSED!"
echo "=========================================="

exit 0
