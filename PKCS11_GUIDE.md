# PKCS#11 Signing and Verification Guide

Complete guide for PKCS#11 signing with SoftHSM2.

---

## Quick Reference

**Sign:**
```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 MODEL \
  --pkcs11-uri "$SOFTHSM2_URI" --signature SIG
```

**Verify:**
```bash
# Export public key (once)
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 --read-object --type pubkey --label mykey -o public-key.der
openssl ec -pubin -inform DER -in public-key.der -outform PEM -out public-key.pem

# Verify
./build/model-signing verify key MODEL --signature SIG --public-key public-key.pem
```

---

## Quick Start

```bash
# 1. Setup (first time only)
./setup-softhsm2.sh

# 2. Load configuration
source softhsm2-config.sh

# 3. Sign a model
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$SOFTHSM2_URI" \
  --signature test-model.sig

# 4. Export public key (once, reuse for all verifications)
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 \
  --read-object --type pubkey --label mykey \
  -o public-key.der

openssl ec -pubin -inform DER -in public-key.der \
  -outform PEM -out public-key.pem

# 5. Verify the signature
./build/model-signing verify key test-model \
  --signature test-model.sig \
  --public-key public-key.pem
```

---

## Setup

### Install SoftHSM2

**Fedora/RHEL:**
```bash
sudo dnf install softhsm
```

**Ubuntu/Debian:**
```bash
sudo apt-get install softhsm2
```

### Run Setup Script

```bash
./setup-softhsm2.sh
```

This will:
- Find the SoftHSM2 module
- Create config in `~/.config/softhsm2/`
- Initialize a token named "mytoken"
- Generate an EC P-256 key pair

---

## Signing

### Basic Signing

```bash
# Load configuration
source softhsm2-config.sh

# Sign
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 MODEL_PATH \
  --pkcs11-uri "$SOFTHSM2_URI" \
  --signature SIGNATURE_FILE
```

### Example

```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$SOFTHSM2_URI" \
  --signature test-model.sig
```

### Verbose Mode

Add `-d` flag:
```bash
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$SOFTHSM2_URI" --signature test-model.sig -d
```

### Without Environment Variables

```bash
SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf" \
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "pkcs11:token=mytoken;object=mykey?module-path=/usr/lib64/pkcs11/libsofthsm2.so&pin-value=1234" \
  --signature test-model.sig
```

---

## Verification

### Export Public Key (One Time)

```bash
source softhsm2-config.sh

# Export from token (DER format)
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 \
  --read-object --type pubkey --label mykey \
  -o public-key.der

# Convert to PEM format
openssl ec -pubin -inform DER -in public-key.der -outform PEM -out public-key.pem
```

### Verify Signature

```bash
./build/model-signing verify key MODEL_PATH \
  --signature SIGNATURE_FILE \
  --public-key public-key.pem
```

### Example

```bash
./build/model-signing verify key test-model \
  --signature test-model.sig \
  --public-key public-key.pem
```

---

## Certificate-Based Signing (Advanced)

### Generate Test Certificate

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 365 -nodes \
  -subj "/CN=Test Certificate"
```

### Sign with Certificate

```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$SOFTHSM2_URI" \
  --signing-certificate test-cert.pem \
  --signature test-model-cert.sig
```

### Verify with Certificate

```bash
./build/model-signing verify certificate test-model \
  --signature test-model-cert.sig \
  --certificate-chain test-cert.pem
```

---

## Command Reference

### Sign a Model
```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 MODEL_PATH \
  --pkcs11-uri "$SOFTHSM2_URI" \
  --signature SIGNATURE_FILE
```

### Verify a Model
```bash
# Step 1: Export public key (do once, reuse for all verifications)
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 --read-object --type pubkey --label mykey -o public-key.der
openssl ec -pubin -inform DER -in public-key.der -outform PEM -out public-key.pem

# Step 2: Verify
./build/model-signing verify key MODEL_PATH \
  --signature SIGNATURE_FILE \
  --public-key public-key.pem
```

### Check Token
```bash
SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf" softhsm2-util --show-slots
```

### List Keys
```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 --list-objects
```

---

## Troubleshooting

### "Failed to enumerate object store"
**Solution:** Run `./setup-softhsm2.sh` (uses home directory)

### "no such file or directory" for module
**Check location:**
```bash
find /usr/lib* -name "libsofthsm2.so"
```
Use the path in `/usr/lib64/pkcs11/` or `/usr/lib/x86_64-linux-gnu/softhsm/`

### "Could not find any object with label"
**List available objects:**
```bash
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 --list-objects
```

### "Key mismatch" warning during verification

If you see:
```
WARNING: Key mismatch: The public key hash in the signature's verification material (...) 
does not match the provided public key (...). Proceeding with verification anyway.
```

**Possible causes:**
1. The public key was exported from a different key than the one used for signing
2. Multiple keys exist in your token with the same label

**Solution - Re-sign and re-export with matching keys:**
```bash
# Run the fix script
./fix-pkcs11-verify.sh
```

**Or manually:**
```bash
# 1. Clean up
rm -f test-model*.sig public-key.*

# 2. Sign
source softhsm2-config.sh
SOFTHSM2_CONF="$SOFTHSM2_CONF" ./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$SOFTHSM2_URI" --signature test-model.sig

# 3. Export public key (immediately after signing)
SOFTHSM2_CONF="$SOFTHSM2_CONF" pkcs11-tool --module $SOFTHSM2_MODULE_PATH \
  --login --pin 1234 --read-object --type pubkey --label mykey -o public-key.der
openssl ec -pubin -inform DER -in public-key.der -outform PEM -out public-key.pem

# 4. Verify
./build/model-signing verify key test-model --signature test-model.sig --public-key public-key.pem
```

**Note:** If verification succeeds despite the warning, the signature is cryptographically valid. The warning indicates metadata mismatch, not signature invalidity.

---

### Verification fails
**Check public key format:**
```bash
cat public-key.pem
# Should start with: -----BEGIN PUBLIC KEY-----
```

**Re-export if needed:**
```bash
openssl ec -pubin -inform DER -in public-key.der -outform PEM -out public-key.pem
```

---

## File Locations

| What | Where |
|------|-------|
| Config | `~/.config/softhsm2/softhsm2.conf` |
| Tokens | `~/.config/softhsm2/tokens/` |
| Module | `/usr/lib64/pkcs11/libsofthsm2.so` |
| Helper script | `./softhsm2-config.sh` |

---

## Environment Variables

When you run `source softhsm2-config.sh`:

| Variable | Value |
|----------|-------|
| `SOFTHSM2_CONF` | Config file path |
| `SOFTHSM2_MODULE_PATH` | Module library path |
| `SOFTHSM2_URI` | Complete PKCS#11 URI |

---

## Security Notes

⚠️ **For testing only!**
- Never use hardcoded PINs in production
- Use `pin-source=file:///path/to/pin.txt` instead of `pin-value`
- Protect PIN files: `chmod 600 pin.txt`
- Keep `~/.config/softhsm2/` secure

---

## Additional Resources

- Package documentation: `pkg/signing/pkcs11/README.md`
- SoftHSM2: https://www.opendnssec.org/softhsm/
- PKCS#11 URI RFC: https://tools.ietf.org/html/rfc7512
