# PKCS#11 Signing and Verification Guide

Complete guide for PKCS#11 signing with SoftHSM2, following the same approach as the Python implementation.

---

## Quick Reference

**Sign:**
```bash
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 MODEL --pkcs11-uri "$keyuri" --signature SIG
```

**Verify:**
```bash
# Export public key (once)
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem

# Verify
./build/model-signing verify key MODEL --signature SIG --public-key public-key.pem
```

---

## Quick Start

```bash
# 1. Setup SoftHSM2 (first time only)
scripts/pkcs11-tests/softhsm_setup setup

# 2. Get the key URI
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')

# 3. Sign a model
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" \
  --signature test-model.sig

# 4. Export public key (once, reuse for all verifications)
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem

# 5. Verify the signature
./build/model-signing verify key test-model \
  --signature test-model.sig \
  --public-key public-key.pem

# 6. Cleanup (when done testing)
scripts/pkcs11-tests/softhsm_setup teardown
```

**Or run the automated test:**
```bash
scripts/pkcs11-tests/test_pkcs11.sh
```

---

## Setup

### Install SoftHSM2

**Fedora/RHEL:**
```bash
sudo dnf install softhsm gnutls-utils
```

**Ubuntu/Debian:**
```bash
sudo apt install softhsm2 gnutls-bin
```

**macOS:**
```bash
brew install softhsm gnutls
```

### Using softhsm_setup Script

The `scripts/pkcs11-tests/softhsm_setup` script provides a modular interface for managing SoftHSM2 test environments.

**Setup:**
```bash
scripts/pkcs11-tests/softhsm_setup setup
```

This will:
- Create isolated config in `~/.config/softhsm2/`
- Initialize a token named `model-signing-test`
- Generate an EC secp384r1 key pair

**Get Key URI:**
```bash
scripts/pkcs11-tests/softhsm_setup getkeyuri
# Output: keyuri: pkcs11:token=model-signing-test;object=mykey?pin-value=1234&module-name=softhsm2
```

**Export Public Key:**
```bash
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem
```

**Teardown:**
```bash
scripts/pkcs11-tests/softhsm_setup teardown
```

---

## Signing

### Basic Signing

```bash
# Get the key URI
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')

# Sign
./build/model-signing sign pkcs11 MODEL_PATH \
  --pkcs11-uri "$keyuri" \
  --signature SIGNATURE_FILE
```

### Example

```bash
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" \
  --signature test-model.sig
```

### Verbose Mode

Add `-d` flag:
```bash
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" --signature test-model.sig -d
```

### Direct URI (Without Setup Script)

```bash
# Using module-name (searches standard locations)
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "pkcs11:token=model-signing-test;object=mykey?module-name=softhsm2&pin-value=1234" \
  --signature test-model.sig

# Or using explicit module-path
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "pkcs11:token=model-signing-test;object=mykey?module-path=/usr/lib64/pkcs11/libsofthsm2.so&pin-value=1234" \
  --signature test-model.sig
```

---

## Verification

Verification requires the **public key** (not the PKCS#11 token).

### Export Public Key

**Using setup script (easiest):**
```bash
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem
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
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" \
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

## Troubleshooting

### Show Available Tokens
```bash
SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf" softhsm2-util --show-slots
```

### List Keys
```bash
MODULE_PATH=$(find /usr/lib* -name "libsofthsm2.so" 2>/dev/null | grep -v "softhsm/" | head -1)
SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf" \
pkcs11-tool --module "$MODULE_PATH" --login --pin 1234 --list-objects
```

### Check Module Path
```bash
find /usr/lib* -name "libsofthsm2.so" 2>/dev/null | grep -v "softhsm/"
```

### Test Token Access
```bash
MODULE_PATH=$(find /usr/lib* -name "libsofthsm2.so" 2>/dev/null | grep -v "softhsm/" | head -1)
SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf" \
pkcs11-tool --module "$MODULE_PATH" --login --pin 1234 --list-objects
```

### Verify Public Key Export
```bash
# Should show EC PUBLIC KEY
cat public-key.pem
```

### Common Errors

**"Could not find any object with label X"**
- Check that the key exists: `scripts/pkcs11-tests/softhsm_setup setup`
- Verify label matches: token uses `mykey` as the label

**"module-name attribute is not set"**
- Add `module-name=softhsm2` to your PKCS#11 URI
- Or use `module-path=/path/to/libsofthsm2.so`

**"Could not find libsofthsm2.so"**
- Install SoftHSM2: `sudo dnf install softhsm` or `sudo apt install softhsm2`
- Check module path: `find /usr/lib* -name "libsofthsm2.so"`

**"failed to initialize PKCS#11"**
- Ensure `SOFTHSM2_CONF` points to valid config
- Default: `~/.config/softhsm2/softhsm2.conf`

---

## Complete Example Workflow

```bash
# 1. Build the binary
make build

# 2. Setup SoftHSM2
scripts/pkcs11-tests/softhsm_setup setup

# 3. Sign
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" --signature test-model.sig

# 4. Export public key
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem

# 5. Verify
./build/model-signing verify key test-model \
  --signature test-model.sig \
  --public-key public-key.pem

# 6. Cleanup
scripts/pkcs11-tests/softhsm_setup teardown
```

---

## Environment Variables

The `softhsm_setup` script uses these environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `PIN` | Token user PIN | 1234 |
| `SO_PIN` | Security Officer PIN | 1234 |
| `SOFTHSM_SETUP_CONFIGDIR` | Config directory | `~/.config/softhsm2` |
| `SOFTHSM2_CONF` | Config file path | `$SOFTHSM_SETUP_CONFIGDIR/softhsm2.conf` |

---

## Configuration Details

### Token Details (after setup)

| Property | Value |
|----------|-------|
| Token Label | `model-signing-test` |
| Key Label | `mykey` |
| Key Type | EC secp384r1 |
| PIN | 1234 |
| Config Dir | `~/.config/softhsm2/` |
| Module | `/usr/lib64/pkcs11/libsofthsm2.so` (Linux) |

---

## Testing Scripts

See [scripts/pkcs11-tests/README.md](scripts/pkcs11-tests/README.md) for detailed information on:
- Automated testing
- CI/CD integration
- Troubleshooting
- Comparison with Python implementation

---

## PKCS#11 URI Format

The PKCS#11 URI follows RFC 7512:

```
pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN
```

**Path Attributes** (before `?`):
- `token` - Token label
- `object` - Key label  
- `id` - Key ID (hex-encoded bytes)
- `slot-id` - Slot number

**Query Attributes** (after `?`):
- `module-name` - Module name (searches standard paths)
- `module-path` - Explicit module path
- `pin-value` - PIN (avoid in production!)
- `pin-source` - Path to PIN file (`file:///path/to/pin`)

**Examples:**
```bash
# Using module-name (recommended)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234

# Using module-path
pkcs11:token=mytoken;object=mykey?module-path=/usr/lib64/pkcs11/libsofthsm2.so&pin-value=1234

# Using PIN from file (production)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-source=file:///secure/pin.txt

# Using slot-id instead of token
pkcs11:slot-id=0;object=mykey?module-name=softhsm2&pin-value=1234
```

---

## Production Considerations

### Security Best Practices

1. **PIN Management**
   - Never hardcode PINs in URIs
   - Use `pin-source=file:///secure/path`
   - Restrict file permissions: `chmod 600 /secure/pin`

2. **Module Path Restrictions**
   - Use `SetAllowedModulePaths()` to whitelist modules
   - Default: `SetAllowAnyModule(true)` (dev only!)

3. **HSM vs SoftHSM**
   - SoftHSM2: Development and testing
   - Hardware HSM: Production signing
   - YubiKey: Personal/small-scale signing

### Hardware HSM Support

The implementation supports any PKCS#11-compatible HSM:
- YubiKey (via ykcs11)
- AWS CloudHSM
- Thales Luna HSM
- Utimaco HSM

**Example with YubiKey:**
```bash
./build/model-signing sign pkcs11 model \
  --pkcs11-uri "pkcs11:token=YubiKey;object=mykey?module-name=ykcs11&pin-source=file:///secure/pin" \
  --signature model.sig
```

---

## Supported Features

| Feature | Status | Notes |
|---------|--------|-------|
| EC Keys (P-256, P-384, P-521) | ✅ | Fully supported |
| PIN from value | ✅ | Development only |
| PIN from file | ✅ | Production recommended |
| Module-name search | ✅ | Searches standard paths |
| Module-path explicit | ✅ | Direct path specification |
| Certificate-based signing | ✅ | With certificate chain |
| Module security policy | ✅ | Restrict allowed modules |
| Slot-ID selection | ✅ | Direct slot access |
| Token label search | ✅ | Search by token name |

---

## Comparison with Python

The Go implementation maintains full compatibility with the Python project:

| Feature | Python | Go | Compatible |
|---------|--------|-----|------------|
| RFC 7512 URI parsing | ✅ | ✅ | ✅ |
| secp384r1 keys | ✅ | ✅ | ✅ |
| PIN from file | ✅ | ✅ | ✅ |
| Module security | ✅ | ✅ | ✅ |
| Sigstore bundles | ✅ | ✅ | ✅ |
| DSSE envelope | ✅ | ✅ | ✅ |

**Testing Scripts:**
- Python: `scripts/pkcs11-tests/softhsm_setup`
- Go: `scripts/pkcs11-tests/softhsm_setup` (same!)

Signatures created by either implementation can be verified by the other.

---

## Additional Resources

- [Python PKCS#11 Implementation](https://github.com/sigstore/model-transparency/blob/main/src/model_signing/_signing/sign_pkcs11.py)
- [RFC 7512 - PKCS#11 URI](https://datatracker.ietf.org/doc/html/rfc7512)
- [SoftHSM2 Documentation](https://github.com/opendnssec/SoftHSMv2)
- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
