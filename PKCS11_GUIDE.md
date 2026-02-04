# PKCS#11 Signing and Verification Guide

Guide for PKCS#11 signing with hardware security modules (HSMs) or SoftHSM2.

> **Quick Start:** See the [main README](README.md#sign-verify-with-pkcs11--hsm) for basic usage.  
> **Testing:** See [scripts/pkcs11-tests/](scripts/pkcs11-tests/) for automated testing and setup details.

---

## Installation

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

---

## Basic Usage

```bash
# Setup test environment
scripts/pkcs11-tests/softhsm_setup setup

# Get key URI
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')

# Sign
./build/model-signing sign pkcs11 MODEL --pkcs11-uri "$keyuri" --signature SIG

# Verify
scripts/pkcs11-tests/softhsm_setup getpubkey > public-key.pem
./build/model-signing verify key MODEL --signature SIG --public-key public-key.pem
```

---

## Certificate-Based Signing

```bash
# Sign with certificate
keyuri=$(scripts/pkcs11-tests/softhsm_setup getkeyuri | sed -n 's/^keyuri: //p')
./build/model-signing sign pkcs11 test-model \
  --pkcs11-uri "$keyuri" \
  --signing-certificate cert.pem \
  --signature test-model.sig

# Verify
./build/model-signing verify certificate test-model \
  --signature test-model.sig \
  --certificate-chain cert.pem
```

---

## PKCS#11 URI Format

RFC 7512 format:
```
pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN
```

**Key Attributes:**
- `token` - Token label
- `object` - Key label
- `slot-id` - Direct slot number
- `module-name` - Module name (searches standard paths)
- `module-path` - Explicit module path
- `pin-value` - PIN (dev only)
- `pin-source` - PIN file path (production: `file:///secure/pin`)

**Examples:**
```bash
# Development (module-name)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234

# Production (PIN from file)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-source=file:///secure/pin

# Using slot-id
pkcs11:slot-id=0;object=mykey?module-name=softhsm2&pin-value=1234
```

---

## Production Considerations

**PIN Security:**
- Never hardcode PINs in URIs for production
- Use `pin-source=file:///secure/path`
- Set file permissions: `chmod 600 /secure/pin`

**Hardware HSM Support:**
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

## Additional Resources

- [Testing Scripts Documentation](scripts/pkcs11-tests/)
- [RFC 7512 - PKCS#11 URI](https://datatracker.ietf.org/doc/html/rfc7512)
- [SoftHSM2 Documentation](https://github.com/opendnssec/SoftHSMv2)
