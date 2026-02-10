# PKCS#11 Signing and Verification Guide

Advanced guide for PKCS#11 signing with hardware security modules (HSMs) or SoftHSM2.

> **Quick Start:** See the [main README](README.md#sign-verify-with-pkcs11--hsm) for installation and basic usage.  
> **Testing:** See [scripts/tests/](scripts/tests/) for automated testing and setup details.

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

**URI Examples:**
```bash
# Development (inline PIN - testing only)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234

# Production (PIN from secure file)
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-source=file:///secure/pin

# Using explicit slot ID
pkcs11:slot-id=0;object=mykey?module-name=softhsm2&pin-value=1234

# Full module path
pkcs11:token=mytoken;object=mykey?module-path=/usr/lib64/pkcs11/libsofthsm2.so&pin-source=file:///secure/pin
```

## Production HSM Usage

**PIN Security Best Practices:**
- **Never** hardcode PINs in URIs (`pin-value`) for production
- Always use `pin-source=file:///secure/path` to read PINs from a protected file
- Set strict file permissions: `chmod 600 /secure/pin` and restrict ownership
- Consider environment-based PIN management or secrets vaults in production pipelines

**Supported Hardware HSMs:**
- **YubiKey** (via `ykcs11` module)
- **AWS CloudHSM** (PKCS#11 client library)
- **Thales Luna HSM** (Cryptoki library)
- **Utimaco HSM** (CryptoServer library)
- Any PKCS#11-compliant HSM

**YubiKey Example:**
```bash
# Key generation on YubiKey (one-time)
ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE 9a pubkey.pem
ykman piv certificates generate --subject "CN=My Key" 9a pubkey.pem

# Sign using YubiKey
model-signing sign pkcs11-key \
  --pkcs11-uri "pkcs11:slot-id=0;object=Private key for Digital Signature?module-name=libykcs11&pin-source=file:///secure/yubikey-pin" \
  --signature model.sig \
  model
```

**AWS CloudHSM Example:**
```bash
# After configuring CloudHSM client
model-signing sign pkcs11-key \
  --pkcs11-uri "pkcs11:token=cavium;object=model-signing-key?module-path=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so&pin-source=file:///secure/hsm-pin" \
  --signature model.sig \
  model
```

## Implementation Details

**Library Used:**
- [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11) v1.6.0
- High-level PKCS#11 wrapper implementing Go's `crypto.Signer` interface
- Automatic session/context management and key finding
- Handles signature format conversion automatically

**Supported Key Types:**
- ECDSA keys on curves: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- RSA keys (via crypto11, though not primary focus)

**Default Module Paths:**
- `/usr/lib64/pkcs11/` (Fedora, RHEL, openSUSE)
- `/usr/lib/pkcs11/` (Fedora 32-bit, ArchLinux)

## Commands Reference

**Key-Based Signing:**
```bash
model-signing sign pkcs11-key \
  --pkcs11-uri <URI> \
  --signature <output.sig> \
  [--ignore-paths <path1,path2>] \
  [--module-paths <dir1,dir2>] \
  <model-path>
```

**Certificate-Based Signing:**
```bash
model-signing sign pkcs11-certificate \
  --pkcs11-uri <URI> \
  --signing-certificate <cert.pem> \
  --signature <output.sig> \
  [--certificate-chain <chain.pem>] \
  [--ignore-paths <path1,path2>] \
  [--module-paths <dir1,dir2>] \
  <model-path>
```

**Verification:**
```bash
# Key-based signature
model-signing verify key \
  --signature <sig> \
  --public-key <key.pem> \
  <model-path>

# Certificate-based signature
model-signing verify certificate \
  --signature <sig> \
  [--certificate-chain <chain.pem>] \
  <model-path>
```

## Additional Resources

- [Testing Scripts Documentation](scripts/tests/)
- [RFC 7512 - PKCS#11 URI](https://datatracker.ietf.org/doc/html/rfc7512)
- [SoftHSM2 Documentation](https://github.com/opendnssec/SoftHSMv2)
- [crypto11 Library](https://github.com/ThalesGroup/crypto11)
