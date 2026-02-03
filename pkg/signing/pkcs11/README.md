# PKCS#11 Signing Support

This package provides PKCS#11 signing support for model signing, allowing you to sign models using hardware security modules (HSMs) or software tokens.

## Features

- **PKCS#11 URI Support**: Full RFC 7512 compliant PKCS#11 URI parsing
- **Elliptic Curve Keys**: Support for P-256, P-384, and P-521 curves
- **Certificate Chains**: Support for signing with X.509 certificates and trust chains
- **Hardware Security**: Sign using HSMs or software tokens like SoftHSM

## Usage

### Basic PKCS#11 Signing

```go
import (
    "github.com/sigstore/model-signing/pkg/signing/pkcs11"
    "github.com/sigstore/model-signing/pkg/interfaces"
)

// Create a PKCS#11 signer
signer, err := pkcs11.NewSigner(
    "pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234",
    []string{"/usr/lib64/pkcs11/"},
)
if err != nil {
    log.Fatal(err)
}
defer signer.Close()

// Sign a payload
signature, err := signer.Sign(payload)
if err != nil {
    log.Fatal(err)
}

// Write signature to file
err = signature.Write("model.sig")
```

### Certificate-based PKCS#11 Signing

```go
import (
    "github.com/sigstore/model-signing/pkg/signing/pkcs11"
)

// Create a PKCS#11 certificate signer
signer, err := pkcs11.NewCertSigner(
    "pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234",
    "/path/to/signing-cert.pem",
    []string{"/path/to/ca-cert.pem", "/path/to/intermediate-cert.pem"},
    []string{"/usr/lib64/pkcs11/"},
)
if err != nil {
    log.Fatal(err)
}
defer signer.Close()

// Sign a payload
signature, err := signer.Sign(payload)
if err != nil {
    log.Fatal(err)
}

// Write signature to file
err = signature.Write("model.sig")
```

## PKCS#11 URI Format

The PKCS#11 URI follows RFC 7512 format:

```
pkcs11:[path-attributes]?[query-attributes]
```

### Path Attributes

- `token`: Token label
- `object`: Key label/name
- `id`: Key ID (hex-encoded)
- `slot-id`: Slot number
- `type`: Object type (public, private, cert, secret-key, data)

### Query Attributes

- `module-name`: PKCS#11 module name (e.g., softhsm2)
- `module-path`: Full path to PKCS#11 module
- `pin-value`: PIN for authentication
- `pin-source`: URI to file containing PIN

### Examples

```
# Using token label and object name
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234

# Using slot ID and key ID
pkcs11:slot-id=0;id=%01%02%03?module-path=/usr/lib64/pkcs11/libsofthsm2.so&pin-value=1234

# Using PIN from file
pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-source=file:///path/to/pin.txt
```

## Supported Curves

The implementation supports the following elliptic curves:

- **P-256** (secp256r1) - SHA-256 hash
- **P-384** (secp384r1) - SHA-384 hash
- **P-521** (secp521r1) - SHA-512 hash

## Dependencies

This package requires:

- `github.com/miekg/pkcs11` - Go PKCS#11 bindings
- A PKCS#11 module (e.g., SoftHSM2, OpenSC, vendor-specific HSM drivers)

## Testing with SoftHSM

To test with SoftHSM2:

1. Install SoftHSM2:
   ```bash
   # Fedora/RHEL
   sudo dnf install softhsm
   
   # Ubuntu/Debian
   sudo apt-get install softhsm2
   ```

2. Initialize a token:
   ```bash
   softhsm2-util --init-token --slot 0 --label "mytoken" --pin 1234 --so-pin 5678
   ```

3. Generate a key pair:
   ```bash
   pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so \
     --login --pin 1234 \
     --keypairgen --key-type EC:secp256r1 \
     --label mykey
   ```

4. Use the PKCS#11 URI:
   ```
   pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234
   ```

## Security Considerations

- **PIN Management**: Never hardcode PINs in your code. Use `pin-source` to read from a secure file or environment variable.
- **Module Paths**: By default, the implementation allows any module to be loaded. In production, use `SetAllowedModulePaths()` to restrict which modules can be loaded.
- **Session Management**: Always call `Close()` on signers to properly clean up PKCS#11 sessions.

## Error Handling

Common errors and solutions:

- **"module-name attribute is not set"**: Specify either `module-name` or `module-path` in the URI
- **"Could not find any object with label X"**: Verify the key exists and the label matches exactly
- **"failed to initialize PKCS#11"**: Check that the PKCS#11 module path is correct and accessible
- **"Unsupported elliptic curve"**: Only P-256, P-384, and P-521 curves are supported

## Comparison with Python Implementation

This Go implementation is functionally equivalent to the Python implementation in `model-transparency`:

| Feature | Python | Go |
|---------|--------|-----|
| PKCS#11 URI parsing | ✓ | ✓ |
| EC key support (P-256/384/521) | ✓ | ✓ |
| Certificate chains | ✓ | ✓ |
| PIN from file | ✓ | ✓ |
| Module path resolution | ✓ | ✓ |
| DSSE envelope | ✓ | ✓ |
| Sigstore bundle output | ✓ | ✓ |
