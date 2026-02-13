// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/ThalesGroup/crypto11"

	internalcrypto "github.com/sigstore/model-signing/internal/crypto"
	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/utils"
	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// DefaultModulePaths are standard PKCS#11 module search paths for various Linux distributions.
var DefaultModulePaths = []string{
	"/usr/lib64/pkcs11/",                 // Fedora, RHEL, openSUSE
	"/usr/lib/pkcs11/",                   // Fedora 32-bit, ArchLinux
	"/usr/lib/x86_64-linux-gnu/softhsm/", // Ubuntu/Debian x86_64
	"/usr/lib/softhsm/",                  // Ubuntu/Debian (older or 32-bit)
	"/usr/local/lib/softhsm/",            // Homebrew on macOS
}

// Signer implements signing using PKCS#11 with elliptic curve keys.
type Signer struct {
	ctx       *crypto11.Context
	key       crypto11.Signer
	publicKey *ecdsa.PublicKey
	uri       *URI
}

// NewSigner creates a new PKCS#11 signer.
func NewSigner(pkcs11URI string, modulePaths []string) (*Signer, error) {
	uri := NewURI()
	if err := uri.Parse(pkcs11URI); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#11 URI: %w", err)
	}

	// Use default module paths if none provided
	if len(modulePaths) == 0 {
		modulePaths = DefaultModulePaths
	}
	uri.SetModuleDirectories(modulePaths)
	uri.SetAllowAnyModule(true)

	// Get module path
	modulePath, err := uri.GetModule()
	if err != nil {
		return nil, fmt.Errorf("failed to get module: %w", err)
	}

	// Get PIN
	pin := ""
	if uri.HasPIN() {
		pin, err = uri.GetPIN()
		if err != nil {
			return nil, err
		}
	}

	// Get token label
	tokenLabel := uri.GetTokenLabel()
	if tokenLabel == "" {
		return nil, fmt.Errorf("token label is required")
	}

	// Configure crypto11 context
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       modulePath,
		TokenLabel: tokenLabel,
		Pin:        pin,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure PKCS#11 context: %w", err)
	}

	// Find key pair
	keyID, label, err := uri.GetKeyIDAndLabel()
	if err != nil {
		ctx.Close()
		return nil, err
	}

	// Find the key pair using crypto11
	key, err := ctx.FindKeyPair(keyID, []byte(label))
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("failed to find key pair: %w", err)
	}

	// Get public key from the key pair
	pubKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		ctx.Close()
		return nil, fmt.Errorf("key is not an ECDSA key")
	}

	// Validate the curve is supported
	if err := utils.CheckSupportedECKey(pubKey); err != nil {
		ctx.Close()
		return nil, err
	}

	return &Signer{
		ctx:       ctx,
		key:       key,
		publicKey: pubKey,
		uri:       uri,
	}, nil
}

// Close closes the PKCS#11 context.
func (s *Signer) Close() error {
	return s.ctx.Close()
}

// PublicKey returns the ECDSA public key.
func (s *Signer) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// signPayload performs the core signing operation and creates a bundle.
// This is the common logic shared between key-based and certificate-based signing.
func (s *Signer) signPayload(payload *interfaces.Payload, verificationMaterial *bundle.VerificationMaterial) (interfaces.SignatureBundle, error) {
	// Serialize payload to JSON
	rawPayload, err := protojson.Marshal(payload.Statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Compute PAE (Pre-Authentication Encoding)
	pae := internalcrypto.ComputePAE(utils.InTotoJSONPayloadType, rawPayload)

	// Hash the PAE
	hashAlg := utils.GetHashAlgorithm(s.publicKey)
	hasher := hashAlg.New()
	hasher.Write(pae)
	digest := hasher.Sum(nil)

	// Sign the digest using crypto11 (implements crypto.Signer)
	signature, err := s.key.Sign(rand.Reader, digest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Create DSSE envelope using local helper and convert to protobuf
	env := dsse.CreateEnvelope(utils.InTotoJSONPayloadType, rawPayload, signature)
	protoEnv, err := env.ToProtobuf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert envelope to protobuf: %w", err)
	}

	// Create bundle
	bundleObj := &bundle.Bundle{
		MediaType:            utils.BundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content: &bundle.Bundle_DsseEnvelope{
			DsseEnvelope: protoEnv,
		},
	}

	return &SignatureBundle{bundle: bundleObj}, nil
}

// Sign signs the payload and returns a signature bundle.
func (s *Signer) Sign(payload *interfaces.Payload) (interfaces.SignatureBundle, error) {
	return s.signPayload(payload, s.getVerificationMaterial())
}

// getVerificationMaterial returns the verification material for the bundle.
func (s *Signer) getVerificationMaterial() *bundle.VerificationMaterial {
	// Compute SHA256 hash of the public key
	keyHash, err := config.ComputePublicKeyHash(s.publicKey)
	if err != nil {
		// Fallback to empty hint if hash computation fails
		keyHash = ""
	}

	return &bundle.VerificationMaterial{
		Content: &bundle.VerificationMaterial_PublicKey{
			PublicKey: &common.PublicKeyIdentifier{
				Hint: keyHash,
			},
		},
	}
}

// CertSigner implements signing using PKCS#11 with certificates.
type CertSigner struct {
	*Signer
	signingCertificate *x509.Certificate
	trustChain         []*x509.Certificate
}

// NewCertSigner creates a new PKCS#11 certificate signer.
func NewCertSigner(
	pkcs11URI string,
	signingCertificatePath string,
	certificateChainPaths []string,
	modulePaths []string,
) (*CertSigner, error) {
	// Create base signer
	baseSigner, err := NewSigner(pkcs11URI, modulePaths)
	if err != nil {
		return nil, err
	}

	// Load signing certificate
	certData, err := os.ReadFile(signingCertificatePath)
	if err != nil {
		baseSigner.Close()
		return nil, fmt.Errorf("failed to read signing certificate: %w", err)
	}

	signingCert, err := utils.ParsePEMCertificate(certData)
	if err != nil {
		baseSigner.Close()
		return nil, fmt.Errorf("failed to parse signing certificate: %w", err)
	}

	// Verify that the certificate's public key matches the private key
	certPubKey, ok := signingCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		baseSigner.Close()
		return nil, fmt.Errorf("certificate public key is not an ECDSA key")
	}

	if !certPubKey.Equal(baseSigner.publicKey) {
		baseSigner.Close()
		return nil, fmt.Errorf("the public key from the certificate does not match the public key paired with the private key")
	}

	// Load trust chain certificates
	var trustChain []*x509.Certificate
	for _, certPath := range certificateChainPaths {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			baseSigner.Close()
			return nil, fmt.Errorf("failed to read certificate chain file %s: %w", certPath, err)
		}

		certs, err := utils.ParsePEMCertificates(certData)
		if err != nil {
			baseSigner.Close()
			return nil, fmt.Errorf("failed to parse certificate chain file %s: %w", certPath, err)
		}

		trustChain = append(trustChain, certs...)
	}

	return &CertSigner{
		Signer:             baseSigner,
		signingCertificate: signingCert,
		trustChain:         trustChain,
	}, nil
}

// Sign signs the payload and returns a signature bundle with certificate chain.
func (s *CertSigner) Sign(payload *interfaces.Payload) (interfaces.SignatureBundle, error) {
	return s.signPayload(payload, s.getVerificationMaterial())
}

// getVerificationMaterial returns the verification material with certificate chain.
func (s *CertSigner) getVerificationMaterial() *bundle.VerificationMaterial {
	// Build certificate chain
	chain := []*common.X509Certificate{
		{
			RawBytes: s.signingCertificate.Raw,
		},
	}

	for _, cert := range s.trustChain {
		chain = append(chain, &common.X509Certificate{
			RawBytes: cert.Raw,
		})
	}

	return &bundle.VerificationMaterial{
		Content: &bundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &common.X509CertificateChain{
				Certificates: chain,
			},
		},
	}
}

// SignatureBundle wraps a Sigstore bundle as a signature.
type SignatureBundle struct {
	bundle *bundle.Bundle
}

// Write serializes the signature bundle to a file.
func (s *SignatureBundle) Write(path string) error {
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   false, // Use camelCase for JSON fields
		EmitUnpopulated: false,
	}

	data, err := opts.Marshal(s.bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// Bundle returns the underlying Sigstore bundle.
func (s *SignatureBundle) Bundle() *bundle.Bundle {
	return s.bundle
}
