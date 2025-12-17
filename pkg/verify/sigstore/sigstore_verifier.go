package sigstore

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/hashing"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/signing"
	sigstoresigning "github.com/sigstore/model-signing/pkg/signing/sigstore"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Ensure Verifier implements signing.Verifier at compile time.
var _ signing.Verifier = (*Verifier)(nil)

// VerifierConfig holds configuration for creating a Sigstore verifier.
type VerifierConfig struct {
	// Identity is the expected identity that signed the model.
	// This is matched against the certificate's subject.
	Identity string

	// OIDCIssuer is the expected OpenID Connect issuer that provided
	// the certificate used for the signature.
	OIDCIssuer string

	// UseStaging uses staging configurations instead of production.
	// Should only be set to true when testing. Default is false.
	UseStaging bool

	// TrustRootPath is a path to a custom trust root JSON file.
	// When provided, verification uses this instead of the default
	// Sigstore trust root.
	TrustRootPath string
}

// Verifier verifies Sigstore signatures on model manifests.
//
// It checks both the cryptographic signature and an identity policy:
// the certificate must belong to the expected identity and be issued
// by the expected OIDC issuer.
type Verifier struct {
	config   VerifierConfig
	verifier *sigstoreverify.SignedEntityVerifier
}

// NewVerifier creates a new Sigstore verifier with the given configuration.
func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if config.Identity == "" {
		return nil, fmt.Errorf("identity is required")
	}
	if config.OIDCIssuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}

	// Validate OIDC issuer is a valid URL
	if _, err := url.ParseRequestURI(config.OIDCIssuer); err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer URL %q: %w", config.OIDCIssuer, err)
	}

	// Create trust root
	var trustRoot *root.TrustedRoot
	var err error

	if config.UseStaging {
		// TODO: Use staging TUF options when available
		trustRoot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch staging trust root: %w", err)
		}
	} else if config.TrustRootPath != "" {
		trustRoot, err = root.NewTrustedRootFromPath(config.TrustRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust root from file: %w", err)
		}
	} else {
		// Use production trust root
		trustRoot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch production trust root: %w", err)
		}
	}

	// Create verifier options
	// WithTransparencyLog verifies Rekor transparency log entries including SignedEntryTimestamps
	// WithIntegratedTimestamps uses integrated timestamps from the transparency log
	// Both are needed for proper Sigstore verification with short-lived certificates
	verifierOpts := []sigstoreverify.VerifierOption{
		sigstoreverify.WithTransparencyLog(1),
		sigstoreverify.WithIntegratedTimestamps(1),
	}

	// Create the verifier
	verifier, err := sigstoreverify.NewSignedEntityVerifier(trustRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &Verifier{
		config:   config,
		verifier: verifier,
	}, nil
}

// Verify verifies the signature and returns the manifest.
//
// This performs cryptographic verification of the signature and checks
// the identity policy before extracting and validating the manifest.
func (v *Verifier) Verify(signature signing.Signature) (*manifest.Manifest, error) {
	// Cast to Sigstore signature
	sig, ok := signature.(*sigstoresigning.Signature)
	if !ok {
		return nil, fmt.Errorf("signature is not a Sigstore signature")
	}

	// Create certificate identity for verification
	// Using NewShortCertificateIdentity for simpler initialization
	certIdentity, err := sigstoreverify.NewShortCertificateIdentity(
		v.config.OIDCIssuer, // issuer
		"",                  // issuer regex (empty = exact match)
		v.config.Identity,   // SAN value
		"",                  // SAN regex (empty = exact match)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	// Build policy for identity verification
	policy := sigstoreverify.NewPolicy(
		sigstoreverify.WithoutArtifactUnsafe(),
		sigstoreverify.WithCertificateIdentity(certIdentity),
	)

	// Verify the bundle
	verificationResult, err := v.verifier.Verify(sig.Bundle(), policy)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Extract DSSE envelope from the bundle
	bundle := sig.Bundle()
	envelope, err := bundle.Envelope()
	if err != nil {
		return nil, fmt.Errorf("failed to extract envelope from bundle: %w", err)
	}

	dsseEnvelope := envelope.RawEnvelope()
	if dsseEnvelope == nil {
		return nil, fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	// Verify payload type
	if dsseEnvelope.PayloadType != signing.InTotoJSONPayloadType {
		return nil, fmt.Errorf("expected DSSE payload %s, but got %s",
			signing.InTotoJSONPayloadType, dsseEnvelope.PayloadType)
	}

	// Decode the base64-encoded payload
	payloadBytes, err := base64.StdEncoding.DecodeString(string(dsseEnvelope.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}

	// Extract manifest from payload
	m, err := signing.VerifySignedContent(dsseEnvelope.PayloadType, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	// Verify that verification result is valid (this uses the result to avoid unused warning)
	_ = verificationResult

	return m, nil
}

// SigstoreVerifierOptions contains options for high-level Sigstore verification.
//
// This is used by the CLI and follows the Python CLI pattern.
type SigstoreVerifierOptions struct {
	ModelPath        string
	SignaturePath    string
	IgnorePaths      []string
	IgnoreGitPaths   bool
	AllowSymlinks    bool
	UseStaging       bool
	Identity         string
	IdentityProvider string
	TrustConfigPath  string
	IgnoreUnsignedFiles bool
}

// SigstoreVerifier provides high-level verification with validation.
//
// This mirrors the Python CLI behavior and includes input validation.
type SigstoreVerifier struct {
	opts SigstoreVerifierOptions
}

// NewSigstoreVerifier creates a new high-level Sigstore verifier with validation.
func NewSigstoreVerifier(opts SigstoreVerifierOptions) (*SigstoreVerifier, error) {
	// Validate required paths using new validation utilities
	if err := utils.ValidateFolderExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signature", opts.SignaturePath); err != nil {
		return nil, err
	}

	// Validate identity is provided
	if opts.Identity == "" {
		return nil, fmt.Errorf("identity is required")
	}

	// Validate identity provider is a valid URL
	if opts.IdentityProvider == "" {
		return nil, fmt.Errorf("identity provider is required")
	}
	if _, err := url.ParseRequestURI(opts.IdentityProvider); err != nil {
		return nil, fmt.Errorf("invalid identity provider %q: %w", opts.IdentityProvider, err)
	}

	// Validate ignore paths using new validation utilities
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}

	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}

	return &SigstoreVerifier{opts: opts}, nil
}

// Verify performs the complete verification flow.
//
// This follows the Python verification pattern:
// 1. Create verifier config
// 2. Create hashing config
// 3. Create verification config
// 4. Execute verification
func (sv *SigstoreVerifier) Verify(ctx context.Context) (verify.Result, error) {
	// Print verification info (matching Python CLI behavior)
	fmt.Println("Sigstore verification")
	fmt.Printf("  MODEL_PATH:          %s\n", filepath.Clean(sv.opts.ModelPath))
	fmt.Printf("  --signature:         %s\n", filepath.Clean(sv.opts.SignaturePath))
	fmt.Printf("  --ignore-paths:      %v\n", sv.opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:  %v\n", sv.opts.IgnoreGitPaths)
	fmt.Printf("  --allow-symlinks:    %v\n", sv.opts.AllowSymlinks)
	fmt.Printf("  --use-staging:       %v\n", sv.opts.UseStaging)
	fmt.Printf("  --identity:          %s\n", sv.opts.Identity)
	fmt.Printf("  --identity_provider: %s\n", sv.opts.IdentityProvider)
	fmt.Printf("  --ignore-unsigned-files: %v\n", sv.opts.IgnoreUnsignedFiles)

	// Resolve ignore paths
	ignorePaths := sv.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, sv.opts.SignaturePath)

	// Create Sigstore verifier
	verifierConfig := VerifierConfig{
		Identity:      sv.opts.Identity,
		OIDCIssuer:    sv.opts.IdentityProvider,
		UseStaging:    sv.opts.UseStaging,
		TrustRootPath: sv.opts.TrustConfigPath,
	}

	sigstoreVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create Sigstore verifier: %w", err)
	}

	// Create hashing config
	// Note: We don't set specific hashing params here because the Config
	// will guess them from the signature's manifest
	hashingConfig := hashing.NewConfig().
		SetIgnoredPaths(ignorePaths, sv.opts.IgnoreGitPaths).
		SetAllowSymlinks(sv.opts.AllowSymlinks)

	// Create verification config
	verifyConfig := verify.NewConfig().
		SetVerifier(sigstoreVerifier).
		SetHashingConfig(hashingConfig).
		SetIgnoreUnsignedFiles(sv.opts.IgnoreUnsignedFiles)

	// Perform verification
	if err := verifyConfig.Verify(sv.opts.ModelPath, sv.opts.SignaturePath); err != nil {
		return verify.Result{
			Verified: false,
			Message:  err.Error(),
		}, err
	}

	return verify.Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}