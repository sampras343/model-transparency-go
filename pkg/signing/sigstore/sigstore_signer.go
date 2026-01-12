package sigstore_signer

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

type SigstoreSignerOptions struct {
	ModelPath             string
	SignaturePath         string
	IgnorePaths           []string
	IgnoreGitPaths        bool
	AllowSymlinks         bool
	UseStaging            bool
	OAuthForceOob         bool
	UseAmbientCredentials bool
	IdentityToken         string
	ClientId              string
	ClientSecret          string
	TrustConfigPath       string
}

type SigstoreSigner struct {
	opts SigstoreSignerOptions
}

func NewSigstoreSigner(opts SigstoreSignerOptions) (*SigstoreSigner, error) {
	// Validate required paths using new validation utilities
	if err := utils.ValidateFolderExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	// Validate ignore paths using new validation utilities
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}
	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}
	return &SigstoreSigner{opts: opts}, nil
}

// Sign performs the complete signing flow.
//
//nolint:revive
func (ss *SigstoreSigner) Sign(ctx context.Context) (signing.Result, error) {
	// Print verification info (matching Python CLI behavior)
	fmt.Println("Sigstore verification")
	fmt.Printf("  MODEL_PATH:          %s\n", filepath.Clean(ss.opts.ModelPath))
	fmt.Printf("  --signature:         %s\n", filepath.Clean(ss.opts.SignaturePath))
	fmt.Printf("  --ignore-paths:      %v\n", ss.opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:  %v\n", ss.opts.IgnoreGitPaths)
	fmt.Printf("  --allow-symlinks:    %v\n", ss.opts.AllowSymlinks)
	fmt.Printf("  --use-staging:       %v\n", ss.opts.UseStaging)
	fmt.Printf("  --oauth-force-oob:          %s\n", ss.opts.OAuthForceOob)
	fmt.Printf("  --use-ambient-credentials: %s\n", ss.opts.UseAmbientCredentials)
	fmt.Printf("  --identity-token: %v\n", ss.opts.IdentityToken)
	fmt.Printf("  --client-id: %v\n", ss.opts.ClientId)
	fmt.Printf("  --client-secret: %v\n", ss.opts.ClientSecret)
	fmt.Printf("  --trust-config: %v\n", ss.opts.TrustConfigPath)

	// Resolve ignore paths
	ignorePaths := ss.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, ss.opts.SignaturePath)

	// Create Sigstore verifier
	verifierConfig := SigstoreVerifierConfig{
		Identity:      ss.opts.Identity,
		OIDCIssuer:    ss.opts.IdentityProvider,
		UseStaging:    ss.opts.UseStaging,
		TrustRootPath: ss.opts.TrustConfigPath,
	}

	sigstoreVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create Sigstore verifier: %w", err)
	}

	// Create hashing config
	// Note: We don't set specific hashing params here because the Config
	// will guess them from the signature's manifest
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, sv.opts.IgnoreGitPaths).
		SetAllowSymlinks(sv.opts.AllowSymlinks)

	// Create verification config
	verifyConfig := config.NewVerifierConfig().
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
