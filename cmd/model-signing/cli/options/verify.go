package options



import (
	"github.com/spf13/cobra"

)


type SigstoreVerifyOptions struct {
	SignaturePath    string   // --signature SIGNATURE_PATH (required)
	IgnorePaths      []string // --ignore-paths
	IgnoreGitPaths   bool     // --ignore-git-paths (default true; users can pass --ignore-git-paths=false)
	UseStaging       bool     // --use-staging
	Identity         string   // --identity (required)
	IdentityProvider string   // --identity_provider (required)
}


func (o *SigstoreVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", "Location of the signature file to verify.")
	_ = cmd.MarkFlagRequired("signature")

	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying.")

	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().StringVar(&o.Identity, "identity", "", "The expected identity of the signer (e.g., name@example.com).")
	_ = cmd.MarkFlagRequired("identity")
	cmd.Flags().StringVar(&o.IdentityProvider, "identity_provider", "", "The expected identity provider (e.g., https://accounts.example.com).")
	_ = cmd.MarkFlagRequired("identity_provider")
}