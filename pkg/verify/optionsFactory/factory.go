package verifyfactory

import (
	"fmt"

	"github.com/sigstore/model-signing/pkg/verify/sigstore"
	"github.com/sigstore/model-signing/pkg/verify"
)

type Kind string

const (
	KindSigstore Kind = "sigstore"
	KindCert     Kind = "certificate"
	KindKey      Kind = "key"
)

type Params map[string]any

func New(kind Kind, p Params) (verify.Verifier, error) {
	switch kind {
	case KindSigstore:
		opts := sigstore.SigstoreVerifierOptions{
			ModelPath:        p["modelPath"].(string),
			SignaturePath:    p["signaturePath"].(string),
			IgnorePaths:      toStringSlice(p["ignorePaths"]),
			IgnoreGitPaths:   toBool(p["ignoreGitPaths"]),
			UseStaging:       toBool(p["useStaging"]),
			Identity:         toString(p["identity"]),
			IdentityProvider: toString(p["identityProvider"]),
		}
		return sigstore.New(opts)
	case KindCert:
		return nil, nil
	case KindKey:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown verifier kind: %s", kind)
	}
}
