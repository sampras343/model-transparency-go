# Model Transparency Go

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
- [Model Signing](#model-signing)
  - [Build](#build)
    - [Building from Source](#building-from-source)
    - [Building with Podman](#building-with-podman)
  - [Model Signing CLI](#model-signing-cli)
    - [Sign-Verify with Sigstore](#sign-verify-with-sigstore)
    - [Sign-Verify using Private Sigstore Instances](#sign-verify-using-private-sigstore-instances)
    - [Sign-Verify with private-public key](#sign-verify-with-private-public-key)
    - [Sign-Verify with certificate](#sign-verify-with-certificate)
    - [Sign-Verify OCI Images](#sign-verify-oci-images)
  - [Model Signing API](#model-signing-api)
  - [Model Signing Format](#model-signing-format)
- [Contributing](#contributing)

<!-- tocstop -->

## Overview

There is currently significant growth in the number of ML-powered applications.
This brings benefits, but it also provides grounds for attackers to exploit
unsuspecting ML users.

Building on the work with [Open Source Security Foundation][openssf], we are
creating this collection of projects to strengthen the ML supply chain in
_the same way_ as the traditional software supply chain.

The focus is on providing *verifiable* claims about the integrity and provenance
of the resulting models, meaning users can check for themselves that these
claims are true rather than having to just trust the model trainer.

## Model Signing

This project demonstrates how to protect the integrity of a model by signing it.
We support generating signatures via [Sigstore](https://www.sigstore.dev/), a
tool for making code signatures transparent without requiring management of
cryptographic key material. But we also support traditional signing methods, so
models can be signed with public keys or signing certificates.

The signing part creates a
[sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
protobuf that is stored as in JSON format. The bundle contains the verification
material necessary to check the payload and a payload as a
[DSSE envelope](https://github.com/sigstore/protobuf-specs/blob/main/protos/envelope.proto).
Further the DSSE envelope contains an in-toto statment and the signature over
that statement. The signature format and how the the signature is computed can
be seen
[here](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md).

Finally, the statement itself contains subjects which are a list of (file path,
digest) pairs a predicate type set to `https://model_signing/signature/v1.0` and
a dictionary of predicates. The idea is to use the predicates to store (and
therefor sign) model card information in the future.

The verification part reads the sigstore bundle file and firstly verifies that the
signature is valid and secondly compute the model's file hashes again to compare
against the signed ones.

When users download a given version of a signed model they can check that the
signature comes from a known or trusted identity and thus that the model hasn't
been tampered with after training.

When using Sigstore, signing events are recorded to Sigstore's append-only
transparency log.  Transparency logs make signing events discoverable: Model
verifiers can validate that the models they are looking at exist in the
transparency log by checking a proof of inclusion (which is handled by the model
signing library).  Furthermore, model signers that monitor the log can check for
any unexpected signing events.

Model signers should monitor for occurences of their signing identity in the
log. Sigstore is actively developing a [log
monitor](https://github.com/sigstore/rekor-monitor) that runs on GitHub Actions.

![Signing models with Sigstore](docs/images/sigstore-model-diagram.png)


### Build

#### Building from Source

Clone the repository and build the `model-signing` binary:

```bash
[...]$ go build -o model-signing ./cmd/model-signing && sudo cp -r model-signing /usr/local/bin/
```

Verify if the binary is available to use:

```bash
[...]$ model-signing --help
```

#### Building with Podman

Build the container image using the provided `Containerfile`:

```bash
[...]$ podman build -t model-signing -f Containerfile .
```

Run the container:

```bash
[...]$ podman run --rm model-signing --help
```

#### Optional: OpenTelemetry tracing

The CLI can export distributed traces via OpenTelemetry when built with the
`otel` build tag. By default, tracing is no-op and the existing application level logger is used.

To build with OpenTelemetry support:

```bash
[...]$ go build -tags=otel -o model-signing ./cmd/model-signing
```

When the binary is built with `otel` and the following environment variables
are expected to be set, sign and verify operations are traced and exported via OTLP:

- `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` – endpoint for the OTLP exporter (e.g. `http://localhost:4318`)
- `OTEL_SERVICE_NAME` – service name in traces (default: `model-signing`)
- `OTEL_TRACES_EXPORTER` – set to `otlp` to enable trace export; set to `none` to disable

### Model Signing CLI

After installing the package, the CLI can be used by calling the binary directly, `model-signing <args>`.

Users that don't want to install the package, but want to test this using the repository can do:
```bash
[...]$ go run cmd/model-signing/main.go --help
```

For the remainder of the section, we would use `model-signing <args>` method.

The CLI has two subcommands: `sign` for signing and `verify` for verification.
Each subcommand has another level of subcommands to select the signing method
(`sigstore` -- the default, can be skipped --, `key`, `certificate`). Then, each
of these subcommands has several flags to configure parameters for
signing/verification.

For the demo, we will use the `bert-base-uncased` model, which can be obtained
via:

```bash
[...]$ git clone --depth=1 "https://huggingface.co/bert-base-uncased"
```

We remove the `.git` directory since that should not be included in the
signature:

```bash
[...]$ rm -rf bert-base-uncased/.git
```

By default, the code also ignores git related paths.

### Sign-Verify with Sigstore

**Signing:**

The simplest example of the CLI is to sign a model using Sigstore:

```bash
[...]$ model-signing sign bert-base-uncased
```

This will open an OIDC flow to obtain a short lived token for the certificate.
The identity used during signing and the provider must be reused during
verification.

All signing methods support changing the signature name and location via the `--signature` flag:

```bash
[...]$ model-signing sign bert-base-uncased --signature model.sig
```
Consult the help for a list of all flags (`model-signing --help`, or directly
`model-signing` with no arguments)

**Verifying:**

For verification using sigstore:

```bash
[...]$ model-signing verify bert-base-uncased \
      --signature model.sig \
      --identity "$identity"
      --identity-provider "$oidc_provider"
```
Where `$identity` and `$oidc_provider` are those set up during the signing flow
and `--signature` must point to the signature to verify.



For developers signing models with Sigstore, there are three identity providers
that can be used at the moment:

* Google's provider is `https://accounts.google.com`.
* GitHub's provider is `https://github.com/login/oauth`.
  * GitHub Actions uses `https://token.actions.githubusercontent.com`
* Microsoft's provider is `https://login.microsoftonline.com`.

For automated signing using a workload identity, the following platforms
are currently supported, shown with their expected identities:

* GitHub Actions
  (`https://github.com/octo-org/octo-automation/.github/workflows/oidc.yml@refs/heads/main`)
* GitLab CI
  (`https://gitlab.com/my-group/my-project//path/to/.gitlab-ci.yml@refs/heads/main`)
* Google Cloud Platform (`SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com`)
* Buildkite CI (`https://buildkite.com/ORGANIZATION_SLUG/PIPELINE_SLUG`)

### Sign-Verify using Private Sigstore Instances
To use a private Sigstore setup (e.g. custom Rekor/Fulcio), use the `--trust-config` flag:

```bash
[...]$ model-signing sign bert-base-uncased --trust-config client_trust_config.json --client-id trusted-artifact-signer
```

For verification:

```bash
[...]$ model-signing verify bert-base-uncased \
      --signature model.sig \
      --trust-config client_trust_config.json
      --identity "$identity"
      --identity-provider "$oidc_provider"
```

The `client_trust_config.json` file should include:

- A signed target trust root
- A `signingConfig` section with your private Rekor, Fulcio, and CT log endpoints
- Public keys for verification (if applicable)

You can find an example `client_trust_config.json` that references the public Sigstore production services in the Sigstore Python repository [here](https://github.com/sigstore/sigstore-python/blob/main/test/assets/trust_config/config.v1.json).

### Sign-Verify with private-public key

As another example, here is how we can sign with private keys. First, we
generate the key pair:

```bash
[...]$ openssl ecparam -name prime256v1 -genkey -noout -out key.priv
[...]$ openssl ec -in key.priv -pubout > key.pub
```
**Signing:**

And then we use the private key to sign.

```bash
[...]$ model-signing sign key bert-base-uncased \
       --private-key key.priv --signature model_key.sig
```

**Verifying:**

Similarly, for key verification, we can use

```bash
[...]$ model-signing verify key bert-base-uncased \
       --signature model_key.sig --public-key key.pub
```

### Sign-Verify with certificate

As another example, here is how we can sign with certificate. For this, 
we will be using the sample test certs available in the repository

**Signing:**
```bash
[...]$ model-signing sign certificate bert-base-uncased \
       --signature model_cert.sig \
       --signing-certificate scripts/tests/keys/certificate/signing-key-cert.pem \
       --private-key scripts/tests/keys/certificate/signing-key.pem \
       --certificate-chain scripts/tests/keys/certificate/int-ca-cert.pem
```

**Verifying:**
```bash
[...]$ model-signing verify certificate bert-base-uncased \
       --signature model_cert.sig \
       --certificate-chain scripts/tests/keys/certificate/ca-cert.pem \
       --ignore-unsigned-files
```

### Sign-Verify OCI Images

**Signing OCI Images:**

The tool supports signing and verifying OCI model images directly from their manifest without requiring the model files on disk. This is useful for signing images in registries without pulling them.

```bash
# Get the OCI manifest (from skopeo inspect --raw)
[...]$ skopeo inspect --raw docker://quay.io/user/model:latest > manifest.json

# Sign using the manifest
[...]$ model-signing sign manifest.json
```

**Verifying OCI Images:**

You can verify in two ways:

1. **Against the OCI manifest** (no files needed):
```bash
[...$ model-signing verify manifest.json \
  --signature model.sig \
  --identity "$identity" \
  --identity-provider "$oidc_provider"
```

2. **Against local model files** (automatically detects OCI layer signatures):
```bash
[...]$ model-signing verify model_dir \
  --signature model.sig \
  --identity "$identity" \
  --identity-provider "$oidc_provider"
```

The tool automatically detects OCI manifest signatures and matches files by path using `org.opencontainers.image.title` annotations (ORAS-style). For multi-layer images, verification against local files attempts to match individual files by path.

#### Global Options

The CLI supports the following global options available for all commands:

| Option | Description | Default |
|--------|-------------|---------|
| `--log-level` | Set the minimum log level (`debug`, `info`, `warn`, `error`, `silent`) | `info` |
| `--log-format` | Set the log output format (`text`, `json`) | `text` |
| `--output-file` | Redirect log output to a file | stdout |
| `--timeout` | Command execution timeout | `3m` |

**CLI examples:**

```bash
# Enable debug logging
[...]$ model-signing sign bert-base-uncased --log-level debug

# JSON format logs
[...]$ model-signing sign bert-base-uncased --log-level debug --log-format json --output-file output.log

# Suppress all output except errors
[...]$ model-signing verify bert-base-uncased --signature model.sig --log-level error
```

**Library usage** (`pkg/logging`):

Logging is also available programmatically via the `logging.Logger` interface, which all signers and verifiers accept. The interface is swappable with any logging backend.

```go
import "github.com/sigstore/model-signing/pkg/logging"

logger := logging.NewLoggerWithOptions(logging.LoggerOptions{
    Level:  logging.LevelDebug,
    Format: logging.FormatJSON,
})

opts := key.KeySignerOptions{
    ModelPath:      "/path/to/model",
    PrivateKeyPath: "/path/to/key.pem",
    Logger:         logger,
}
```

### Model Signing API

We offer an API which can be used in integrations with ML frameworks, ML
pipelins and ML model hubs libraries. The CLI wraps around the API.

The API is split into the following main components:

- `github.com/sigstore/model-signing/pkg/hashing`: Responsible with generating a list of hashes for
  every component of the model. A component could be a file, a file shard, a
  tensor, etc., depending on the method used. We currently support only files
  and file shards. The result of hashing is a manifest, a listing of hashes for
  every object in the model.
- `github.com/sigstore/model-signing/pkg/signing`: Responsible with taking the manifest and generating a
  signature, based on a signing configuration. The signing configuration can
  select the method used to sign as well as the parameters.
- `github.com/sigstore/model-signing/pkg/verify`: Responsible with taking a signature and verifying
  it. If the cryptographic parts of the signature can be validated, the
  verification layer would return an expanded manifest which can then be
  compared agains a manifest obtained from hashing the existing model. If the
  two manifest don't match then the model integrity was compromised and the
  `model-signing` package detected that.
- `github.com/sigstore/model-signing/pkg/logging`: Provides a swappable `Logger` interface and
  `Formatter` interface for structured, level-based logging. All signers and
  verifiers accept a `logging.Logger` for diagnostic output.

The first two of these components allows configurability but can also be used
directly, with a default configuration. The only difference is for the
verification component where we need to configure the verification method since
there are no sensible defaults that can be used.

**Using as a Go library:**: For a complete reference on interfaces, configuration types, and programmatic usage (signing/verification flows, config-based verification, extending the library) and simple code examples on how to use these APIs for different signing or verifying strategies are provided under [examples](examples/).

### Model Signing Format

For a diagram showing the model signing format as well as an explanation of the
layers, see the [model signing format](docs/model_signing_format.md) document.

## Contributing

Please see the [Contributor Guide](CONTRIBUTING.md) for more information.

[openssf]: https://openssf.org/
