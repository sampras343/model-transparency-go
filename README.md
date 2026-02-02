# Model Transparency Go

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
- [Model Signing](#model-signing)
  - [Model Signing CLI](#model-signing-cli)
  - [Model Signing API](#model-signing-api)
  - [Model Signing Format](#model-signing-format)
- [Building](#building)
  - [Building from Source](#building-from-source)
  - [Building with Podman](#building-with-podman)
- [Status](#status)
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


## Building

### Building from Source

Clone the repository and build the `model-signing` binary:

```bash
[...]$ go build -o model-signing ./cmd/model-signing
```

To install the binary to your `$GOPATH/bin`:

```bash
[...]$ go install ./cmd/model-signing
```

Verify the installation:

```bash
[...]$ ./model-signing --help
```

### Building with Podman

Build the container image using the provided `Containerfile`:

```bash
[...]$ podman build -t model-signing -f Containerfile .
```

Run the container:

```bash
[...]$ podman run --rm model-signing --help
```
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

The simplest example of the CLI is to sign a model using Sigstore:

```bash
[...]$ model-signing sign bert-base-uncased
```

This will open an OIDC flow to obtain a short lived token for the certificate.
The identity used during signing and the provider must be reused during
verification.

For verification using sigstore:

```bash
[...]$ model-signing verify bert-base-uncased \
      --signature model.sig \
      --identity "$identity"
      --identity-provider "$oidc_provider"
```