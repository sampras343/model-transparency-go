# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.0.2] - 2026-03-03

### Added

- Cross-platform release binaries for Linux amd64, macOS amd64/arm64, and Windows amd64.

### Changed

- PKCS#11 support is now an optional build tag (`-tags=pkcs11`), following the
  same pattern as OpenTelemetry (`-tags=otel`). Default builds exclude PKCS#11.
- Release binary naming convention changed to `model_transparency_cli_<os>_<arch>`.
- `Containerfile.pkcs11` now always includes the `pkcs11` build tag.

## [v0.0.1] - 2026-02-27

### Added

- CLI tool with `sign` and `verify` commands.
- Support for multiple signing methods: Sigstore, private keys, certificates, and hardware tokens (PKCS#11).
- OCI model image manifest signing and verification.
- Reusable library packages for external integration.
- Example programs for each signing method.

[v0.0.2]: https://github.com/sampras343/model-transparency-go/releases/tag/v0.0.2
[v0.0.1]: https://github.com/sampras343/model-transparency-go/releases/tag/v0.0.1
