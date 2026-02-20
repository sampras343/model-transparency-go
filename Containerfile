# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS builder

# Optional Go build tags (e.g. "otel" for OpenTelemetry support).
# Default (empty) produces a standard build without optional features.
# Usage: podman build --build-arg BUILD_TAGS=otel -t model-signing:otel .
ARG BUILD_TAGS=""

USER 0
WORKDIR /app

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates gcc libc6-dev && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

RUN CGO_ENABLED=1 GOOS=linux go build -tags="${BUILD_TAGS}" -ldflags="-s -w" -o /usr/local/bin/model-signing ./cmd/model-signing

# Minimal distroless runtime (no PKCS#11 libraries).
# For PKCS#11 / HSM support, use Containerfile.pkcs11 instead.
FROM gcr.io/distroless/base-debian12:nonroot AS deploy

COPY --from=builder /usr/local/bin/model-signing /usr/local/bin/model-signing
COPY LICENSE /licenses/license.txt

ENTRYPOINT ["model-signing"]
CMD ["--help"]

ARG APP_VERSION="0.0.1"

LABEL summary="Provides a go library for model transparency." \
      org.opencontainers.image.title="Model Transparency Go Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0"
