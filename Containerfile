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

FROM golang:1.25-alpine AS build-env

ENV CGO_ENABLED=1

# Install build dependencies for CGO and PKCS#11 support
RUN apk add --no-cache git ca-certificates gcc musl-dev

WORKDIR /model-signing
RUN git config --global --add safe.directory /model-signing

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

# Build with CGO enabled for PKCS#11 support
RUN go build -o model-signing -mod=readonly -trimpath ./cmd/model-signing

# Use alpine instead of distroless to support PKCS#11 runtime dependencies
FROM alpine:latest

# Create a non-root user and group with a home directory
RUN addgroup -S appgroup && \
    adduser -S -G appgroup -h /home/appuser -s /sbin/nologin appuser

# Install runtime dependencies including PKCS#11 support
RUN apk add --no-cache \
    ca-certificates \
    softhsm \
    p11-kit

COPY --from=build-env /model-signing/model-signing /usr/local/bin/model-signing
COPY LICENSE /licenses/license.txt

ARG APP_VERSION="0.0.1"

LABEL org.opencontainers.image.title="Model Transparency Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0"

USER appuser

WORKDIR /home/appuser

# Set the binary as the entrypoint of the container
ENTRYPOINT ["model-signing"]
CMD ["--help"]
