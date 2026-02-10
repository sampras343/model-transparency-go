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

USER 0
WORKDIR /app

ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /usr/local/bin/model-signing ./cmd/model-signing

FROM golang:1.25.7@sha256:cc737435e2742bd6da3b7d575623968683609a3d2e0695f9d85bee84071c08e6 AS deploy

COPY --from=builder /usr/local/bin/model-signing /usr/local/bin/model-signing
COPY LICENSE /licenses/license.txt

USER 65532:65532

ENTRYPOINT ["model-signing"]
CMD ["--help"]

ARG APP_VERSION="0.0.1"

LABEL summary="Provides a go library for model transparency." \
      org.opencontainers.image.title="Model Transparency Go Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0"
