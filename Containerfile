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

FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /model-signing ./cmd/model-signing

FROM gcr.io/distroless/static:nonroot AS final_image

COPY --from=builder /model-signing /model-signing

USER nonroot:nonroot

ENTRYPOINT ["/model-signing"]
CMD ["--help"]

ARG APP_VERSION="0.0.1"

LABEL org.opencontainers.image.title="Model Transparency Library" \
      org.opencontainers.image.description="Supply chain security for ML" \
      org.opencontainers.image.version="$APP_VERSION" \
      org.opencontainers.image.authors="The Sigstore Authors <sigstore-dev@googlegroups.com>" \
      org.opencontainers.image.licenses="Apache-2.0"
