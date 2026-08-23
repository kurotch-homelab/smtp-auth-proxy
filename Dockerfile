# syntax=docker/dockerfile:1

# ---- Stage 1: build the admin UI -------------------------------------------
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
# Vite writes into ../internal/webui/dist, which the Go build embeds.
RUN npm run build

# ---- Stage 2: build the Go binary ------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src

# Module downloads are cached separately from the source so that editing code
# does not re-resolve the dependency graph.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
COPY --from=web /src/internal/webui/dist ./internal/webui/dist

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w \
      -X github.com/kurotch-homelab/smtp-auth-proxy/internal/version.Version=${VERSION} \
      -X github.com/kurotch-homelab/smtp-auth-proxy/internal/version.Commit=${COMMIT} \
      -X github.com/kurotch-homelab/smtp-auth-proxy/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/smtp-auth-proxy ./cmd/smtp-auth-proxy

# ---- Stage 3: runtime ------------------------------------------------------
# distroless/static carries CA certificates (needed for login.microsoftonline.com
# and graph.microsoft.com) and /etc/passwd, but no shell — the attack surface of
# a mail relay is worth keeping minimal.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/smtp-auth-proxy /usr/local/bin/smtp-auth-proxy

# /var/lib/smtp-auth-proxy holds the SQLite database and, when configured, the
# on-disk spool. Mount a volume here in Compose or a PVC in Kubernetes.
WORKDIR /var/lib/smtp-auth-proxy
USER nonroot:nonroot

# 587 submission (STARTTLS), 465 submission (implicit TLS), 8080 admin UI/API.
EXPOSE 587 465 8080

ENTRYPOINT ["/usr/local/bin/smtp-auth-proxy"]
CMD ["serve", "--config", "/etc/smtp-auth-proxy/config.yaml"]
