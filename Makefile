# smtp-auth-proxy — developer entrypoints.
# CI runs these same targets, so `make <target>` locally == the CI job.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

MODULE      := github.com/kurotch-homelab/smtp-auth-proxy
BINARY      := smtp-auth-proxy
BIN_DIR     := bin
IMAGE       ?= ghcr.io/kurotch-homelab/smtp-auth-proxy
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(DATE)

# Pinned tool versions (Dependabot cannot bump these, so review them at release time).
GOLANGCI_LINT_VERSION := v2.13.1
GOFUMPT_VERSION       := v0.11.0
GOVULNCHECK_VERSION   := latest
GOLICENSES_VERSION    := v2.0.1
ACTIONLINT_VERSION    := v1.7.12

TOOLS_DIR := $(CURDIR)/$(BIN_DIR)/tools
export PATH := $(TOOLS_DIR):$(PATH)

# `./...` descends into web/node_modules, where a few npm packages ship
# vendored Go sources. Naming our own trees explicitly keeps them out of every
# build, test, lint and coverage run.
GO_PACKAGES := ./cmd/... ./internal/...
GO_SRC_DIRS := cmd internal

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Build

.PHONY: build
build: ## Build the binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

.PHONY: run
run: ## Run the proxy against ./config.local.yaml
	go run ./cmd/$(BINARY) serve --config config.local.yaml

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf $(BIN_DIR) dist coverage.out coverage.html web/dist web/coverage

##@ Lint

.PHONY: lint
lint: lint-go lint-web lint-actions ## Run every linter

.PHONY: lint-go
lint-go: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/gofumpt ## Lint Go sources
	$(TOOLS_DIR)/gofumpt -l -d $(GO_SRC_DIRS)
	@test -z "$$($(TOOLS_DIR)/gofumpt -l $(GO_SRC_DIRS))" || { echo "::error::gofumpt found unformatted files"; exit 1; }
	$(TOOLS_DIR)/golangci-lint run $(GO_PACKAGES)

.PHONY: tidy-check
tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy
	@git diff --exit-code -- go.mod go.sum || { echo "::error::run 'go mod tidy' and commit the result"; exit 1; }

.PHONY: lint-actions
lint-actions: $(TOOLS_DIR)/actionlint ## Lint GitHub Actions workflows
	$(TOOLS_DIR)/actionlint

.PHONY: lint-web
lint-web: web/node_modules ## Lint the admin UI
	cd web && npm run lint && npm run format:check && npm run typecheck

.PHONY: fmt
fmt: $(TOOLS_DIR)/gofumpt ## Format Go and web sources in place
	$(TOOLS_DIR)/gofumpt -w $(GO_SRC_DIRS)
	@if [ -d web/node_modules ]; then cd web && npm run format; fi

##@ Test

.PHONY: test
test: ## Unit + integration tests (SQLite; set TEST_POSTGRES_DSN for Postgres too)
	go test -race -covermode=atomic -coverprofile=coverage.out $(GO_PACKAGES)

.PHONY: postgres-up
postgres-up: ## Start a throwaway PostgreSQL for the store tests
	docker run -d --rm --name sap-test-pg \
		-e POSTGRES_USER=proxy -e POSTGRES_PASSWORD=proxy -e POSTGRES_DB=proxy_test \
		-p 55432:5432 postgres:17-alpine >/dev/null
	@until docker exec sap-test-pg pg_isready -U proxy >/dev/null 2>&1; do sleep 1; done
	@echo 'export TEST_POSTGRES_DSN="postgres://proxy:proxy@localhost:55432/proxy_test?sslmode=disable"'

.PHONY: postgres-down
postgres-down: ## Stop the throwaway PostgreSQL
	-docker rm -f sap-test-pg >/dev/null 2>&1

.PHONY: test-e2e
test-e2e: ## End-to-end tests against fake upstreams
	go test -race -tags=e2e -timeout=10m $(GO_PACKAGES)

.PHONY: test-web
test-web: web/node_modules ## Admin UI unit tests
	cd web && npm run test:coverage

.PHONY: test-ui-e2e
test-ui-e2e: web/node_modules build ## Playwright end-to-end tests
	cd web && npm run test:e2e

.PHONY: cover
cover: test ## Open the HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

.PHONY: coverage-check
coverage-check: ## Enforce the per-package coverage thresholds
	go run ./internal/tools/covercheck -profile coverage.out -config .coverage.yaml

##@ Security

.PHONY: vuln
vuln: ## Check Go and npm dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(GO_PACKAGES)
	@if [ -d web ]; then cd web && npm audit --audit-level=high; fi

.PHONY: license-check
license-check: ## Fail on dependencies whose license is incompatible with Apache-2.0
	go run github.com/google/go-licenses/v2@$(GOLICENSES_VERSION) check $(GO_PACKAGES) \
		--disallowed_types=forbidden,restricted,unknown

##@ Container & charts

.PHONY: docker
docker: ## Build the container image locally
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(DATE) -t $(IMAGE):$(VERSION) .

.PHONY: compose-up
compose-up: ## Start the Docker Compose stack
	docker compose -f deploy/compose/docker-compose.yml up -d --build

.PHONY: compose-down
compose-down: ## Stop the Docker Compose stack
	docker compose -f deploy/compose/docker-compose.yml down -v

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart
	helm lint deploy/helm/smtp-auth-proxy
	helm template smtp-auth-proxy deploy/helm/smtp-auth-proxy >/dev/null

##@ Web assets

web/node_modules: web/package-lock.json
	cd web && npm ci
	@touch web/node_modules

.PHONY: web-build
web-build: web/node_modules ## Build the admin UI into web/dist (embedded at compile time)
	cd web && npm run build

##@ Tools

$(TOOLS_DIR)/golangci-lint:
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(TOOLS_DIR)/gofumpt:
	GOBIN=$(TOOLS_DIR) go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

$(TOOLS_DIR)/actionlint:
	GOBIN=$(TOOLS_DIR) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: tools
tools: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/gofumpt $(TOOLS_DIR)/actionlint ## Install pinned dev tools into bin/tools
