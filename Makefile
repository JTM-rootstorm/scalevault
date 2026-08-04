.PHONY: bootstrap build build-go format lint test verify verify-python verify-go verify-go-build verify-schemas verify-plugin

UV_CACHE_DIR ?= .cache/uv
GOCACHE ?= $(CURDIR)/.cache/go-build
PYTHON ?= UV_CACHE_DIR=$(UV_CACHE_DIR) uv run
PNPM ?= pnpm
PLUGIN_DIR ?= plugins/continuity-archive
BUILD_DIR ?= bin
GO_BUILD_FLAGS ?= -trimpath -buildvcs=false -ldflags=-buildid=

bootstrap:
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv sync --all-groups
	$(PNPM) install --frozen-lockfile

build: build-go

build-go:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/memory-relay ./services/memory-relay/cmd/relay
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/memory-node-agent ./services/memory-node-agent/cmd/node-agent

format:
	$(PYTHON) ruff format services/memory-node migrations tests scripts
	$(PYTHON) ruff check --fix services/memory-node migrations tests scripts
	gofmt -w gen/relay/v1 services/memory-relay services/memory-node-agent

lint: verify-python verify-go verify-schemas verify-plugin

test:
	$(PYTHON) pytest
	GOCACHE=$(GOCACHE) go test ./gen/relay/... ./services/memory-relay/... ./services/memory-node-agent/...
	npm --prefix $(PLUGIN_DIR) test

verify: verify-python verify-go verify-go-build verify-schemas verify-plugin

verify-python:
	$(PYTHON) ruff format --check services/memory-node migrations tests scripts
	$(PYTHON) ruff check services/memory-node migrations tests scripts
	$(PYTHON) mypy services/memory-node/src tests
	$(PYTHON) pytest

verify-go:
	@test -z "$$(gofmt -l gen/relay/v1 services/memory-relay services/memory-node-agent)"
	GOCACHE=$(GOCACHE) go vet ./gen/relay/... ./services/memory-relay/... ./services/memory-node-agent/...
	GOCACHE=$(GOCACHE) go test ./gen/relay/... ./services/memory-relay/... ./services/memory-node-agent/...

verify-go-build:
	@set -eu; build_root="$$(mktemp -d)"; trap 'rm -rf "$$build_root"' EXIT; \
	for pass in first second; do \
		mkdir -p "$$build_root/$$pass"; \
		CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o "$$build_root/$$pass/memory-relay" ./services/memory-relay/cmd/relay; \
		CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o "$$build_root/$$pass/memory-node-agent" ./services/memory-node-agent/cmd/node-agent; \
	done; \
	cmp "$$build_root/first/memory-relay" "$$build_root/second/memory-relay"; \
	cmp "$$build_root/first/memory-node-agent" "$$build_root/second/memory-node-agent"

verify-schemas:
	$(PYTHON) python scripts/validate_schemas.py
	protoc --proto_path=proto --descriptor_set_out=/tmp/scalevault-relay.pb proto/relay-v1.proto

verify-plugin:
	npm --prefix $(PLUGIN_DIR) run check
	npm --prefix $(PLUGIN_DIR) test
