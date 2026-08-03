.PHONY: bootstrap format lint test verify verify-python verify-go verify-schemas verify-plugin

UV_CACHE_DIR ?= .cache/uv
GOCACHE ?= $(CURDIR)/.cache/go-build
PYTHON ?= UV_CACHE_DIR=$(UV_CACHE_DIR) uv run
PNPM ?= pnpm
PLUGIN_DIR ?= plugins/continuity-archive

bootstrap:
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv sync --all-groups
	$(PNPM) install --frozen-lockfile

format:
	$(PYTHON) ruff format services/memory-node migrations tests scripts
	$(PYTHON) ruff check --fix services/memory-node migrations tests scripts
	gofmt -w services/memory-relay services/memory-node-agent

lint: verify-python verify-go verify-schemas verify-plugin

test:
	$(PYTHON) pytest
	GOCACHE=$(GOCACHE) go test ./services/memory-relay/... ./services/memory-node-agent/...
	npm --prefix $(PLUGIN_DIR) test

verify: verify-python verify-go verify-schemas verify-plugin

verify-python:
	$(PYTHON) ruff format --check services/memory-node migrations tests scripts
	$(PYTHON) ruff check services/memory-node migrations tests scripts
	$(PYTHON) mypy services/memory-node/src tests
	$(PYTHON) pytest

verify-go:
	@test -z "$$(gofmt -l services/memory-relay services/memory-node-agent)"
	GOCACHE=$(GOCACHE) go vet ./services/memory-relay/... ./services/memory-node-agent/...
	GOCACHE=$(GOCACHE) go test ./services/memory-relay/... ./services/memory-node-agent/...

verify-schemas:
	$(PYTHON) python scripts/validate_schemas.py
	protoc --proto_path=proto --descriptor_set_out=/tmp/scalevault-relay.pb proto/relay-v1.proto

verify-plugin:
	npm --prefix $(PLUGIN_DIR) run check
	npm --prefix $(PLUGIN_DIR) test
