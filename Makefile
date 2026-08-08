.PHONY: bootstrap build build-go format generate generate-protobuf lint migrate-database test test-fast test-database test-database-required verify verify-generated verify-go verify-go-build verify-locks verify-plugin verify-protobuf verify-python verify-schemas

UV_CACHE_DIR ?= .cache/uv
GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
PYTHON ?= UV_CACHE_DIR=$(UV_CACHE_DIR) uv run --locked
PNPM ?= pnpm
PLUGIN_DIR ?= plugins/continuity-archive
BUILD_DIR ?= bin
GO_BUILD_FLAGS ?= -trimpath -buildvcs=false -ldflags=-buildid=

bootstrap:
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv sync --all-groups --locked
	$(PNPM) install --frozen-lockfile
	GOWORK=off GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go -C tools mod download

build: build-go

build-go:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/memory-relay ./services/memory-relay/cmd/relay
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/memory-node-agent ./services/memory-node-agent/cmd/node-agent

format:
	$(PYTHON) ruff format services/memory-node migrations tests scripts
	$(PYTHON) ruff check --fix services/memory-node migrations tests scripts
	gofmt -w gen/relay/v1 services/memory-relay services/memory-node-agent
	$(PNPM) --dir $(PLUGIN_DIR) run format

generate: generate-protobuf

generate-protobuf:
	./scripts/generate_protobuf.sh --write

lint: verify-python verify-go verify-schemas verify-plugin

migrate-database:
	$(PYTHON) python scripts/migrate_database.py upgrade head

test:
	$(PYTHON) pytest
	GOCACHE=$(GOCACHE) go test ./gen/relay/... ./services/memory-relay/... ./services/memory-node-agent/...
	$(PNPM) --dir $(PLUGIN_DIR) test

test-fast:
	$(PYTHON) pytest -m "not database"

test-database:
	$(PYTHON) pytest tests/integration

test-database-required:
	SCALEVAULT_REQUIRE_DATABASE_TESTS=1 $(PYTHON) pytest tests/integration

verify: verify-locks verify-python verify-go verify-go-build verify-schemas verify-plugin

verify-locks:
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv lock --check
	GOWORK=off GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go -C tools mod verify
	go -C gen/relay mod verify
	go -C services/memory-relay mod verify
	go -C services/memory-node-agent mod verify

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

verify-generated: verify-protobuf

verify-protobuf:
	./scripts/generate_protobuf.sh --check

verify-schemas: verify-protobuf
	$(PYTHON) python scripts/validate_schemas.py
	protoc --proto_path=proto --descriptor_set_out=/tmp/scalevault-relay.pb proto/relay-v1.proto

verify-plugin:
	$(PNPM) --dir $(PLUGIN_DIR) run check
	$(PNPM) --dir $(PLUGIN_DIR) test
