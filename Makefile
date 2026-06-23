# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Adrian Enderlin

GO       ?= $(shell if command -v go >/dev/null 2>&1; then command -v go; elif [ -x /usr/local/go/bin/go ]; then printf '%s\n' /usr/local/go/bin/go; else printf '%s\n' go; fi)
GOPATH   ?= $(shell $(GO) env GOPATH 2>/dev/null)
BIN      := bin
BPFOBJ   := shield/bpf/out/xdp_kernloom_shield.bpf.o

.PHONY: all build build-forge bpf test integration integration-forge integration-clean clean

all: build

bpf:
	$(MAKE) -C shield/bpf

build: bpf
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/klshield ./shield/cmd/klshield
	$(GO) build -o $(BIN)/kliq     ./iq/cmd/kliq

test:
	$(GO) test ./...

integration: build build-forge
	sudo -E tests/integration/run.sh $(SCENARIOS)

# Build forge binary from sibling repo (for scenarios 09, 10 and 12).
build-forge:
	@if [ -d "$(dir $(abspath .))/kernloom-forge" ]; then \
	  echo "Building forge from $(dir $(abspath .))/kernloom-forge..."; \
	  mkdir -p bin; \
	  (cd $(dir $(abspath .))/kernloom-forge && $(GO) build -o $(abspath bin)/forge ./cmd/forge/) \
	    && echo "forge built: bin/forge" \
	    || echo "WARNING: forge build failed — scenarios 09+10 may fail"; \
	else \
	  echo "kernloom-forge not found at $(dir $(abspath .))/kernloom-forge — skipping forge build"; \
	fi

# No-XDP integration tests — Forge control plane plus RuntimePolicyPack checks.
# Builds Forge and KLIQ binaries only when the selected scenarios need them.
integration-forge:
	bash tests/integration/run-forge.sh $(SCENARIOS)

integration-clean:
	sudo -E tests/integration/scenarios/99_cleanup.sh

clean:
	$(MAKE) -C shield/bpf clean
	rm -rf $(BIN)
