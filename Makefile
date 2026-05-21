# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Adrian Enderlin

GOPATH   ?= $(shell go env GOPATH)
BIN      := bin
BPFOBJ   := shield/bpf/out/xdp_kernloom_shield.bpf.o

.PHONY: all build build-forge bpf test integration integration-forge integration-clean clean

all: build

bpf:
	$(MAKE) -C shield/bpf

build: bpf
	mkdir -p $(BIN)
	go build -o $(BIN)/klshield ./shield/cmd/klshield
	go build -o $(BIN)/kliq     ./iq/cmd/kliq

test:
	go test ./...

integration: build build-forge
	sudo tests/integration/run.sh

# Build forge binary from sibling repo (for scenarios 09+10).
build-forge:
	@if [ -d "$(dir $(abspath .))/kernloom-forge" ]; then \
	  echo "Building forge from $(dir $(abspath .))/kernloom-forge..."; \
	  mkdir -p bin; \
	  (cd $(dir $(abspath .))/kernloom-forge && go build -o $(abspath bin)/forge ./cmd/forge/) \
	    && echo "forge built: bin/forge" \
	    || echo "WARNING: forge build failed — scenarios 09+10 may fail"; \
	else \
	  echo "kernloom-forge not found at $(dir $(abspath .))/kernloom-forge — skipping forge build"; \
	fi

# Forge control-plane tests — no XDP/BPF required, runs on standard CI.
# Builds forge binary from ../kernloom-forge if not already present.
integration-forge:
	bash tests/integration/run-forge.sh

integration-clean:
	sudo tests/integration/scenarios/99_cleanup.sh

clean:
	$(MAKE) -C shield/bpf clean
	rm -rf $(BIN)
