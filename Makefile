# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Adrian Enderlin

GOPATH   ?= $(shell go env GOPATH)
BIN      := bin
BPFOBJ   := shield/bpf/out/xdp_kernloom_shield.bpf.o

.PHONY: all build bpf test integration integration-clean clean

all: build

bpf:
	$(MAKE) -C shield/bpf

build: bpf
	mkdir -p $(BIN)
	go build -o $(BIN)/klshield ./shield/cmd/klshield
	go build -o $(BIN)/kliq     ./iq/cmd/kliq

test:
	go test ./...

integration: build
	sudo tests/integration/run.sh

integration-clean:
	sudo tests/integration/scenarios/99_cleanup.sh

clean:
	$(MAKE) -C shield/bpf clean
	rm -rf $(BIN)
