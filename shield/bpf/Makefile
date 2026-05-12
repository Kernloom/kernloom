# SPDX-License-Identifier: GPL-2.0-only

BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Werror
OUTDIR := out

XDP_SRC  := xdp_kernloom_shield.bpf.c
XDP_OBJ  := $(OUTDIR)/xdp_kernloom_shield.bpf.o

TC_SRC   := tc_kernloom_egress.bpf.c
TC_OBJ   := $(OUTDIR)/tc_kernloom_egress.bpf.o

all: $(XDP_OBJ) $(TC_OBJ)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(XDP_OBJ): $(XDP_SRC) | $(OUTDIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(TC_OBJ): $(TC_SRC) | $(OUTDIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTDIR)

.PHONY: all clean