# SPDX-License-Identifier: GPL-2.0
CLANG    ?= clang
CC       ?= gcc
KERNEL_SRC ?= ../../..
TOOLS_PATH := $(abspath $(KERNEL_SRC)/tools)
LIBBPF_SRC := $(TOOLS_PATH)/lib/bpf
LIBBPF_A   := $(LIBBPF_SRC)/libbpf.a
LIBBPF_CFLAGS ?= -I$(TOOLS_PATH)/lib -I$(TOOLS_PATH)/include
LIBBPF_LIBS   ?= $(LIBBPF_A) -lelf -lz

# In-tree bpftool; fall back to installed bpftool if not built yet.
BPFTOOL ?= $(TOOLS_PATH)/bpf/bpftool/bpftool

# Architecture detection for BPF target
ARCH ?= $(shell uname -m | sed \
	-e 's/x86_64/x86/' \
	-e 's/arm.*/arm/' \
	-e 's/aarch64/arm64/' \
	-e 's/ppc64le/powerpc/' \
	-e 's/mips.*/mips/' \
	-e 's/riscv64/riscv/' \
	-e 's/loongarch64/loongarch/')

BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
USER_CFLAGS := -Wall -O2 $(LIBBPF_CFLAGS) -I.

VMLINUX_H := vmlinux.h

# Policies that have full userspace loaders (skeleton-based)
POLICIES := fifo mru sampling s3fifo lhd mglru get_scan

BPF_OBJECTS := \
	cache_ext_minimal.bpf.o \
	$(foreach p,$(POLICIES),cache_ext_$(p).bpf.o)

POLICY_BINS := $(foreach p,$(POLICIES),cache_ext_$(p))

all: $(VMLINUX_H) cache_ext_loader $(BPF_OBJECTS) $(POLICY_BINS)

$(LIBBPF_A):
	$(MAKE) -C $(LIBBPF_SRC)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# BPF compilation
%.bpf.o: %.bpf.c cache_ext_common.bpf.h cache_ext_lib.bpf.h dir_watcher.bpf.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Skeleton generation (intermediate; preserved across clean for inspection)
.PRECIOUS: %.skel.h
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Generic loader (accepts policy .bpf.o + cgroup path on the command line)
cache_ext_loader: cache_ext_loader.c $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

# Per-policy skeleton-based loaders
cache_ext_fifo:     cache_ext_fifo.c     cache_ext_fifo.skel.h     $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_mru:      cache_ext_mru.c      cache_ext_mru.skel.h      $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_sampling: cache_ext_sampling.c cache_ext_sampling.skel.h $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_s3fifo:   cache_ext_s3fifo.c   cache_ext_s3fifo.skel.h   $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_lhd:      cache_ext_lhd.c      cache_ext_lhd.skel.h      $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_mglru:    cache_ext_mglru.c    cache_ext_mglru.skel.h    $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

cache_ext_get_scan: cache_ext_get_scan.c cache_ext_get_scan.skel.h $(LIBBPF_A)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	$(RM) cache_ext_loader $(BPF_OBJECTS) $(POLICY_BINS) *.skel.h $(VMLINUX_H)

.PHONY: all clean
