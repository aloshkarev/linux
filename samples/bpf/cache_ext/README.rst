.. SPDX-License-Identifier: GPL-2.0

cache_ext BPF samples
=====================

This directory contains small, upstream-facing cache_ext policies ported from
the research examples under ``testing/cache_ext``:

``cache_ext_minimal.bpf.c``
  Records one accessed folio and nominates it once it is reclaimable.

``cache_ext_fifo.bpf.c``
  Maintains a cache_ext list in insertion order and nominates the oldest
  reclaimable folio.

``cache_ext_mru.bpf.c``
  Moves accessed folios to the list head and nominates the most recently used
  reclaimable folio.

``cache_ext_sampling.bpf.c``
  Tracks approximate access counts in an LRU hash map and uses
  ``bpf_cache_ext_list_sample()`` to choose a low-frequency reclaim candidate.

Build notes
-----------

The samples expect a ``vmlinux.h`` generated from the running kernel or from a
kernel BTF file::

  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
  make

Attach a policy to a cgroup with the generic loader::

  ./cache_ext_loader cache_ext_fifo.bpf.o /sys/fs/cgroup fifo_ops

The loader keeps the link alive until it receives ``SIGINT`` or ``SIGTERM``.
