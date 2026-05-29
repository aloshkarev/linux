.. SPDX-License-Identifier: GPL-2.0

=========
cache_ext
=========

``cache_ext`` lets a BPF ``struct_ops`` program participate in page-cache
admission, readahead/preallocation, and reclaim decisions for a memory cgroup.
The kernel still owns folio lifetime, LRU isolation, reclaim, and fallback
behavior; BPF only nominates policy decisions through bounded callbacks and
kfuncs.

Configuration
=============

``cache_ext`` is enabled with ``CONFIG_CACHE_EXT``. The option depends on the
BPF syscall, cgroup BPF, memory cgroups, BPF JIT, and BTF debug information
because policies are loaded as BPF ``struct_ops`` programs and use BTF-typed
kfuncs.

Userspace attaches a policy by loading a BPF object containing a
``struct cache_ext_ops`` map and calling::

  bpf_map__attach_cache_ext_ops(map, cgroup_fd)

The link is scoped to the target cgroup's memory controller. Detaching the link
removes the policy and releases cache_ext data structures for the memcg.

Policy callbacks
================

Policies implement ``struct cache_ext_ops``:

``init(struct mem_cgroup *memcg)``
  Optional sleepable callback. Use it to allocate cache_ext data structures such
  as lists with ``bpf_cache_ext_ds_registry_new_list()``.

``folio_added(struct folio *folio)``
  Called when a folio enters the page cache and is added to the valid-folio
  tracking set. Policies commonly add the folio to a FIFO, MRU, or sampling
  list here.

``folio_accessed(struct folio *folio)``
  Called on page-cache access. Policies can update metadata or reposition the
  folio in a list.

``folio_evicted(struct folio *folio)``
  Called as a folio leaves the page cache. Policies should remove per-folio
  metadata and call ``bpf_cache_ext_list_del()`` if the folio was list-managed.

``admit_folio(struct cache_ext_admission_ctx *ctx)``
  Optional admission and readahead callback. It returns
  ``CACHE_EXT_ADMIT_CACHE``, ``CACHE_EXT_ADMIT_SKIP``, or
  ``CACHE_EXT_ADMIT_PREALLOC``. Input fields describe the file, offset, request
  size, readahead state, and recent prefetch accounting. Output fields allow the
  policy to request readahead pages, preallocation pages, and dropbehind.

``evict_folios(struct cache_ext_eviction_ctx *ctx, struct mem_cgroup *memcg)``
  Called from reclaim. ``request_nr_folios_to_evict`` is input. The policy
  writes up to ``ARRAY_SIZE(ctx->folios_to_evict)`` candidate folio pointers and
  the number of candidates in ``nr_folios_to_evict``. The kernel validates each
  candidate against the memcg/node valid-folio set before attempting isolation.

Data structures and kfuncs
==========================

``bpf_cache_ext_ds_registry_new_list(memcg)``
  Allocates a list and returns an opaque non-zero handle. Handles are stable IDs
  scoped to the attached memcg, not raw kernel pointers.

``bpf_cache_ext_list_add(handle, folio)``,
``bpf_cache_ext_list_add_tail(handle, folio)``,
``bpf_cache_ext_list_move(handle, folio, tail)``, and
``bpf_cache_ext_list_del(folio)``
  Maintain one list node per valid folio. A folio can be in at most one
  cache_ext list at a time.

``bpf_cache_ext_list_iterate(memcg, handle, cb, ctx)``
  Iterates the list and calls ``cb(index, node)``. The callback returns
  ``CACHE_EXT_CONTINUE_ITER``, ``CACHE_EXT_STOP_ITER``, or
  ``CACHE_EXT_EVICT_NODE``. Eviction nominations are copied into the eviction
  context until the fixed candidate array is full.

``bpf_cache_ext_list_sample(memcg, handle, score_cb, opts, ctx)``
  Temporarily samples list nodes, invokes a score callback, and nominates low
  scoring candidates. Oversized samples fail instead of unboundedly allocating
  memory.

``bpf_cache_ext_schedule_prealloc(index, nr_pages, dropbehind)``
  Schedules asynchronous preallocation from admission context. Calls outside a
  valid admission/preallocation file context fail with ``-EINVAL``.

NUMA and lifetime rules
=======================

The data-structure registry is memcg-wide: one registry is kept per memory
cgroup, and handles are valid regardless of the NUMA node that owns an
individual folio. Valid-folio tracking remains node-local so reclaim can reject
stale or cross-node candidates against the lruvec currently under pressure.

On detach, memcg teardown, or callback failure, the kernel clears registered
lists and falls back to ordinary page-cache and LRU behavior. Invalid handles,
stale folios, oversized samples, or empty candidate lists do not bypass kernel
reclaim validation.

Tracing
=======

The implementation emits tracepoints for operational debugging:

``filemap:mm_cache_ext_attach`` and ``filemap:mm_cache_ext_detach``
  Policy attach/detach results.

``filemap:mm_cache_ext_list_op``
  Failed list operations, invalid handles, oversized samples, and list
  allocation exhaustion.

``filemap:mm_cache_ext_prealloc``
  Preallocation scheduling requests and rejected calls.

``vmscan:mm_cache_ext_reclaim``
  Requested, nominated, isolated, and reclaimed folio counts for a reclaim pass.

Extended iteration
==================

``bpf_cache_ext_list_iterate_extended(memcg, handle, cb, opts, ctx)``
  A superset of ``bpf_cache_ext_list_iterate`` that accepts a
  ``struct cache_ext_iterate_opts`` controlling which list segments to iterate
  (``continue_list``/``continue_mode``) versus evict from
  (``evict_list``/``evict_mode``), and caps the per-call budget with
  ``nr_folios_continue`` and ``nr_folios_evict``. Used by the MGLRU and
  GET-SCAN sample policies to implement multi-pass reclaim.

Examples and tests
==================

Curated policies live in ``samples/bpf/cache_ext``. Each policy ships a
skeleton-based userspace loader (e.g. ``cache_ext_fifo --watch_dir <dir>
--cgroup_path <path>``) and a matching BPF program. The initial BPF selftest is
``tools/testing/selftests/bpf/prog_tests/cache_ext_basic.c`` and validates
loading, cgroup attachment, detach cleanup, and creation of an opaque registry
handle. Additional tests should extend this coverage toward verifier-negative
cases, admission decisions, sampling boundaries, stale folio rejection, and
teardown races.

See also
========

:doc:`cache-ext-mglru` — MGLRU internals and coexistence notes.
