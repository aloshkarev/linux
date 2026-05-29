.. SPDX-License-Identifier: GPL-2.0

==============================
cache_ext and MGLRU internals
==============================

This document collects implementation notes on Multi-Gen LRU (MGLRU) relevant
to understanding how cache_ext policies interoperate with the default reclaim
path when ``CONFIG_LRU_GEN`` is enabled.

MGLRU overview
==============

MGLRU organises page-cache and anonymous folios into multiple generations.
Each generation is a collection of folios with similar access recency.

Key data:

- The generation counter is stored in ``folio->flags`` (values range from
  ``MIN_NR_GENS`` to ``MAX_NR_GENS``).
- Each generation has multiple **tiers**. The tier counter records
  ``order_base_2(accesses)`` and is updated via an atomic CAS on ``folio->flags``.
- A PID controller monitors the refault rate across all tiers and decides which
  tiers to evict from.  The goal is to balance the refault percentage between
  file-backed and anonymous folios in proportion to swappiness.

Per-list state:

``max_seq``
  Index of the youngest (most recently aged) generation.

``min_seq``
  Index of the oldest generation, which is the eviction candidate.

Per-folio state:

``gen_counter``
  Which generation this folio belongs to.  Newly promoted folios are placed in
  ``(max_seq % MAX_NR_GENS) + 1``.

Aging
-----

Aging increments ``max_seq``, creating a new empty generation and pushing older
generations toward ``min_seq``.

Eviction
--------

Eviction consumes generations starting from the oldest.  When
``lrugen->folios[min_seq % MAX_NR_GENS]`` becomes empty, ``min_seq`` is
incremented.

``order_base_2(N)`` returns the position of the highest set bit of *N* (that
is, the floor of the base-2 logarithm), which determines the tier a folio is
placed in based on its reference count.

Eviction code path
==================

1. ``try_to_shrink_lruvec`` — top-level shrinker entry point.
2. ``evict_folios`` — acquires the lruvec lock.
3. ``isolate_folios`` — decides which tier and type (anon/file) to drain, using
   the PID controller output.
4. ``scan_folios`` — scans the lowest generation
   (``lru_gen_from_seq(lrugen->min_seq[type])``).

   a. ``sort_folio`` — checks whether a folio needs promotion or special
      handling, and promotes any folio whose tier exceeds the tier chosen in
      step 3 to the next generation.
   b. ``isolate_folio`` — performs actual isolation if ``sort_folio`` did not
      promote the folio.
   c. Folios that could neither be sorted nor isolated are skipped and returned
      to the list tail.

Aging code path (happens during eviction)
-----------------------------------------

1. ``try_to_shrink_lruvec``
2. ``get_nr_to_scan``
3. ``should_run_aging`` / ``try_to_inc_max_seq``

Tiers
-----

The maximum number of tiers is ``MAX_NR_TIERS`` (currently 4).  Each folio
tracks its reference count through file-descriptor accesses via
``folio_lru_refs()``.  This information is stored in page flags and updated
with a CAS instruction.  The tier of a folio is derived from its reference
count with ``lru_tier_from_refs()``.

cache_ext and MGLRU coexistence
================================

When both ``CONFIG_CACHE_EXT`` and ``CONFIG_LRU_GEN`` are enabled:

- The cache_ext ``evict_folios`` callback is invoked **before** the normal
  MGLRU reclaim path for the target memcg.  Nominees returned by the BPF
  policy are validated against the memcg valid-folio set and isolated from
  their LRU generation before being passed to ``shrink_folio_list``.
- Folios that the BPF policy does not nominate (or that fail validation) are
  recycled through the normal MGLRU pipeline unchanged.
- The cache_ext ``folio_added`` and ``folio_evicted`` callbacks fire
  regardless of which LRU generation the folio is placed in.
- The MGLRU aging and promotion logic is not visible to the BPF policy; the
  policy operates only on the handles and folios it has registered via
  ``bpf_cache_ext_ds_registry_new_list`` and ``bpf_cache_ext_list_*`` kfuncs.

The ``cache_ext_mglru`` sample policy (``samples/bpf/cache_ext/cache_ext_mglru.bpf.c``)
reimplements MGLRU semantics in BPF, demonstrating how a policy can track
generation and tier counters in a BPF hash map and replicate the kernel's
recency-based selection logic in user-controlled BPF code.

See also
========

* :doc:`cache-ext` — full cache_ext API reference.
* ``mm/vmscan.c`` — MGLRU eviction and aging implementation.
* ``include/linux/mm_inline.h`` — ``folio_lru_refs``, ``lru_tier_from_refs``.
