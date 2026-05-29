/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CACHE_EXT_COMMON_BPF_H
#define __CACHE_EXT_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
	SEC("struct_ops.s/" #name)              \
	BPF_PROG(name, ##args)

enum cache_ext_iter_callback_ret {
	CACHE_EXT_CONTINUE_ITER = 0,
	CACHE_EXT_STOP_ITER = 1,
	CACHE_EXT_EVICT_NODE = 2,
};

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_move(u64 list, struct folio *folio, bool tail) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_iterate_extended(struct mem_cgroup *memcg, u64 list,
					int(iter_fn)(int idx,
						     struct cache_ext_list_node *node),
					struct cache_ext_iterate_opts *opts,
					struct cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *node),
			      struct sampling_options *opts,
			      struct cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;

static __always_inline unsigned long *cache_ext_folio_flags(struct folio *folio)
{
	struct page *page = &folio->page;

	return &page->flags;
}

static __always_inline bool cache_ext_test_bit(unsigned int bit,
					       const unsigned long *addr)
{
	return (*addr >> bit) & 1;
}

static __always_inline bool cache_ext_folio_reclaimable(struct folio *folio)
{
	unsigned long *flags;

	if (!folio)
		return false;

	flags = cache_ext_folio_flags(folio);
	if (!cache_ext_test_bit(PG_uptodate, flags) ||
	    !cache_ext_test_bit(PG_lru, flags) ||
	    cache_ext_test_bit(PG_dirty, flags) ||
	    cache_ext_test_bit(PG_writeback, flags) ||
	    cache_ext_test_bit(PG_unevictable, flags))
		return false;

	return true;
}

#endif /* __CACHE_EXT_COMMON_BPF_H */
