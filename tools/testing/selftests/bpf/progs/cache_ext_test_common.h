/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CACHE_EXT_TEST_COMMON_H
#define __CACHE_EXT_TEST_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

#ifdef CACHE_EXT_SELFTEST_STUB_TYPES
struct cache_ext_list_node {
	struct folio *folio;
	struct list_head node;
};

struct cache_ext_eviction_ctx {
	unsigned long request_nr_folios_to_evict;
	unsigned long nr_folios_to_evict;
	struct folio *folios_to_evict[32];
	s64 scores[32];
};

struct cache_ext_admission_ctx {
	u64 ino;
	u64 file_id;
	u64 offset;
	u64 size;
	u64 i_size;
	u64 ra_prev_pos;
	u32 ra_size;
	u32 ra_async_size;
	u32 ra_order;
	u32 ra_pages_max;
	u32 iocb_flags;
	u32 readahead_pages;
	u32 prealloc_pages;
	u32 dropbehind;
	u64 ra_prefetch_added;
	u64 ra_prefetch_hit;
	u64 ra_prefetch_miss;
	u64 ra_prefetch_inflight;
	u64 inode_ra_prefetch_added;
	u64 inode_ra_prefetch_hit;
	u64 inode_ra_prefetch_miss;
	u64 inode_ra_prefetch_inflight;
	u64 file_ra_prefetch_added;
	u64 file_ra_prefetch_hit;
	u64 file_ra_prefetch_miss;
	u64 file_ra_prefetch_inflight;
};

struct sampling_options {
	u32 sample_size;
	u32 select_size;
};

struct cache_ext_ops {
	s32 (*init)(struct mem_cgroup *memcg);
	void (*evict_folios)(struct cache_ext_eviction_ctx *ctx,
			     struct mem_cgroup *memcg);
	void (*folio_added)(struct folio *folio);
	void (*folio_accessed)(struct folio *folio);
	void (*folio_evicted)(struct folio *folio);
	s32 (*admit_folio)(struct cache_ext_admission_ctx *ctx);
};
#endif

int bpf_cache_ext_list_add(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio) __ksym;
int bpf_cache_ext_list_del(struct folio *folio) __ksym;
int bpf_cache_ext_list_move(u64 list, struct folio *folio, bool tail) __ksym;
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct cache_ext_eviction_ctx *ctx) __ksym;
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *node),
			      struct sampling_options *opts,
			      struct cache_ext_eviction_ctx *ctx) __ksym;
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg) __ksym;
int bpf_cache_ext_schedule_prealloc(u64 index, u32 nr_pages,
				    bool dropbehind) __ksym;

#endif /* __CACHE_EXT_TEST_COMMON_H */
