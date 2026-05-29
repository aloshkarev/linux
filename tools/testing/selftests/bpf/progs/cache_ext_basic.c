// SPDX-License-Identifier: GPL-2.0
#include "cache_ext_test_common.h"

char _license[] SEC("license") = "GPL";

u64 list_handle;
u64 init_called;
u64 added_called;
u64 evicted_called;
u64 evict_called;
u64 prealloc_reject_ret;
s64 invalid_iter_ret;
s64 invalid_sample_ret;
s64 oversized_sample_ret;
struct cache_ext_eviction_ctx init_eviction_ctx;
struct sampling_options oversized_opts;
struct sampling_options sample_opts;

static int never_select(int idx, struct cache_ext_list_node *node)
{
	return CACHE_EXT_CONTINUE_ITER;
}

static s64 zero_score(struct cache_ext_list_node *node)
{
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cache_ext_basic_init, struct mem_cgroup *memcg)
{
	list_handle = bpf_cache_ext_ds_registry_new_list(memcg);
	init_called++;
	init_eviction_ctx.request_nr_folios_to_evict = 1;
	init_eviction_ctx.nr_folios_to_evict = 0;
	oversized_opts.sample_size = 2049;
	oversized_opts.select_size = 1;
	sample_opts.sample_size = 1;
	sample_opts.select_size = 1;
	invalid_iter_ret = bpf_cache_ext_list_iterate(memcg, 0, never_select,
						      &init_eviction_ctx);
	invalid_sample_ret = bpf_cache_ext_list_sample(memcg, 0, zero_score,
						       &sample_opts,
						       &init_eviction_ctx);
	oversized_sample_ret = bpf_cache_ext_list_sample(memcg, list_handle,
							 zero_score,
							 &oversized_opts,
							 &init_eviction_ctx);
	return list_handle ? 0 : -1;
}

void BPF_STRUCT_OPS(cache_ext_basic_folio_added, struct folio *folio)
{
	added_called++;
	if (list_handle)
		bpf_cache_ext_list_add_tail(list_handle, folio);
}

void BPF_STRUCT_OPS(cache_ext_basic_folio_accessed, struct folio *folio)
{
	if (list_handle)
		bpf_cache_ext_list_move(list_handle, folio, false);
}

void BPF_STRUCT_OPS(cache_ext_basic_folio_evicted, struct folio *folio)
{
	evicted_called++;
	bpf_cache_ext_list_del(folio);
}

static int select_first(int idx, struct cache_ext_list_node *node)
{
	return node->folio ? CACHE_EXT_EVICT_NODE : CACHE_EXT_CONTINUE_ITER;
}

void BPF_STRUCT_OPS(cache_ext_basic_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	evict_called++;
	if (list_handle)
		bpf_cache_ext_list_iterate(memcg, list_handle, select_first,
					   eviction_ctx);
}

s32 BPF_STRUCT_OPS(cache_ext_basic_admit_folio,
		   struct cache_ext_admission_ctx *admission_ctx)
{
	admission_ctx->readahead_pages = 1;
	admission_ctx->prealloc_pages = 1;
	admission_ctx->dropbehind = 1;
	return 0;
}

SEC(".struct_ops.link")
struct cache_ext_ops prealloc_reject_ops = {
	.init = (void *)cache_ext_basic_init,
	.admit_folio = (void *)cache_ext_basic_admit_folio,
};

s32 BPF_STRUCT_OPS_SLEEPABLE(cache_ext_prealloc_reject_init,
			     struct mem_cgroup *memcg)
{
	prealloc_reject_ret = bpf_cache_ext_schedule_prealloc(0, 1, false);
	return 0;
}

SEC(".struct_ops.link")
struct cache_ext_ops prealloc_reject_init_ops = {
	.init = (void *)cache_ext_prealloc_reject_init,
};

s32 BPF_STRUCT_OPS_SLEEPABLE(cache_ext_init_fail, struct mem_cgroup *memcg)
{
	return -22;
}

SEC(".struct_ops.link")
struct cache_ext_ops init_fail_ops = {
	.init = (void *)cache_ext_init_fail,
};

SEC(".struct_ops.link")
struct cache_ext_ops basic_ops = {
	.init = (void *)cache_ext_basic_init,
	.folio_added = (void *)cache_ext_basic_folio_added,
	.folio_accessed = (void *)cache_ext_basic_folio_accessed,
	.folio_evicted = (void *)cache_ext_basic_folio_evicted,
	.evict_folios = (void *)cache_ext_basic_evict_folios,
	.admit_folio = (void *)cache_ext_basic_admit_folio,
};
