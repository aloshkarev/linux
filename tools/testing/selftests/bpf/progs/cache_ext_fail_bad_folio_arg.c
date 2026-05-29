// SPDX-License-Identifier: GPL-2.0
#include "cache_ext_test_common.h"

char _license[] SEC("license") = "GPL";

static u64 bad_list;

s32 BPF_STRUCT_OPS_SLEEPABLE(cache_ext_bad_arg_init, struct mem_cgroup *memcg)
{
	bad_list = bpf_cache_ext_ds_registry_new_list(memcg);
	return bad_list ? 0 : -1;
}

/*
 * A scalar zero is not a valid trusted struct folio pointer for list kfuncs.
 * This catches accidental use of cache_ext list helpers outside folio callback
 * contexts that provide real folio arguments.
 */
void BPF_STRUCT_OPS(cache_ext_bad_arg_accessed, struct folio *folio)
{
	bpf_cache_ext_list_add_tail(bad_list, (struct folio *)0);
}

SEC(".struct_ops.link")
struct cache_ext_ops bad_folio_arg_ops = {
	.init = (void *)cache_ext_bad_arg_init,
	.folio_accessed = (void *)cache_ext_bad_arg_accessed,
};
