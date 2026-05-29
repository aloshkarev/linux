// SPDX-License-Identifier: GPL-2.0
#include "cache_ext_test_common.h"

char _license[] SEC("license") = "GPL";

/*
 * bpf_cache_ext_ds_registry_new_list() is KF_SLEEPABLE. Calling it from a
 * non-sleepable folio callback must be rejected by the verifier.
 */
void BPF_STRUCT_OPS(cache_ext_bad_folio_added, struct folio *folio)
{
	bpf_cache_ext_ds_registry_new_list((struct mem_cgroup *)0);
}

SEC(".struct_ops.link")
struct cache_ext_ops bad_sleepable_ops = {
	.folio_added = (void *)cache_ext_bad_folio_added,
};
