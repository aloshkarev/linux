// SPDX-License-Identifier: GPL-2.0
#include "cache_ext_common.bpf.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} last_seen SEC(".maps");

void BPF_STRUCT_OPS(minimal_folio_accessed, struct folio *folio)
{
	u32 key = 0;
	u64 ptr = (u64)folio;

	bpf_map_update_elem(&last_seen, &key, &ptr, BPF_ANY);
}

void BPF_STRUCT_OPS(minimal_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	u32 key = 0;
	u64 *ptr = bpf_map_lookup_elem(&last_seen, &key);
	struct folio *folio;

	if (!ptr)
		return;

	folio = (struct folio *)*ptr;
	if (!cache_ext_folio_reclaimable(folio))
		return;

	eviction_ctx->folios_to_evict[0] = folio;
	eviction_ctx->nr_folios_to_evict = 1;
}

SEC(".struct_ops.link")
struct cache_ext_ops minimal_ops = {
	.folio_accessed = (void *)minimal_folio_accessed,
	.evict_folios = (void *)minimal_evict_folios,
};
