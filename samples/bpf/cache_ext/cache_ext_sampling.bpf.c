// SPDX-License-Identifier: GPL-2.0
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define INT64_MAX  (9223372036854775807LL)

/* #define DEBUG */
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

/*
 * Maps
 */
#define MAX_PAGES (1 << 20)

struct folio_metadata {
	u64 accesses;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct folio_metadata);
	__uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

__u64 sampling_list;

#define MAX_STAT_NAME_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[MAX_STAT_NAME_LEN]);
	__type(value, s64);
	__uint(max_entries, 256);
} stats SEC(".maps");

/* App type for specific optimizations */
enum App {
	GENERIC_APP,
	LEVELDB,
};

char STAT_SCAN_PAGES[MAX_STAT_NAME_LEN]          = "scan_pages";
char STAT_TOTAL_PAGES[MAX_STAT_NAME_LEN]         = "total_pages";
char STAT_EVICTED_SCAN_PAGES[MAX_STAT_NAME_LEN]  = "evicted_scan_pages";
char STAT_EVICTED_TOTAL_PAGES[MAX_STAT_NAME_LEN] = "evicted_total_pages";

const int APP_TYPE = GENERIC_APP;

static inline void update_stat(char (*stat_name)[MAX_STAT_NAME_LEN], s64 delta)
{
#ifdef DEBUG
	u64 *counter = bpf_map_lookup_elem(&stats, stat_name);

	if (!counter) {
		u64 zero = 0;

		bpf_map_update_elem(&stats, stat_name, &zero, BPF_NOEXIST);
		counter = bpf_map_lookup_elem(&stats, stat_name);
	}
	if (counter)
		__sync_fetch_and_add(counter, delta);
#endif
}

static inline bool is_folio_relevant(struct folio *folio)
{
	if (!folio || folio->mapping == NULL || folio->mapping->host == NULL)
		return false;

	return inode_in_watchlist(folio->mapping->host->i_ino);
}

static inline bool is_last_page_in_file(struct folio *folio)
{
	struct address_space *mapping = folio->mapping;
	struct inode *inode;
	unsigned long long file_size, page_index, last_page_index;

	if (!mapping)
		return false;
	inode = mapping->host;
	if (!inode)
		return false;
	if (folio_test_large(folio) || folio_test_hugetlb(folio)) {
		bpf_printk("cache_ext: Hugepages not supported\n");
		return false;
	}
	file_size = i_size_read(inode);
	page_index = folio_index(folio);
	last_page_index = (file_size + 4096 - 1) / 4096 - 1;
	return page_index == last_page_index;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sampling_init, struct mem_cgroup *memcg)
{
	dbg_printk("cache_ext: Hi from the sampling_init hook!\n");
	sampling_list = bpf_cache_ext_ds_registry_new_list(memcg);
	if (sampling_list == 0) {
		bpf_printk("cache_ext: Failed to create sampling_list\n");
		return -1;
	}
	bpf_printk("cache_ext: Created sampling_list: %llu\n", sampling_list);
	return 0;
}

void BPF_STRUCT_OPS(sampling_folio_added, struct folio *folio)
{
	struct folio_metadata new_meta = { .accesses = 1 };
	u64 key;

	dbg_printk("cache_ext: Hi from the sampling_folio_added hook!\n");
	if (!is_folio_relevant(folio))
		return;

	if (bpf_cache_ext_list_add_tail(sampling_list, folio)) {
		bpf_printk("cache_ext: Failed to add folio to sampling_list\n");
		return;
	}
	dbg_printk("cache_ext: Added folio to sampling_list\n");
	update_stat(&STAT_TOTAL_PAGES, 1);

	key = (u64)folio;
	bpf_map_update_elem(&folio_metadata_map, &key, &new_meta, BPF_ANY);
}

void BPF_STRUCT_OPS(sampling_folio_accessed, struct folio *folio)
{
	struct folio_metadata *meta;
	u64 key;

	if (!is_folio_relevant(folio))
		return;

	key = (u64)folio;
	meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
	if (!meta) {
		struct folio_metadata new_meta = { 0 };
		int ret = bpf_map_update_elem(&folio_metadata_map, &key,
					      &new_meta, BPF_ANY);

		if (ret != 0) {
			bpf_printk("cache_ext: Failed to create folio metadata. ret=%d\n",
				   ret);
			return;
		}
		meta = bpf_map_lookup_elem(&folio_metadata_map, &key);
		if (!meta) {
			bpf_printk("cache_ext: Failed to get created folio metadata\n");
			return;
		}
	}
	__sync_fetch_and_add(&meta->accesses, 1);
}

void BPF_STRUCT_OPS(sampling_folio_evicted, struct folio *folio)
{
	u64 key;

	dbg_printk("cache_ext: Hi from the sampling_folio_evicted hook!\n");
	key = (u64)folio;
	bpf_map_delete_elem(&folio_metadata_map, &key);
	update_stat(&STAT_TOTAL_PAGES, -1);
	update_stat(&STAT_EVICTED_TOTAL_PAGES, 1);
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node *a)
{
	struct folio_metadata *meta_a;
	u64 key_a = (u64)a->folio;
	s64 score;

	meta_a = bpf_map_lookup_elem(&folio_metadata_map, &key_a);
	if (!meta_a) {
		bpf_printk("cache_ext: Failed to get metadata\n");
		return INT64_MAX;
	}
	score = meta_a->accesses;
	if (APP_TYPE == LEVELDB && is_last_page_in_file(a->folio))
		score += 100000;

	if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
		return INT64_MAX;
	if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
		return INT64_MAX;

	return score;
}

void BPF_STRUCT_OPS(sampling_evict_folios,
		    struct cache_ext_eviction_ctx *eviction_ctx,
		    struct mem_cgroup *memcg)
{
	struct sampling_options sampling_opts = {
		.sample_size = 20,
	};

	dbg_printk("cache_ext: Hi from the sampling_evict_folios hook!\n");
	bpf_cache_ext_list_sample(memcg, sampling_list, bpf_lfu_score_fn,
				  &sampling_opts, eviction_ctx);
	dbg_printk("cache_ext: Evicting %d pages (%d requested)\n",
		   eviction_ctx->nr_folios_to_evict,
		   eviction_ctx->request_nr_folios_to_evict);
}

SEC(".struct_ops.link")
struct cache_ext_ops sampling_ops = {
	.init           = (void *)sampling_init,
	.evict_folios   = (void *)sampling_evict_folios,
	.folio_accessed = (void *)sampling_folio_accessed,
	.folio_evicted  = (void *)sampling_folio_evicted,
	.folio_added    = (void *)sampling_folio_added,
};
