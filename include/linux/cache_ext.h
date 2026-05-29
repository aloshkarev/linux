#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H 1

/*
 * BPF-Exposed data structures for cache_ext.
 */

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct cache_ext_eviction_ctx;
struct mem_cgroup;
struct folio;
struct file;

bool cache_ext_is_callback_calling_kfunc_iterate(u32 btf_id);
bool cache_ext_is_callback_calling_kfunc_sample(u32 btf_id);

/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

/*
 * Indexed Linked List.
 *
 * This is a linked list that is indexed by the folio it contains. This is
 * because we need to be able to quickly:
 * - Find the folio corresponding to a given node.
 * - Find the node corresponding to a given folio.
 *
 * Instead of maintaining a hash-table per list, we can piggyback on the valid
 * folios hashtable we already maintain. It will also keep a pointer to the node
 * in the valid_folio struct.
 */
struct cache_ext_list {
	struct list_head head;
	/* This is for the ds registry. */
	struct hlist_node h_node;
	u64 id;
};

struct cache_ext_list_node {
	struct folio *folio;
	struct list_head node;
};

/*
 * BPF API
 */

struct sampling_options {
	__u32 sample_size;
	__u32 select_size;
};

struct cache_ext_iterate_opts {
	u64 continue_list;
	u64 continue_mode;
	u64 evict_list;
	u64 evict_mode;
	u64 nr_folios_continue;
	u64 nr_folios_evict;
};

int bpf_cache_ext_list_add(u64 list, struct folio *folio);
int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio);
int bpf_cache_ext_list_move(u64 list, struct folio *folio, bool tail);
int bpf_cache_ext_list_del(struct folio *folio);
int bpf_cache_ext_list_iterate(struct mem_cgroup *memcg, u64 list,
			       int(iter_fn)(int idx,
					    struct cache_ext_list_node *node),
			       struct cache_ext_eviction_ctx *ctx);
int bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			      s64(score_fn)(struct cache_ext_list_node *a),
			      struct sampling_options *opts,
			      struct cache_ext_eviction_ctx *ctx);
int bpf_cache_ext_list_iterate_extended(struct mem_cgroup *memcg, u64 list,
					int(iter_fn)(int idx,
						     struct cache_ext_list_node *node),
					struct cache_ext_iterate_opts *opts,
					struct cache_ext_eviction_ctx *ctx);
u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg);

void cache_ext_schedule_prealloc(struct file *file, u64 index,
				 unsigned long ra_pages, bool dropbehind);
void cache_ext_set_prealloc_file(struct file *file);
void cache_ext_clear_prealloc_file(void);

int bpf_cache_ext_schedule_prealloc(u64 index, u32 nr_pages, bool dropbehind);

/*
 * Used by the valid_folios_set code
 */
struct cache_ext_list_node *cache_ext_list_node_alloc(struct folio *folio);
void cache_ext_list_node_free(struct cache_ext_list_node *node);

/*
 * cache_ext data structure registry.
 */

#define CACHE_EXT_REGISTRY_MAX_ENTRIES 5

/* NOTE: For now, tie the registry lifetime to the struct_ops lifetime. */
struct cache_ext_ds_registry {
	DECLARE_HASHTABLE(ds_hash, 5);
	rwlock_t lock;
	int nr_entries;
	u64 next_id;
};

void cache_ext_ds_registry_init(struct cache_ext_ds_registry *registry);
void cache_ext_ds_registry_read_lock(struct folio *folio);
void cache_ext_ds_registry_read_unlock(struct folio *folio);
void cache_ext_ds_registry_write_lock(struct folio *folio);
void cache_ext_ds_registry_write_unlock(struct folio *folio);
void cache_ext_ds_registry_del_all(struct mem_cgroup *memcg);
struct cache_ext_list *cache_ext_ds_registry_new_list(struct mem_cgroup *memcg);
struct cache_ext_list *
cache_ext_ds_registry_get(struct cache_ext_ds_registry *registry, u64 list_ptr);
struct cache_ext_ds_registry *
cache_ext_ds_registry_from_folio(struct folio *folio);
struct cache_ext_ds_registry *
cache_ext_ds_registry_from_memcg(struct mem_cgroup *memcg);

#endif /* _LINUX_CACHE_EXT_H */
