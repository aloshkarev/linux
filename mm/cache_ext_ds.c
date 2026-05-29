/*
 * BPF-Exposed data structures for cache_ext.
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/memcontrol.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/cache_ext.h>
#include <linux/btf.h>
#include <linux/mm_types.h>
#include <linux/sort.h>
#include <linux/file.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <trace/events/filemap.h>

/******************************************************************************
 * Linked List ****************************************************************
 *****************************************************************************/

static struct cache_ext_list *cache_ext_list_alloc(void)
{
	struct cache_ext_list *list =
		kmalloc(sizeof(struct cache_ext_list), GFP_KERNEL);
	if (!list)
		return NULL;

	INIT_LIST_HEAD(&list->head);
	return list;
}

struct cache_ext_list_node *cache_ext_list_node_alloc(struct folio *folio)
{
	struct cache_ext_list_node *node =
		kmalloc(sizeof(struct cache_ext_list_node), GFP_KERNEL);
	if (!node)
		return NULL;

	INIT_LIST_HEAD(&node->node);
	node->folio = folio;
	return node;
}

void cache_ext_list_node_free(struct cache_ext_list_node *node)
{
	kfree(node);
}

static int __cache_ext_list_add_impl(struct cache_ext_list *list,
				     struct folio *folio, bool tail)
{
	struct valid_folios_set *valid_folios_set = folio_to_valid_folios_set(folio);
	spinlock_t *bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);
	struct valid_folio *valid_folio;

	spin_lock(bucket_lock);
	valid_folio = valid_folios_lookup(folio);
	if (!valid_folio) {
		spin_unlock(bucket_lock);
		return -1;
	}

	/* Get the global list lock */
	cache_ext_ds_registry_write_lock(folio);

	/* Is this node already in a list? */
	if (!list_empty(&valid_folio->cache_ext_node->node)) {
		cache_ext_ds_registry_write_unlock(folio);
		spin_unlock(bucket_lock);
		return -1;
	}

	if (tail)
		list_add_tail(&valid_folio->cache_ext_node->node, &list->head);
	else
		list_add(&valid_folio->cache_ext_node->node, &list->head);

	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

static int cache_ext_list_add(struct cache_ext_list *list, struct folio *folio)
{
	return __cache_ext_list_add_impl(list, folio, false);
}

static int cache_ext_list_add_tail(struct cache_ext_list *list, struct folio *folio)
{
	return __cache_ext_list_add_impl(list, folio, true);
}

static int cache_ext_list_move(struct cache_ext_list *list, struct folio *folio,
			       bool tail)
{
	struct valid_folios_set *valid_folios_set = folio_to_valid_folios_set(folio);
	spinlock_t *bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);
	struct valid_folio *valid_folio;

	spin_lock(bucket_lock);
	valid_folio = valid_folios_lookup(folio);
	if (!valid_folio) {
		spin_unlock(bucket_lock);
		return -1;
	}

	cache_ext_ds_registry_write_lock(folio);

	if (tail)
		list_move_tail(&valid_folio->cache_ext_node->node, &list->head);
	else
		list_move(&valid_folio->cache_ext_node->node, &list->head);

	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

static int cache_ext_list_del(struct folio *folio)
{
	struct valid_folios_set *valid_folios_set = folio_to_valid_folios_set(folio);
	spinlock_t *bucket_lock = valid_folios_set_get_bucket_lock(valid_folios_set, folio);
	struct valid_folio *valid_folio;

	spin_lock(bucket_lock);

	valid_folio = valid_folios_lookup(folio);
	if (!valid_folio) {
		spin_unlock(bucket_lock);
		return -ENOENT;
	}

	cache_ext_ds_registry_write_lock(folio);

	if (list_empty(&valid_folio->cache_ext_node->node)) {
		cache_ext_ds_registry_write_unlock(folio);
		spin_unlock(bucket_lock);
		return -1;
	}

	list_del_init(&valid_folio->cache_ext_node->node);

	cache_ext_ds_registry_write_unlock(folio);
	spin_unlock(bucket_lock);
	return 0;
}

enum cache_ext_iter_callback_ret {
	CACHE_EXT_CONTINUE_ITER = 0,
	CACHE_EXT_STOP_ITER = 1,
	CACHE_EXT_EVICT_NODE = 2,
};

enum cache_ext_iter_ret {
	CACHE_EXT_DONE_ITER = 0,
	CACHE_EXT_MAX_ITER_REACHED = 8,
	CACHE_EXT_EVICT_ARRAY_FILLED = 9,
};

static int cache_ext_list_iterate(struct mem_cgroup *memcg,
				  struct cache_ext_list *list, void *iter_fn,
				  struct cache_ext_eviction_ctx *ctx)
{
	u64 ret = CACHE_EXT_DONE_ITER, cb_ret, iter = 0;
	u64 max_iter = 4096;
	struct cache_ext_list_node *node;
	bpf_callback_t bpf_iter_fn = (bpf_callback_t)iter_fn;
	struct cache_ext_ds_registry *registry;

	if (ctx->nr_folios_to_evict >= ARRAY_SIZE(ctx->folios_to_evict))
		return CACHE_EXT_EVICT_ARRAY_FILLED;

	registry = cache_ext_ds_registry_from_memcg(memcg);
	read_lock(&registry->lock);

	list_for_each_entry(node, &list->head, node) {
		if (iter > max_iter) {
			ret = CACHE_EXT_MAX_ITER_REACHED;
			break;
		}

		cb_ret = bpf_iter_fn((u64)iter, (u64)(uintptr_t)node, (u64)0,
				     (u64)0, (u64)0);
		iter++;

		if (cb_ret == CACHE_EXT_CONTINUE_ITER) {
			continue;
		} else if (cb_ret == CACHE_EXT_STOP_ITER) {
			ret = CACHE_EXT_DONE_ITER;
			break;
		} else if (cb_ret == CACHE_EXT_EVICT_NODE) {
			ctx->folios_to_evict[ctx->nr_folios_to_evict] = node->folio;
			ctx->nr_folios_to_evict++;

			if (ctx->nr_folios_to_evict == ARRAY_SIZE(ctx->folios_to_evict)) {
				ret = CACHE_EXT_EVICT_ARRAY_FILLED;
				break;
			}
		} else {
			pr_warn("cache_ext: unknown iterate return code\n");
			break;
		}
	}

	read_unlock(&registry->lock);
	return ret;
}

enum cache_ext_iterate_mode {
	CACHE_EXT_ITERATE_SKIP = 0,
	CACHE_EXT_ITERATE_HEAD,
	CACHE_EXT_ITERATE_TAIL,
	CACHE_EXT_ITERATE_MAX,
};

enum cache_ext_iterate_list {
	CACHE_EXT_ITERATE_SELF = 0,
};

static bool cache_ext_validate_iterate_opts(struct cache_ext_iterate_opts *opts)
{
	if (opts->continue_mode >= CACHE_EXT_ITERATE_MAX)
		return false;
	if (opts->evict_mode >= CACHE_EXT_ITERATE_MAX)
		return false;
	if (opts->continue_list != CACHE_EXT_ITERATE_SELF &&
	    opts->continue_mode == CACHE_EXT_ITERATE_SKIP)
		return false;
	if (opts->evict_list != CACHE_EXT_ITERATE_SELF &&
	    opts->evict_mode == CACHE_EXT_ITERATE_SKIP)
		return false;
	return true;
}

static int cache_ext_list_iterate_extended(struct mem_cgroup *memcg,
					   struct cache_ext_list *list,
					   void *iter_fn,
					   struct cache_ext_iterate_opts *opts,
					   struct cache_ext_eviction_ctx *ctx)
{
	u64 ret = CACHE_EXT_DONE_ITER, cb_ret, iter = 0;
	u64 max_iter = 4096;
	struct cache_ext_list_node *node, *node2;
	bpf_callback_t bpf_iter_fn = (bpf_callback_t)iter_fn;
	struct cache_ext_list *continue_list, *evict_list;
	struct cache_ext_ds_registry *registry;

	if (!cache_ext_validate_iterate_opts(opts))
		return -1;

	if (ctx->nr_folios_to_evict >= ARRAY_SIZE(ctx->folios_to_evict))
		return CACHE_EXT_EVICT_ARRAY_FILLED;

	registry = cache_ext_ds_registry_from_memcg(memcg);

	if (opts->continue_list != CACHE_EXT_ITERATE_SELF) {
		continue_list = cache_ext_ds_registry_get(registry, opts->continue_list);
		if (!continue_list)
			return -1;
	} else {
		continue_list = list;
	}

	if (opts->evict_list != CACHE_EXT_ITERATE_SELF) {
		evict_list = cache_ext_ds_registry_get(registry, opts->evict_list);
		if (!evict_list)
			return -1;
	} else {
		evict_list = list;
	}

	if (opts->continue_mode == CACHE_EXT_ITERATE_SKIP &&
	    opts->evict_mode == CACHE_EXT_ITERATE_SKIP)
		read_lock(&registry->lock);
	else
		write_lock(&registry->lock);

	list_for_each_entry_safe(node, node2, &list->head, node) {
		if (iter > max_iter) {
			ret = CACHE_EXT_MAX_ITER_REACHED;
			break;
		}

		cb_ret = bpf_iter_fn((u64)iter, (u64)(uintptr_t)node, (u64)0,
				     (u64)0, (u64)0);
		iter++;

		if (cb_ret == CACHE_EXT_CONTINUE_ITER) {
			if (opts->continue_mode == CACHE_EXT_ITERATE_HEAD)
				list_move(&node->node, &continue_list->head);
			else if (opts->continue_mode == CACHE_EXT_ITERATE_TAIL)
				list_move_tail(&node->node, &continue_list->head);

			opts->nr_folios_continue++;
			continue;
		} else if (cb_ret == CACHE_EXT_STOP_ITER) {
			ret = CACHE_EXT_DONE_ITER;
			break;
		} else if (cb_ret == CACHE_EXT_EVICT_NODE) {
			ctx->folios_to_evict[ctx->nr_folios_to_evict] = node->folio;
			ctx->nr_folios_to_evict++;

			if (opts->evict_mode == CACHE_EXT_ITERATE_HEAD)
				list_move(&node->node, &evict_list->head);
			else if (opts->evict_mode == CACHE_EXT_ITERATE_TAIL)
				list_move_tail(&node->node, &evict_list->head);

			opts->nr_folios_evict++;

			if (ctx->nr_folios_to_evict == ARRAY_SIZE(ctx->folios_to_evict)) {
				ret = CACHE_EXT_EVICT_ARRAY_FILLED;
				break;
			}
		} else {
			pr_warn("cache_ext: unknown iterate return code\n");
			break;
		}
	}

	if (opts->continue_mode == CACHE_EXT_CONTINUE_ITER &&
	    opts->evict_mode == CACHE_EXT_CONTINUE_ITER)
		read_unlock(&registry->lock);
	else
		write_unlock(&registry->lock);

	return ret;
}

static int cache_ext_list_free(struct cache_ext_list *list)
{
	struct cache_ext_list_node *node, *tmp;

	list_for_each_entry_safe(node, tmp, &list->head, node)
		list_del(&node->node);

	kfree(list);
	return 0;
}

__bpf_kfunc int bpf_cache_ext_list_add(u64 list, struct folio *folio)
{
	int ret;
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_folio(folio), list);
	if (!list_ptr) {
		trace_mm_cache_ext_list_op("add", list, -ENOENT);
		return -1;
	}

	ret = cache_ext_list_add(list_ptr, folio);
	if (ret)
		trace_mm_cache_ext_list_op("add", list, ret);
	return ret;
}

__bpf_kfunc int bpf_cache_ext_list_add_tail(u64 list, struct folio *folio)
{
	int ret;
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_folio(folio), list);
	if (!list_ptr) {
		trace_mm_cache_ext_list_op("add_tail", list, -ENOENT);
		return -1;
	}

	ret = cache_ext_list_add_tail(list_ptr, folio);
	if (ret)
		trace_mm_cache_ext_list_op("add_tail", list, ret);
	return ret;
}

__bpf_kfunc int bpf_cache_ext_list_move(u64 list, struct folio *folio, bool tail)
{
	int ret;
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(
		cache_ext_ds_registry_from_folio(folio), list);
	if (!list_ptr) {
		trace_mm_cache_ext_list_op("move", list, -ENOENT);
		return -1;
	}

	ret = cache_ext_list_move(list_ptr, folio, tail);
	if (ret)
		trace_mm_cache_ext_list_op("move", list, ret);
	return ret;
}

__bpf_kfunc int bpf_cache_ext_list_del(struct folio *folio)
{
	int ret = cache_ext_list_del(folio);

	if (ret)
		trace_mm_cache_ext_list_op("del", 0, ret);
	return ret;
}

__bpf_kfunc int bpf_cache_ext_list_iterate(
	struct mem_cgroup *memcg, u64 list,
	int(iter_fn)(int idx, struct cache_ext_list_node *node),
	struct cache_ext_eviction_ctx *ctx)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_memcg(memcg);
	struct cache_ext_list *list_ptr = cache_ext_ds_registry_get(registry, list);
	if (!list_ptr) {
		trace_mm_cache_ext_list_op("iterate", list, -ENOENT);
		return -1;
	}

	return cache_ext_list_iterate(memcg, list_ptr, (void *)iter_fn, ctx);
}

__bpf_kfunc int bpf_cache_ext_list_iterate_extended(
	struct mem_cgroup *memcg, u64 list,
	int(iter_fn)(int idx, struct cache_ext_list_node *node),
	struct cache_ext_iterate_opts *opts,
	struct cache_ext_eviction_ctx *ctx)
{
	struct cache_ext_ds_registry *registry;
	struct cache_ext_list *list_ptr;

	if (!opts)
		return -1;

	registry = cache_ext_ds_registry_from_memcg(memcg);
	list_ptr = cache_ext_ds_registry_get(registry, list);
	if (!list_ptr) {
		trace_mm_cache_ext_list_op("iterate_extended", list, -ENOENT);
		return -1;
	}

	return cache_ext_list_iterate_extended(memcg, list_ptr, (void *)iter_fn, opts, ctx);
}

#define MAX_SAMPLE_FOLIOS 2048
DEFINE_PER_CPU(struct cache_ext_list_node *, sample_folios[MAX_SAMPLE_FOLIOS]);
static DEFINE_PER_CPU(struct file *, cache_ext_prealloc_file);

static void __putback_list_nodes(struct cache_ext_list *list,
				 struct cache_ext_list_node **sample_folios_arr,
				 int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (sample_folios_arr[i]->node.next == LIST_POISON1 ||
		    sample_folios_arr[i]->node.next == LIST_POISON2 ||
		    sample_folios_arr[i]->node.prev == LIST_POISON1 ||
		    sample_folios_arr[i]->node.prev == LIST_POISON2) {
			pr_warn("cache_ext: folio removed while isolated by sampling\n");
			continue;
		}
		list_add_tail(&sample_folios_arr[i]->node, &list->head);
	}
}

static int __bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
				       s64(score_fn)(struct cache_ext_list_node *a),
				       struct sampling_options *opts,
				       struct cache_ext_eviction_ctx *ctx)
{
	int sample_size = opts->sample_size;
	int num_folios_to_sample = ctx->request_nr_folios_to_evict * sample_size;
	struct cache_ext_list_node **sample_folios_arr;
	struct cache_ext_ds_registry *registry;
	struct cache_ext_list *list_ptr;
	int sample_folios_size = 0;
	int sample_folios_idx = 0;
	int i;

	if (num_folios_to_sample > MAX_SAMPLE_FOLIOS) {
		pr_warn("cache_ext: num_folios_to_sample is too large\n");
		trace_mm_cache_ext_list_op("sample", list, -E2BIG);
		return -1;
	}

	sample_folios_arr = this_cpu_ptr(sample_folios);

	registry = cache_ext_ds_registry_from_memcg(memcg);
	list_ptr = cache_ext_ds_registry_get(registry, list);
	if (!list_ptr) {
		pr_err("cache_ext: list is NULL\n");
		trace_mm_cache_ext_list_op("sample", list, -ENOENT);
		return -1;
	}

	write_lock(&registry->lock);

	for (i = 0; i < num_folios_to_sample; i++) {
		struct cache_ext_list_node *node;

		if (list_empty(&list_ptr->head)) {
			pr_warn("cache_ext: ran out of folios to sample\n");
			__putback_list_nodes(list_ptr, sample_folios_arr, sample_folios_size);
			write_unlock(&registry->lock);
			trace_mm_cache_ext_list_op("sample", list, -ENODATA);
			return -1;
		}
		node = list_first_entry(&list_ptr->head, struct cache_ext_list_node, node);
		sample_folios_arr[i] = node;
		sample_folios_size++;
		list_del_init(&node->node);
	}

	write_unlock(&registry->lock);

	ctx->nr_folios_to_evict = 0;
	for (i = 0; i < ctx->request_nr_folios_to_evict; i++) {
		struct cache_ext_list_node *min_node = sample_folios_arr[sample_folios_idx];
		s64 min_score = score_fn(min_node);
		int j;

		sample_folios_idx++;
		for (j = 1; j < sample_size; j++) {
			struct cache_ext_list_node *curr_node =
				sample_folios_arr[sample_folios_idx];
			s64 curr_score = score_fn(curr_node);
			sample_folios_idx++;
			if (curr_score < min_score) {
				min_score = curr_score;
				min_node = curr_node;
			}
		}
		ctx->folios_to_evict[ctx->nr_folios_to_evict] = min_node->folio;
		ctx->scores[ctx->nr_folios_to_evict] = min_score;
		ctx->nr_folios_to_evict++;
	}

	write_lock(&registry->lock);
	__putback_list_nodes(list_ptr, sample_folios_arr, sample_folios_size);
	write_unlock(&registry->lock);

	return 0;
}

__bpf_kfunc int
bpf_cache_ext_list_sample(struct mem_cgroup *memcg, u64 list,
			  s64(score_fn)(struct cache_ext_list_node *a),
			  struct sampling_options *opts,
			  struct cache_ext_eviction_ctx *ctx)
{
	scoped_guard(preempt) {
		return __bpf_cache_ext_list_sample(memcg, list, score_fn, opts, ctx);
	}
	BUG();
}

void cache_ext_set_prealloc_file(struct file *file)
{
	this_cpu_write(cache_ext_prealloc_file, file);
}

void cache_ext_clear_prealloc_file(void)
{
	this_cpu_write(cache_ext_prealloc_file, NULL);
}

__bpf_kfunc int bpf_cache_ext_schedule_prealloc(u64 index, u32 nr_pages,
						bool dropbehind)
{
	struct file *file = this_cpu_read(cache_ext_prealloc_file);

	if (!file || !nr_pages)
		trace_mm_cache_ext_prealloc(file, index, nr_pages, dropbehind, -EINVAL);
	if (!file || !nr_pages)
		return -EINVAL;

	cache_ext_schedule_prealloc(file, index, nr_pages, dropbehind);
	trace_mm_cache_ext_prealloc(file, index, nr_pages, dropbehind, 0);
	return 0;
}

enum cache_ext_list_ops_type {
	KF_bpf_cache_ext_list_add,
	KF_bpf_cache_ext_list_add_tail,
	KF_bpf_cache_ext_list_del,
	KF_bpf_cache_ext_list_iterate,
	KF_bpf_cache_ext_list_sample,
	KF_bpf_cache_ext_list_move,
	KF_bpf_cache_ext_list_iterate_extended,
};

BTF_SET8_START(cache_ext_list_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add_tail)
BTF_ID_FLAGS(func, bpf_cache_ext_list_del)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate)
BTF_ID_FLAGS(func, bpf_cache_ext_list_sample)
BTF_ID_FLAGS(func, bpf_cache_ext_list_move)
BTF_ID_FLAGS(func, bpf_cache_ext_list_iterate_extended)
BTF_SET8_END(cache_ext_list_ops)

BTF_SET8_START(cache_ext_sched_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_schedule_prealloc)
BTF_SET8_END(cache_ext_sched_ops)

BTF_ID_LIST(cache_ext_list_ops_list)
BTF_ID(func, bpf_cache_ext_list_add)
BTF_ID(func, bpf_cache_ext_list_add_tail)
BTF_ID(func, bpf_cache_ext_list_del)
BTF_ID(func, bpf_cache_ext_list_iterate)
BTF_ID(func, bpf_cache_ext_list_sample)
BTF_ID(func, bpf_cache_ext_list_move)
BTF_ID(func, bpf_cache_ext_list_iterate_extended)

noinline bool cache_ext_is_callback_calling_kfunc_iterate(u32 btf_id)
{
	return (btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_iterate] ||
		btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_iterate_extended]);
}

noinline bool cache_ext_is_callback_calling_kfunc_sample(u32 btf_id)
{
	return (btf_id == cache_ext_list_ops_list[KF_bpf_cache_ext_list_sample]);
}

static const struct btf_kfunc_id_set cache_ext_kfunc_set_list_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_list_ops,
};

static const struct btf_kfunc_id_set cache_ext_kfunc_set_sched_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_sched_ops,
};

/******************************************************************************
 * DS Registry ****************************************************************
 *****************************************************************************/

void cache_ext_ds_registry_init(struct cache_ext_ds_registry *registry)
{
	hash_init(registry->ds_hash);
	rwlock_init(&registry->lock);
	registry->nr_entries = 0;
	registry->next_id = 1;
}

struct cache_ext_ds_registry *
cache_ext_ds_registry_from_memcg(struct mem_cgroup *memcg)
{
	/*
	 * cache_ext policies are scoped to a memcg, not to each NUMA node. Keep
	 * a single registry per memcg so list handles are valid for folios on
	 * any node. Valid-folio sets remain per-node for reclaim validation.
	 */
	return &memcg->nodeinfo[0]->cache_ext_ds_registry;
}

struct cache_ext_list *cache_ext_ds_registry_new_list(struct mem_cgroup *memcg)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_memcg(memcg);
	struct cache_ext_list *list = cache_ext_list_alloc();
	u64 key;

	if (!list)
		return NULL;

	write_lock(&registry->lock);
	if (registry->nr_entries >= CACHE_EXT_REGISTRY_MAX_ENTRIES) {
		write_unlock(&registry->lock);
		cache_ext_list_free(list);
		trace_mm_cache_ext_list_op("new_list", 0, -ENOSPC);
		return NULL;
	}
	list->id = registry->next_id++;
	if (!list->id)
		list->id = registry->next_id++;
	key = list->id;
	hash_add(registry->ds_hash, &list->h_node, key);
	registry->nr_entries++;
	write_unlock(&registry->lock);

	return list;
}

struct cache_ext_list *
cache_ext_ds_registry_get(struct cache_ext_ds_registry *registry, u64 list_ptr)
{
	struct cache_ext_list *cur_list;
	u64 key = list_ptr;

	read_lock(&registry->lock);
	hash_for_each_possible(registry->ds_hash, cur_list, h_node, key) {
		if (key == cur_list->id) {
			read_unlock(&registry->lock);
			return cur_list;
		}
	}
	read_unlock(&registry->lock);

	return NULL;
}

struct cache_ext_ds_registry *
cache_ext_ds_registry_from_folio(struct folio *folio)
{
	struct mem_cgroup *memcg = folio_memcg(folio);

	return cache_ext_ds_registry_from_memcg(memcg);
}

void cache_ext_ds_registry_read_lock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_folio(folio);
	read_lock(&registry->lock);
}

void cache_ext_ds_registry_read_unlock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_folio(folio);
	read_unlock(&registry->lock);
}

void cache_ext_ds_registry_write_lock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_folio(folio);
	write_lock(&registry->lock);
}

void cache_ext_ds_registry_write_unlock(struct folio *folio)
{
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_folio(folio);
	write_unlock(&registry->lock);
}

void cache_ext_ds_registry_del_all(struct mem_cgroup *memcg)
{
	int bkt;
	struct hlist_node *tmp;
	struct cache_ext_list *cur_list;
	struct cache_ext_ds_registry *registry = cache_ext_ds_registry_from_memcg(memcg);
	struct valid_folios_set *valid_folios_set = memcg_to_valid_folios_set(memcg);

	write_lock(&registry->lock);
	hash_for_each_safe(registry->ds_hash, bkt, tmp, cur_list, h_node) {
		hash_del(&cur_list->h_node);
		cache_ext_list_free(cur_list);
	}
	registry->nr_entries = 0;
	write_unlock(&registry->lock);

	valid_folios_clear_list(valid_folios_set);
}

__bpf_kfunc u64 bpf_cache_ext_ds_registry_new_list(struct mem_cgroup *memcg)
{
	struct cache_ext_list *list = cache_ext_ds_registry_new_list(memcg);

	return list ? list->id : 0;
}

BTF_SET8_START(cache_ext_registry_ops)
BTF_ID_FLAGS(func, bpf_cache_ext_ds_registry_new_list, KF_SLEEPABLE)
BTF_SET8_END(cache_ext_registry_ops)

static const struct btf_kfunc_id_set cache_ext_kfunc_set_registry_ops = {
	.owner = THIS_MODULE,
	.set = &cache_ext_registry_ops,
};

static int __init register_cache_ext_kfuncs(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&cache_ext_kfunc_set_list_ops);
	if (ret)
		return ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&cache_ext_kfunc_set_registry_ops);
	if (ret)
		return ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&cache_ext_kfunc_set_sched_ops);
	if (ret)
		return ret;

	return 0;
}

__initcall(register_cache_ext_kfuncs);
