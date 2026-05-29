#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/cgroup.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/memcontrol.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <trace/events/filemap.h>

static const struct btf_type *cache_ext_eviction_ctx_type;
static const struct btf_type *cache_ext_admission_ctx_type;

static int bpf_cache_ext_init(struct btf *btf)
{
	u32 eviction_type_id, admission_type_id;

	eviction_type_id = btf_find_by_name_kind(btf, "cache_ext_eviction_ctx",
						 BTF_KIND_STRUCT);
	if (eviction_type_id < 0) {
		pr_err("cache_ext: failed to find struct cache_ext_eviction_ctx\n");
		return -EINVAL;
	}

	admission_type_id = btf_find_by_name_kind(btf, "cache_ext_admission_ctx",
						  BTF_KIND_STRUCT);
	if (admission_type_id < 0) {
		pr_err("cache_ext: failed to find struct cache_ext_admission_ctx\n");
		return -EINVAL;
	}

	cache_ext_eviction_ctx_type = btf_type_by_id(btf, eviction_type_id);
	cache_ext_admission_ctx_type = btf_type_by_id(btf, admission_type_id);
	return 0;
}

static const struct bpf_func_proto *
bpf_cache_ext_get_func_proto(enum bpf_func_id func_id,
			     const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_cache_ext_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_cache_ext_btf_struct_access(struct bpf_verifier_log *log,
					   const struct bpf_reg_state *reg,
					   int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == cache_ext_eviction_ctx_type) {
		if (off + size > sizeof(struct cache_ext_eviction_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	} else if (t == cache_ext_admission_ctx_type) {
		if (off + size > sizeof(struct cache_ext_admission_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	}

	return -EACCES;
}

static int bpf_cache_ext_reg(void *kdata, struct bpf_link *link)
{
	struct cache_ext_ops *ops = kdata;
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
	int ret;

	if (!link) {
		pr_err("cache_ext: link is NULL\n");
		return -EINVAL;
	}

	cgrp = bpf_cache_ext_link_cgroup(link);
	if (!cgrp) {
		pr_err("cache_ext: cgroup is NULL\n");
		return -EINVAL;
	}

	memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
	if (!memcg) {
		pr_err("cache_ext: failed to get memcg for registration\n");
		return -EINVAL;
	}

	ret = cache_ext_memcg_init(memcg);
	if (ret) {
		trace_mm_cache_ext_attach(memcg, ret);
		return ret;
	}

	if (ops->init) {
		ret = ops->init(memcg);
		if (ret) {
			pr_err("cache_ext: init failed (%d)\n", ret);
			cache_ext_memcg_exit(memcg);
			trace_mm_cache_ext_attach(memcg, ret);
			return ret;
		}
	}

	trace_mm_cache_ext_attach(memcg, 0);
	return 0;
}

static void bpf_cache_ext_unreg(void *kdata, struct bpf_link *link)
{
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;

	(void)kdata;

	if (!link)
		return;

	cgrp = bpf_cache_ext_link_cgroup(link);
	if (!cgrp)
		return;

	memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
	if (!memcg)
		return;

	cache_ext_memcg_exit(memcg);
	trace_mm_cache_ext_detach(memcg);
}

static int bpf_cache_ext_init_member(const struct btf_type *t,
				     const struct btf_member *member,
				     void *kdata, const void *udata)
{
	return 0;
}

static int bpf_cache_ext_check_member(const struct btf_type *t,
				      const struct btf_member *member,
				      const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_cache_ext_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_cache_ext_verifier_ops = {
	.get_func_proto = bpf_cache_ext_get_func_proto,
	.is_valid_access = bpf_cache_ext_is_valid_access,
	.btf_struct_access = bpf_cache_ext_btf_struct_access,
};

struct bpf_struct_ops bpf_cache_ext_ops = {
	.verifier_ops = &bpf_cache_ext_verifier_ops,
	.init = bpf_cache_ext_init,
	.reg = bpf_cache_ext_reg,
	.unreg = bpf_cache_ext_unreg,
	.init_member = bpf_cache_ext_init_member,
	.check_member = bpf_cache_ext_check_member,
	.validate = bpf_cache_ext_validate,
	.name = "cache_ext_ops",
	.owner = THIS_MODULE,
};

static int __init cache_ext_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_cache_ext_ops, cache_ext_ops);
}
late_initcall(cache_ext_struct_ops_init);
