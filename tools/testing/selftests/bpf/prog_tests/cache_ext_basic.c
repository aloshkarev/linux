// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <cgroup_helpers.h>

#include "cache_ext_basic.skel.h"
#include "cache_ext_fail_bad_folio_arg.skel.h"
#include "cache_ext_fail_sleepable.skel.h"

static bool cache_ext_skip_err(int err)
{
	return err == -EOPNOTSUPP || err == -EINVAL || err == -ENOENT;
}

static void cache_ext_basic_attach(void)
{
	struct cache_ext_basic *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	int err;

	cgroup_fd = test__join_cgroup("/cache_ext_basic");
	if (!ASSERT_OK_FD(cgroup_fd, "join cgroup"))
		return;

	skel = cache_ext_basic__open_and_load();
	if (!skel) {
		if (errno == EOPNOTSUPP || errno == ENOENT) {
			test__skip();
			goto out;
		}
		ASSERT_OK_PTR(skel, "open_and_load");
		goto out;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.basic_ops, cgroup_fd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		if (cache_ext_skip_err(err)) {
			test__skip();
			goto out;
		}
		ASSERT_OK(err, "attach cache_ext_ops");
		goto out;
	}

	ASSERT_EQ(skel->bss->init_called, 1, "init_called");
	ASSERT_NEQ(skel->bss->list_handle, 0, "list_handle");
	ASSERT_EQ(skel->bss->invalid_iter_ret, -1, "invalid_iter_ret");
	ASSERT_EQ(skel->bss->invalid_sample_ret, -1, "invalid_sample_ret");
	ASSERT_EQ(skel->bss->oversized_sample_ret, -1, "oversized_sample_ret");

out:
	bpf_link__destroy(link);
	cache_ext_basic__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void cache_ext_repeated_attach_detach(void)
{
	struct cache_ext_basic *skel = NULL;
	int cgroup_fd = -1;
	int i;

	cgroup_fd = test__join_cgroup("/cache_ext_repeated_attach_detach");
	if (!ASSERT_OK_FD(cgroup_fd, "join cgroup"))
		return;

	skel = cache_ext_basic__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	for (i = 0; i < 4; i++) {
		struct bpf_link *link;
		int err;

		link = bpf_map__attach_cache_ext_ops(skel->maps.basic_ops,
						     cgroup_fd);
		err = libbpf_get_error(link);
		if (err) {
			link = NULL;
			if (cache_ext_skip_err(err)) {
				test__skip();
				goto out;
			}
			ASSERT_OK(err, "attach cache_ext_ops");
			goto out;
		}
		bpf_link__destroy(link);
	}

	ASSERT_EQ(skel->bss->init_called, 4, "repeated_init_called");

out:
	cache_ext_basic__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void cache_ext_init_failure_cleanup(void)
{
	struct cache_ext_basic *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	int err;

	cgroup_fd = test__join_cgroup("/cache_ext_init_failure_cleanup");
	if (!ASSERT_OK_FD(cgroup_fd, "join cgroup"))
		return;

	skel = cache_ext_basic__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cache_ext_ops(skel->maps.init_fail_ops,
					     cgroup_fd);
	err = libbpf_get_error(link);
	if (!err) {
		bpf_link__destroy(link);
		ASSERT_ERR(0, "init_fail_attach_should_fail");
		goto out;
	}
	link = NULL;
	if (cache_ext_skip_err(err))
		test__skip();
	else
		ASSERT_EQ(err, -EINVAL, "init_fail_attach_err");

out:
	cache_ext_basic__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void cache_ext_prealloc_reject_outside_admission(void)
{
	struct cache_ext_basic *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	int err;

	cgroup_fd = test__join_cgroup("/cache_ext_prealloc_reject");
	if (!ASSERT_OK_FD(cgroup_fd, "join cgroup"))
		return;

	skel = cache_ext_basic__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cache_ext_ops(skel->maps.prealloc_reject_init_ops,
					     cgroup_fd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		if (cache_ext_skip_err(err)) {
			test__skip();
			goto out;
		}
		ASSERT_OK(err, "attach prealloc_reject_init_ops");
		goto out;
	}

	ASSERT_EQ(skel->bss->prealloc_reject_ret, -EINVAL,
		  "prealloc_rejected_outside_admission");

out:
	bpf_link__destroy(link);
	cache_ext_basic__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void cache_ext_verifier_negative_sleepable(void)
{
	struct cache_ext_fail_sleepable *skel;
	int err;

	skel = cache_ext_fail_sleepable__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	err = cache_ext_fail_sleepable__load(skel);
	ASSERT_ERR(err, "sleepable_kfunc_in_nonsleepable_callback");

	cache_ext_fail_sleepable__destroy(skel);
}

static void cache_ext_verifier_negative_bad_folio_arg(void)
{
	struct cache_ext_fail_bad_folio_arg *skel;
	int err;

	skel = cache_ext_fail_bad_folio_arg__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	err = cache_ext_fail_bad_folio_arg__load(skel);
	ASSERT_ERR(err, "bad_folio_arg_for_list_kfunc");

	cache_ext_fail_bad_folio_arg__destroy(skel);
}

void test_cache_ext_basic(void)
{
	if (test__start_subtest("attach"))
		cache_ext_basic_attach();
	if (test__start_subtest("repeated_attach_detach"))
		cache_ext_repeated_attach_detach();
	if (test__start_subtest("init_failure_cleanup"))
		cache_ext_init_failure_cleanup();
	if (test__start_subtest("prealloc_reject_outside_admission"))
		cache_ext_prealloc_reject_outside_admission();
	if (test__start_subtest("verifier_negative_sleepable"))
		cache_ext_verifier_negative_sleepable();
	if (test__start_subtest("verifier_negative_bad_folio_arg"))
		cache_ext_verifier_negative_bad_folio_arg();
}
