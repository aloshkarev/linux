// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

static volatile sig_atomic_t exiting;

static void handle_signal(int sig)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	const char *object_path, *cgroup_path, *map_name;
	struct bpf_object *obj = NULL;
	struct bpf_link *link = NULL;
	struct bpf_map *map;
	int cgroup_fd = -1;
	int err = 0;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <policy.bpf.o> <cgroup-path> <struct-ops-map>\n",
			argv[0]);
		return 1;
	}

	object_path = argv[1];
	cgroup_path = argv[2];
	map_name = argv[3];

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
	if (cgroup_fd < 0) {
		perror("open cgroup");
		return 1;
	}

	obj = bpf_object__open_file(object_path, NULL);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "failed to open BPF object: %s\n", strerror(errno));
		goto out;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto out;
	}

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		err = -ENOENT;
		fprintf(stderr, "struct_ops map '%s' not found\n", map_name);
		goto out;
	}

	link = bpf_map__attach_cache_ext_ops(map, cgroup_fd);
	err = libbpf_get_error(link);
	if (err) {
		link = NULL;
		fprintf(stderr, "failed to attach cache_ext ops: %d\n", err);
		goto out;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);
	printf("cache_ext policy attached; press Ctrl-C to detach\n");
	while (!exiting)
		pause();

out:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	return err ? 1 : 0;
}
