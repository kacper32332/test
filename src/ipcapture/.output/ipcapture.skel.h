/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __IPCAPTURE_BPF_SKEL_H__
#define __IPCAPTURE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct ipcapture_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rb;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *xdp_pass;
	} progs;
	struct {
		struct bpf_link *xdp_pass;
	} links;

#ifdef __cplusplus
	static inline struct ipcapture_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct ipcapture_bpf *open_and_load();
	static inline int load(struct ipcapture_bpf *skel);
	static inline int attach(struct ipcapture_bpf *skel);
	static inline void detach(struct ipcapture_bpf *skel);
	static inline void destroy(struct ipcapture_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
ipcapture_bpf__destroy(struct ipcapture_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
ipcapture_bpf__create_skeleton(struct ipcapture_bpf *obj);

static inline struct ipcapture_bpf *
ipcapture_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct ipcapture_bpf *obj;
	int err;

	obj = (struct ipcapture_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = ipcapture_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	ipcapture_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct ipcapture_bpf *
ipcapture_bpf__open(void)
{
	return ipcapture_bpf__open_opts(NULL);
}

static inline int
ipcapture_bpf__load(struct ipcapture_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct ipcapture_bpf *
ipcapture_bpf__open_and_load(void)
{
	struct ipcapture_bpf *obj;
	int err;

	obj = ipcapture_bpf__open();
	if (!obj)
		return NULL;
	err = ipcapture_bpf__load(obj);
	if (err) {
		ipcapture_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
ipcapture_bpf__attach(struct ipcapture_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
ipcapture_bpf__detach(struct ipcapture_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *ipcapture_bpf__elf_bytes(size_t *sz);

static inline int
ipcapture_bpf__create_skeleton(struct ipcapture_bpf *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "ipcapture_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "rb";
	map->map = &obj->maps.rb;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "ipcaptur.rodata";
	map->map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "xdp_pass";
	s->progs[0].prog = &obj->progs.xdp_pass;
	s->progs[0].link = &obj->links.xdp_pass;

	s->data = ipcapture_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *ipcapture_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xe0\x0b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0a\0\
\x01\0\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x78\x64\
\x70\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x69\x70\x63\x61\x70\x74\x75\x72\x65\x2e\x62\x70\x66\x2e\x63\0\x4c\
\x42\x42\x30\x5f\x35\0\x78\x64\x70\x5f\x70\x61\x73\x73\x2e\x5f\x5f\x5f\x5f\x66\
\x6d\x74\0\x78\x64\x70\x5f\x70\x61\x73\x73\0\x72\x62\0\x5f\x5f\x6c\x69\x63\x65\
\x6e\x73\x65\0\x2e\x72\x65\x6c\x78\x64\x70\0\x2e\x42\x54\x46\0\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2b\0\0\0\
\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x3b\0\0\0\0\0\x03\0\xf0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x42\
\0\0\0\x01\0\x05\0\0\0\0\0\0\0\0\0\x21\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x53\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\x5c\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x5f\0\0\0\x11\0\
\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x61\x12\x04\0\0\0\0\0\x61\x13\0\0\0\0\
\0\0\xbf\x31\0\0\0\0\0\0\x07\x01\0\0\x0e\0\0\0\x2d\x21\x19\0\0\0\0\0\x69\x34\
\x0c\0\0\0\0\0\x55\x04\x17\0\x08\0\0\0\x07\x03\0\0\x22\0\0\0\x2d\x23\x15\0\0\0\
\0\0\x61\x16\x10\0\0\0\0\0\x61\x17\x0c\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xb7\x02\0\0\x08\0\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x83\0\0\0\x15\0\x0d\
\0\0\0\0\0\x63\x60\x04\0\0\0\0\0\x63\x70\0\0\0\0\0\0\xbf\x01\0\0\0\0\0\0\xb7\
\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xdc\x07\0\0\x20\0\0\0\xdc\x06\0\0\x20\0\0\
\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x21\0\0\0\xbf\x73\0\0\0\0\0\
\0\xbf\x64\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\x02\0\0\0\x95\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x43\x61\x70\x74\x75\x72\x65\x64\x20\x73\x72\
\x63\x5f\x69\x70\x3a\x20\x25\x78\x2c\x20\x64\x65\x73\x74\x5f\x69\x70\x3a\x20\
\x25\x78\0\x47\x50\x4c\0\0\0\0\x58\0\0\0\0\0\0\0\x01\0\0\0\x07\0\0\0\xc0\0\0\0\
\0\0\0\0\x01\0\0\0\x05\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x5c\x03\0\0\x5c\
\x03\0\0\xf7\x03\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x02\0\0\0\x04\0\0\0\0\0\0\x01\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\
\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\x2d\0\0\0\x06\0\0\x04\x18\0\0\0\x34\0\0\
\0\x0b\0\0\0\0\0\0\0\x39\0\0\0\x0b\0\0\0\x20\0\0\0\x42\0\0\0\x0b\0\0\0\x40\0\0\
\0\x4c\0\0\0\x0b\0\0\0\x60\0\0\0\x5c\0\0\0\x0b\0\0\0\x80\0\0\0\x6b\0\0\0\x0b\0\
\0\0\xa0\0\0\0\x7a\0\0\0\0\0\0\x08\x0c\0\0\0\x80\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x8d\0\0\0\x09\0\0\0\x91\0\0\0\x01\0\0\x0c\
\x0d\0\0\0\x9a\0\0\0\x03\0\0\x04\x0e\0\0\0\xa1\0\0\0\x11\0\0\0\0\0\0\0\xa8\0\0\
\0\x11\0\0\0\x30\0\0\0\xb1\0\0\0\x12\0\0\0\x60\0\0\0\xb9\0\0\0\0\0\0\x01\x01\0\
\0\0\x08\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x10\0\0\0\x04\0\0\0\x06\0\0\0\xc7\0\0\
\0\0\0\0\x08\x13\0\0\0\xce\0\0\0\0\0\0\x08\x14\0\0\0\xd4\0\0\0\0\0\0\x01\x02\0\
\0\0\x10\0\0\0\xe3\0\0\0\x0a\0\0\x84\x14\0\0\0\xe9\0\0\0\x16\0\0\0\0\0\0\x04\
\xed\0\0\0\x16\0\0\0\x04\0\0\x04\xf5\0\0\0\x16\0\0\0\x08\0\0\0\xf9\0\0\0\x12\0\
\0\0\x10\0\0\0\x01\x01\0\0\x12\0\0\0\x20\0\0\0\x04\x01\0\0\x12\0\0\0\x30\0\0\0\
\x0d\x01\0\0\x16\0\0\0\x40\0\0\0\x11\x01\0\0\x16\0\0\0\x48\0\0\0\x1a\x01\0\0\
\x17\0\0\0\x50\0\0\0\0\0\0\0\x18\0\0\0\x60\0\0\0\x20\x01\0\0\0\0\0\x08\x10\0\0\
\0\x25\x01\0\0\0\0\0\x08\x13\0\0\0\0\0\0\0\x02\0\0\x05\x08\0\0\0\0\0\0\0\x19\0\
\0\0\0\0\0\0\x2d\x01\0\0\x19\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\x04\x08\0\0\0\x33\
\x01\0\0\x1a\0\0\0\0\0\0\0\x39\x01\0\0\x1a\0\0\0\x20\0\0\0\x3f\x01\0\0\0\0\0\
\x08\x0b\0\0\0\0\0\0\0\0\0\0\x0a\x1c\0\0\0\x46\x01\0\0\0\0\0\x01\x01\0\0\0\x08\
\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x1b\0\0\0\x04\0\0\0\x21\0\0\0\x4b\x01\0\0\0\
\0\0\x0e\x1d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x1c\0\0\0\x04\0\0\0\x04\0\
\0\0\x5c\x01\0\0\0\0\0\x0e\x1f\0\0\0\x01\0\0\0\xdd\x03\0\0\x01\0\0\x0f\x10\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\xe3\x03\0\0\x01\0\0\x0f\x21\0\0\0\x1e\0\0\0\0\0\
\0\0\x21\0\0\0\xeb\x03\0\0\x01\0\0\x0f\x04\0\0\0\x20\0\0\0\0\0\0\0\x04\0\0\0\0\
\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\
\x45\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\
\x72\x62\0\x78\x64\x70\x5f\x6d\x64\0\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\x65\
\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x69\x6e\x67\x72\x65\x73\x73\
\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\x5f\x71\x75\x65\x75\x65\x5f\x69\x6e\
\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x5f\
\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\x74\
\x78\0\x78\x64\x70\x5f\x70\x61\x73\x73\0\x65\x74\x68\x68\x64\x72\0\x68\x5f\x64\
\x65\x73\x74\0\x68\x5f\x73\x6f\x75\x72\x63\x65\0\x68\x5f\x70\x72\x6f\x74\x6f\0\
\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x5f\x5f\x62\x65\x31\x36\
\0\x5f\x5f\x75\x31\x36\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\
\x74\0\x69\x70\x68\x64\x72\0\x69\x68\x6c\0\x76\x65\x72\x73\x69\x6f\x6e\0\x74\
\x6f\x73\0\x74\x6f\x74\x5f\x6c\x65\x6e\0\x69\x64\0\x66\x72\x61\x67\x5f\x6f\x66\
\x66\0\x74\x74\x6c\0\x70\x72\x6f\x74\x6f\x63\x6f\x6c\0\x63\x68\x65\x63\x6b\0\
\x5f\x5f\x75\x38\0\x5f\x5f\x73\x75\x6d\x31\x36\0\x61\x64\x64\x72\x73\0\x73\x61\
\x64\x64\x72\0\x64\x61\x64\x64\x72\0\x5f\x5f\x62\x65\x33\x32\0\x63\x68\x61\x72\
\0\x78\x64\x70\x5f\x70\x61\x73\x73\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x5f\x5f\
\x6c\x69\x63\x65\x6e\x73\x65\0\x2f\x68\x6f\x6d\x65\x2f\x6b\x61\x6c\x69\x2f\x74\
\x65\x73\x74\x74\x65\x73\x74\x2f\x73\x72\x63\x2f\x69\x70\x63\x61\x70\x74\x75\
\x72\x65\x2f\x69\x70\x63\x61\x70\x74\x75\x72\x65\x2e\x62\x70\x66\x2e\x63\0\x20\
\x20\x20\x20\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\x5f\x65\x6e\x64\x20\x3d\
\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x28\x6c\x6f\x6e\x67\x29\x63\x74\x78\x2d\
\x3e\x64\x61\x74\x61\x5f\x65\x6e\x64\x3b\0\x20\x20\x20\x20\x76\x6f\x69\x64\x20\
\x2a\x64\x61\x74\x61\x20\x3d\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x28\x6c\x6f\
\x6e\x67\x29\x63\x74\x78\x2d\x3e\x64\x61\x74\x61\x3b\0\x20\x20\x20\x20\x69\x66\
\x20\x28\x28\x76\x6f\x69\x64\x20\x2a\x29\x28\x65\x74\x68\x20\x2b\x20\x31\x29\
\x20\x3e\x20\x64\x61\x74\x61\x5f\x65\x6e\x64\x29\0\x20\x20\x20\x20\x69\x66\x20\
\x28\x62\x70\x66\x5f\x6e\x74\x6f\x68\x73\x28\x65\x74\x68\x2d\x3e\x68\x5f\x70\
\x72\x6f\x74\x6f\x29\x20\x21\x3d\x20\x45\x54\x48\x5f\x50\x5f\x49\x50\x29\0\x20\
\x20\x20\x20\x69\x66\x20\x28\x21\x69\x73\x5f\x69\x70\x76\x34\x28\x65\x74\x68\
\x2c\x20\x64\x61\x74\x61\x5f\x65\x6e\x64\x29\x29\x20\x7b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x2e\x64\x65\x73\x74\x5f\x69\x70\x20\x3d\x20\x69\x70\x2d\x3e\x64\
\x61\x64\x64\x72\0\x20\x20\x20\x20\x20\x20\x20\x20\x2e\x73\x72\x63\x5f\x69\x70\
\x20\x3d\x20\x69\x70\x2d\x3e\x73\x61\x64\x64\x72\x2c\0\x20\x20\x20\x20\x76\x6f\
\x69\x64\x20\x2a\x72\x69\x6e\x67\x62\x75\x66\x5f\x73\x70\x61\x63\x65\x20\x3d\
\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\x76\
\x65\x28\x26\x72\x62\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x69\x6e\x66\x6f\x29\
\x2c\x20\x30\x29\x3b\0\x20\x20\x20\x20\x69\x66\x20\x28\x21\x72\x69\x6e\x67\x62\
\x75\x66\x5f\x73\x70\x61\x63\x65\x29\x20\x7b\0\x20\x20\x20\x20\x2a\x28\x73\x74\
\x72\x75\x63\x74\x20\x69\x70\x5f\x69\x6e\x66\x6f\x20\x2a\x29\x72\x69\x6e\x67\
\x62\x75\x66\x5f\x73\x70\x61\x63\x65\x20\x3d\x20\x69\x6e\x66\x6f\x3b\0\x20\x20\
\x20\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x73\x75\x62\x6d\x69\
\x74\x28\x72\x69\x6e\x67\x62\x75\x66\x5f\x73\x70\x61\x63\x65\x2c\x20\x30\x29\
\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x43\x61\
\x70\x74\x75\x72\x65\x64\x20\x73\x72\x63\x5f\x69\x70\x3a\x20\x25\x78\x2c\x20\
\x64\x65\x73\x74\x5f\x69\x70\x3a\x20\x25\x78\x22\x2c\x20\x62\x70\x66\x5f\x6e\
\x74\x6f\x68\x6c\x28\x69\x6e\x66\x6f\x2e\x73\x72\x63\x5f\x69\x70\x29\x2c\x20\
\x62\x70\x66\x5f\x6e\x74\x6f\x68\x6c\x28\x69\x6e\x66\x6f\x2e\x64\x65\x73\x74\
\x5f\x69\x70\x29\x29\x3b\0\x7d\0\x30\x3a\x31\0\x30\x3a\x30\0\x30\x3a\x32\0\x30\
\x3a\x39\x3a\x30\x3a\x31\0\x30\x3a\x39\x3a\x30\x3a\x30\0\x2e\x6d\x61\x70\x73\0\
\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x78\x64\x70\0\0\0\
\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\xec\0\0\0\0\x01\0\0\
\x5c\0\0\0\x08\0\0\0\xf3\x03\0\0\x01\0\0\0\0\0\0\0\x0e\0\0\0\x10\0\0\0\xf3\x03\
\0\0\x0e\0\0\0\0\0\0\0\x66\x01\0\0\x98\x01\0\0\x29\x98\0\0\x08\0\0\0\x66\x01\0\
\0\xca\x01\0\0\x25\x94\0\0\x10\0\0\0\x66\x01\0\0\xf4\x01\0\0\x16\x5c\0\0\x20\0\
\0\0\x66\x01\0\0\xf4\x01\0\0\x09\x5c\0\0\x28\0\0\0\x66\x01\0\0\x1a\x02\0\0\x09\
\x6c\0\0\x30\0\0\0\x66\x01\0\0\x47\x02\0\0\x09\xb0\0\0\x48\0\0\0\x66\x01\0\0\
\x6a\x02\0\0\x18\xec\0\0\x50\0\0\0\x66\x01\0\0\x87\x02\0\0\x17\xe8\0\0\x58\0\0\
\0\x66\x01\0\0\xa4\x02\0\0\x1b\xfc\0\0\x80\0\0\0\x66\x01\0\0\xe9\x02\0\0\x09\0\
\x01\0\x88\0\0\0\x66\x01\0\0\x03\x03\0\0\x28\x14\x01\0\x98\0\0\0\x66\x01\0\0\
\x30\x03\0\0\x05\x20\x01\0\xb0\0\0\0\x66\x01\0\0\x5a\x03\0\0\x05\x2c\x01\0\xf0\
\0\0\0\x66\x01\0\0\xbf\x03\0\0\x01\x38\x01\0\x10\0\0\0\xf3\x03\0\0\x05\0\0\0\0\
\0\0\0\x0a\0\0\0\xc1\x03\0\0\0\0\0\0\x08\0\0\0\x0a\0\0\0\xc5\x03\0\0\0\0\0\0\
\x28\0\0\0\x0f\0\0\0\xc9\x03\0\0\0\0\0\0\x48\0\0\0\x15\0\0\0\xcd\x03\0\0\0\0\0\
\0\x50\0\0\0\x15\0\0\0\xd5\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x40\0\0\0\0\0\0\0\x7f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x09\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\
\xd8\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x11\0\
\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x01\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x02\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1b\0\0\0\x01\0\0\0\x02\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xa8\x02\0\0\0\0\0\0\x21\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x23\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xc9\x02\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x69\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\x02\
\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\
\0\0\0\0\x71\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x02\0\0\0\0\0\
\0\x6b\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x76\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x0a\0\0\0\0\0\0\x7c\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct ipcapture_bpf *ipcapture_bpf::open(const struct bpf_object_open_opts *opts) { return ipcapture_bpf__open_opts(opts); }
struct ipcapture_bpf *ipcapture_bpf::open_and_load() { return ipcapture_bpf__open_and_load(); }
int ipcapture_bpf::load(struct ipcapture_bpf *skel) { return ipcapture_bpf__load(skel); }
int ipcapture_bpf::attach(struct ipcapture_bpf *skel) { return ipcapture_bpf__attach(skel); }
void ipcapture_bpf::detach(struct ipcapture_bpf *skel) { ipcapture_bpf__detach(skel); }
void ipcapture_bpf::destroy(struct ipcapture_bpf *skel) { ipcapture_bpf__destroy(skel); }
const void *ipcapture_bpf::elf_bytes(size_t *sz) { return ipcapture_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
ipcapture_bpf__assert(struct ipcapture_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __IPCAPTURE_BPF_SKEL_H__ */
