#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef BPF_DEVCG_DEV_BLOCK
#define BPF_DEVCG_DEV_BLOCK 1
#endif

struct dev_key {
    __u32 major;
    __u32 minor;
};

/* Счётчик обращений к устройствам */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dev_access_count SEC(".maps");

/* Набор заблокированных устройств (major/minor) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct dev_key);
    __type(value, __u8);
} blocked_devices SEC(".maps");

SEC("cgroup/dev")
int cgroup_dev_filter(struct bpf_cgroup_dev_ctx *ctx)
{
    __u32 key = 0;
    __u64 *count;
    struct dev_key dev = {
        .major = ctx->major,
        .minor = ctx->minor,
    };
    __u8 *blocked;
    __u32 dev_type = ctx->access_type >> 16;

    count = bpf_map_lookup_elem(&dev_access_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    if (dev_type == BPF_DEVCG_DEV_BLOCK) {
        blocked = bpf_map_lookup_elem(&blocked_devices, &dev);
        if (blocked)
            return 0; /* запретить доступ */
    }

    return 1; /* разрешить доступ */
}

char LICENSE[] SEC("license") = "GPL";
