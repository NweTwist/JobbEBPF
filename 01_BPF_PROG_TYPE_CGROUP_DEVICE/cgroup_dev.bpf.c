#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Счётчик обращений к устройствам */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dev_access_count SEC(".maps");

SEC("cgroup/dev")
int cgroup_dev_allow(struct bpf_cgroup_dev_ctx *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&dev_access_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 1; /* разрешить доступ */
}

char LICENSE[] SEC("license") = "GPL";
