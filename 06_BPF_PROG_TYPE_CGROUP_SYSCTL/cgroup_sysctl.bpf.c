#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Счётчик обращений к sysctl */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sysctl_count SEC(".maps");

SEC("cgroup/sysctl")
int count_sysctl(struct bpf_sysctl *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&sysctl_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 1; /* разрешить операцию */
}

char LICENSE[] SEC("license") = "GPL";
