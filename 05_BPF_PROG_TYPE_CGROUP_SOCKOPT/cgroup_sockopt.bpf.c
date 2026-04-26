#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Счётчик вызовов setsockopt */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} setsockopt_count SEC(".maps");

SEC("cgroup/setsockopt")
int count_setsockopt(struct bpf_sockopt *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&setsockopt_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 1; /* разрешить операцию */
}

char LICENSE[] SEC("license") = "GPL";
