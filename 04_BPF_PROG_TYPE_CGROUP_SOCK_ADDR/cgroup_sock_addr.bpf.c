#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Счётчик вызовов connect */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} connect4_count SEC(".maps");

SEC("cgroup/connect4")
int count_connect4(struct bpf_sock_addr *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&connect4_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 1; /* разрешить подключение */
}

char LICENSE[] SEC("license") = "GPL";
