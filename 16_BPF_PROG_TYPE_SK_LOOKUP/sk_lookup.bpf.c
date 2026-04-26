#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lookup_count SEC(".maps");

SEC("sk_lookup")
int count_sk_lookup(struct bpf_sk_lookup *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&lookup_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
