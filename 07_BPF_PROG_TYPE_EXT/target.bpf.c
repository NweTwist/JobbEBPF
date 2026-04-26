#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

/* global-функция, доступная для замены через EXT */
__attribute__((noinline))
int count_and_pass(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    count = bpf_map_lookup_elem(&counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return XDP_PASS;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    return count_and_pass(ctx);
}

char LICENSE[] SEC("license") = "GPL";
