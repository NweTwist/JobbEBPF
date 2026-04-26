#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ext_count SEC(".maps");

SEC("freplace/count_and_pass")
int ext_count_and_pass(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    count = bpf_map_lookup_elem(&ext_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
