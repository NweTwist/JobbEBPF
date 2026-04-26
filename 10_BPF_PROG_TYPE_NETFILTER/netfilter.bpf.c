#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct bpf_nf_ctx;

/* Счётчик пакетов netfilter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} nf_count SEC(".maps");

SEC("netfilter")
int nf_count_pkts(struct bpf_nf_ctx *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&nf_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 1; /* NF_ACCEPT */
}

char LICENSE[] SEC("license") = "GPL";
