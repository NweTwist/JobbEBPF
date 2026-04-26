#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} skb_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} sock_map SEC(".maps");

SEC("sk_skb/stream_verdict")
int sk_skb_verdict(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&skb_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
