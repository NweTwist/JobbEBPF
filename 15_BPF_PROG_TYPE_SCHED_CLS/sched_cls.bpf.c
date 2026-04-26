#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cls_count SEC(".maps");

SEC("classifier")
int tc_cls_count(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&cls_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0; /* TC_ACT_OK */
}

char LICENSE[] SEC("license") = "GPL";
