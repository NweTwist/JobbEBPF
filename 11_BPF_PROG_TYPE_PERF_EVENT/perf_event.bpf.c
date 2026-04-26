#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Счётчик событий perf */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} perf_count SEC(".maps");

SEC("perf_event")
int count_perf_event(struct bpf_perf_event_data *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&perf_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
