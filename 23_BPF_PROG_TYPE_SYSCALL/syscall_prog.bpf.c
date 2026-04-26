#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} syscall_run_count SEC(".maps");

SEC("syscall")
int bpf_syscall_prog(void *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&syscall_run_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
