#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Карта для хранения счётчика вызовов openat */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} openat_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(void *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&openat_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
