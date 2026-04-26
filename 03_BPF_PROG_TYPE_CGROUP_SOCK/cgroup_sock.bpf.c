#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct sock_block_rule {
    __u32 enabled;
    __u32 family;
    __u32 type;
    __u32 protocol;
};

struct sock_metrics {
    __u64 total_events;
    __u64 allowed_events;
    __u64 blocked_events;
    __u32 last_family;
    __u32 last_type;
    __u32 last_protocol;
    __u32 last_decision;
    __u64 last_ts_ns;
};

/* Счётчик создания сокетов (обратная совместимость со старой проверкой) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sock_create_count SEC(".maps");

/* Правило блокировки сокетов: 0 в полях family/type/protocol = wildcard */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sock_block_rule);
} sock_block_config SEC(".maps");

/* Метрики в реальном времени */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sock_metrics);
} sock_rt_metrics SEC(".maps");

SEC("cgroup/sock_create")
int count_sock_create(struct bpf_sock *sk)
{
    __u32 key = 0;
    __u64 *count;
    struct sock_block_rule *rule;
    struct sock_metrics *metrics;
    __u32 family = sk->family;
    __u32 type = sk->type;
    __u32 protocol = sk->protocol;
    int should_block = 0;

    count = bpf_map_lookup_elem(&sock_create_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    rule = bpf_map_lookup_elem(&sock_block_config, &key);
    if (rule && rule->enabled) {
        int family_match = (rule->family == 0 || rule->family == family);
        int type_match = (rule->type == 0 || rule->type == type);
        int proto_match = (rule->protocol == 0 || rule->protocol == protocol);

        if (family_match && type_match && proto_match)
            should_block = 1;
    }

    metrics = bpf_map_lookup_elem(&sock_rt_metrics, &key);
    if (metrics) {
        __sync_fetch_and_add(&metrics->total_events, 1);
        if (should_block)
            __sync_fetch_and_add(&metrics->blocked_events, 1);
        else
            __sync_fetch_and_add(&metrics->allowed_events, 1);

        metrics->last_family = family;
        metrics->last_type = type;
        metrics->last_protocol = protocol;
        metrics->last_decision = should_block ? 0 : 1;
        metrics->last_ts_ns = bpf_ktime_get_ns();
    }

    return should_block ? 0 : 1;
}

char LICENSE[] SEC("license") = "GPL";
