#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

/* Счётчик вызовов cong_avoid */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ca_count SEC(".maps");

SEC("struct_ops")
void BPF_PROG(bpf_ca_init, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    tp->snd_cwnd = 10;
}

SEC("struct_ops")
void BPF_PROG(bpf_ca_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&ca_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    /* Простое увеличение окна на 1 MSS за RTT */
    tp->snd_cwnd += 1;
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_ca_ssthresh, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    return tp->snd_cwnd >> 1;
}

SEC("struct_ops")
__u32 BPF_PROG(bpf_ca_undo_cwnd, struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    return tp->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops bpf_cc = {
    .init       = (void *)bpf_ca_init,
    .cong_avoid = (void *)bpf_ca_cong_avoid,
    .ssthresh   = (void *)bpf_ca_ssthresh,
    .undo_cwnd  = (void *)bpf_ca_undo_cwnd,
    .name       = "bpf_cc",
};

char LICENSE[] SEC("license") = "GPL";
