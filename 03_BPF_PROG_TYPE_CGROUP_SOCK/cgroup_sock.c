#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_sock.skel.h"

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

static volatile sig_atomic_t g_stop;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s [--realtime] [--interval SEC] [--block FAMILY TYPE PROTOCOL]\n", prog);
    printf("  %s --once\n\n", prog);
    printf("Examples:\n");
    printf("  %s --realtime\n", prog);
    printf("  %s --block 2 1 6 --realtime\n", prog);
    printf("  %s --once\n", prog);
}

static int run_socket_probe(int family, int type, int protocol, int expect_block)
{
    int s = socket(family, type, protocol);
    if (s >= 0) {
        close(s);
        return expect_block ? -1 : 0;
    }

    if (expect_block && (errno == EACCES || errno == EPERM))
        return 0;

    return -1;
}

int main(int argc, char **argv)
{
    struct cgroup_sock_bpf *skel;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    __u32 key = 0;
    __u64 val = 0;
    struct sock_metrics metrics = {};
    struct sock_metrics prev_metrics = {};
    struct sock_block_rule rule = {};
    int realtime_mode = 1;
    int interval_sec = 1;
    int err;
    int i;

    for (i = 1; i < (int)argc; i++) {
        if (strcmp(argv[i], "--once") == 0) {
            realtime_mode = 0;
        } else if (strcmp(argv[i], "--realtime") == 0) {
            realtime_mode = 1;
        } else if (strcmp(argv[i], "--interval") == 0) {
            if (i + 1 >= (int)argc) {
                print_usage(argv[0]);
                return 1;
            }
            interval_sec = atoi(argv[++i]);
            if (interval_sec <= 0)
                interval_sec = 1;
        } else if (strcmp(argv[i], "--block") == 0) {
            if (i + 3 >= (int)argc) {
                print_usage(argv[0]);
                return 1;
            }
            rule.enabled = 1;
            rule.family = (__u32)strtoul(argv[++i], NULL, 10);
            rule.type = (__u32)strtoul(argv[++i], NULL, 10);
            rule.protocol = (__u32)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* Load */
    skel = cgroup_sock_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА\n");
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Attach */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup (%s)\n", strerror(errno));
        cgroup_sock_bpf__destroy(skel);
        return 1;
    }
    link = bpf_program__attach_cgroup(skel->progs.count_sock_create, cg_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        cgroup_sock_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    if (rule.enabled) {
        err = bpf_map__update_elem(skel->maps.sock_block_config,
                                   &key, sizeof(key), &rule, sizeof(rule), BPF_ANY);
        if (err) {
            fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось применить rule (%d)\n", err);
            bpf_link__destroy(link);
            close(cg_fd);
            cgroup_sock_bpf__destroy(skel);
            return 1;
        }

        printf("  [ATTACH] BLOCK RULE enabled family=%u type=%u protocol=%u\n",
               rule.family, rule.type, rule.protocol);
    }

    /* Trigger */
    if (run_socket_probe(AF_INET, SOCK_STREAM, 0, 0) == 0)
        printf("  [TRIGGER] OK\n");
    else
        printf("  [TRIGGER] WARN (не удалось выполнить базовый probe: %s)\n", strerror(errno));

    if (rule.enabled) {
        int probe_rc = run_socket_probe((int)rule.family, (int)rule.type, (int)rule.protocol, 1);
        if (probe_rc == 0)
            printf("  [TRIGGER] BLOCK PROBE PASS\n");
        else
            printf("  [TRIGGER] BLOCK PROBE FAIL (socket не заблокирован или ошибка не EPERM/EACCES)\n");
    }

    /* Verify */
    err = bpf_map__lookup_elem(skel->maps.sock_create_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        if (!realtime_mode) {
            bpf_link__destroy(link);
            close(cg_fd);
            cgroup_sock_bpf__destroy(skel);
            return 1;
        }
    }

    if (realtime_mode) {
        printf("  [VERIFY] REALTIME MODE: Ctrl+C для остановки\n");
        while (!g_stop) {
            err = bpf_map__lookup_elem(skel->maps.sock_rt_metrics,
                                       &key, sizeof(key), &metrics, sizeof(metrics), 0);
            if (err == 0) {
                unsigned long long d_total = (unsigned long long)(metrics.total_events - prev_metrics.total_events);
                unsigned long long d_allow = (unsigned long long)(metrics.allowed_events - prev_metrics.allowed_events);
                unsigned long long d_block = (unsigned long long)(metrics.blocked_events - prev_metrics.blocked_events);

                printf("    [VERIFY] total=%llu (+%llu) allowed=%llu (+%llu) blocked=%llu (+%llu) last={fam=%u type=%u proto=%u decision=%s}\n",
                       (unsigned long long)metrics.total_events, d_total,
                       (unsigned long long)metrics.allowed_events, d_allow,
                       (unsigned long long)metrics.blocked_events, d_block,
                       metrics.last_family, metrics.last_type, metrics.last_protocol,
                       metrics.last_decision ? "ALLOW" : "BLOCK");
                prev_metrics = metrics;
            } else {
                printf("    [VERIFY] WARN: не удалось прочитать realtime метрики (%d)\n", err);
            }
            sleep((unsigned int)interval_sec);
        }
    }

    /* Cleanup */
    bpf_link__destroy(link);
    close(cg_fd);
    cgroup_sock_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
