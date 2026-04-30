#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_skb.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

int main(void)
{
    struct cgroup_skb_bpf *skel;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load */
    skel = cgroup_skb_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА\n");
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Attach */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup (%s)\n", strerror(errno));
        cgroup_skb_bpf__destroy(skel);
        return 1;
    }
    link = bpf_program__attach_cgroup(skel->progs.count_egress, cg_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        cgroup_skb_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Trigger */
    system("ping -c 1 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Verify */
    err = bpf_map__lookup_elem(skel->maps.egress_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0)
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        close(cg_fd);
        cgroup_skb_bpf__destroy(skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(skel->maps.egress_count,
                                   &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] egress_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    /* Cleanup */
    bpf_link__destroy(link);
    close(cg_fd);
    cgroup_skb_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
