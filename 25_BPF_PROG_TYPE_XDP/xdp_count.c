/* Userspace-программа для проверки BPF_PROG_TYPE_XDP (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_count.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

int main(void)
{
    struct xdp_count_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err;
    int ifindex;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = xdp_count_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение XDP к loopback */
    ifindex = if_nametoindex("lo");
    if (!ifindex) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: if_nametoindex(lo): %s\n", strerror(errno));
        xdp_count_bpf__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_pass_count);
    err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: bpf_xdp_attach: %s\n", strerror(-err));
        xdp_count_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK (lo, ifindex=%d)\n", ifindex);

    /* Генерация трафика */
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Пауза для обработки */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.pkt_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_xdp_detach(ifindex, 0, NULL);
        xdp_count_bpf__destroy(skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(skel->maps.pkt_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] pkt_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    /* Очистка XDP */
    bpf_xdp_detach(ifindex, 0, NULL);
    xdp_count_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
