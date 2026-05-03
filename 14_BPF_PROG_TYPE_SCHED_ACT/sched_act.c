/* Userspace-программа для проверки BPF_PROG_TYPE_SCHED_ACT (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sched_act.skel.h"
#include "../common/keep_attached.h"

#define PIN_PATH "/sys/fs/bpf/_test_sched_act"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static void cleanup(struct sched_act_bpf *skel)
{
    system("tc filter del dev lo egress 2>/dev/null");
    system("tc qdisc del dev lo clsact 2>/dev/null");
    unlink(PIN_PATH);
    kbpf_wait_if_keep_attached(keep_attached);
    if (skel)
        sched_act_bpf__destroy(skel);
}

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct sched_act_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err, prog_fd;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = sched_act_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Pin программы */
    prog_fd = bpf_program__fd(skel->progs.tc_act_count);
    err = bpf_obj_pin(prog_fd, PIN_PATH);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: bpf_obj_pin: %s\n", strerror(errno));
        cleanup(skel);
        return 1;
    }

    /* Присоединение через tc с matchall + action bpf */
    system("tc qdisc del dev lo clsact 2>/dev/null");
    if (system("tc qdisc add dev lo clsact") != 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: tc qdisc add\n");
        cleanup(skel);
        return 1;
    }

    /* SCHED_ACT программы подключаются через action bpf, не через bpf da */
    if (system("tc filter add dev lo egress protocol all prio 1 "
               "matchall action bpf object-pinned " PIN_PATH) != 0) {
        /* Альтернатива: u32 match all */
        if (system("tc filter add dev lo egress protocol ip prio 1 "
                   "u32 match u32 0 0 action bpf object-pinned " PIN_PATH) != 0) {
            fprintf(stderr, "  [ATTACH] ОШИБКА: tc filter add\n");
            cleanup(skel);
            return 1;
        }
    }
    printf("  [ATTACH] OK\n");

    /* Генерация трафика */
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.act_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu, err=%d)\n", (unsigned long long)val, err);
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(skel->maps.act_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] act_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    /* Очистка */
    cleanup(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
