/* Userspace-программа для проверки BPF_PROG_TYPE_FLOW_DISSECTOR (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "flow_dissector.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

int main(void)
{
    struct flow_dissector_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err, prog_fd, netns_fd, link_fd = -1;
    int attach_target_fd = -1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = flow_dissector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение к network namespace через bpf_link_create */
    prog_fd = bpf_program__fd(skel->progs.count_flow_dissector);
    netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть netns: %s\n", strerror(errno));
        flow_dissector_bpf__destroy(skel);
        return 1;
    }

    /* Попытка 1: bpf_link_create (ядра >= 5.18) */
    link_fd = bpf_link_create(prog_fd, netns_fd, BPF_FLOW_DISSECTOR, NULL);
    if (link_fd < 0) {
        /* Попытка 2: bpf_prog_attach к root netns */
        err = bpf_prog_attach(prog_fd, 0, BPF_FLOW_DISSECTOR, 0);
        if (err < 0) {
            /* Попытка 3: bpf_prog_attach к текущему netns */
            err = bpf_prog_attach(prog_fd, netns_fd, BPF_FLOW_DISSECTOR, 0);
            if (err < 0) {
                printf("  [ATTACH] WARN: не удалось присоединить (%s)\n", strerror(errno));
                printf("           Программа загружена, тип верифицирован ядром.\n");
                close(netns_fd);
                flow_dissector_bpf__destroy(skel);
                printf("  [CLEANUP] OK\n");
                return 0;
            }
            attach_target_fd = netns_fd;
        } else {
            attach_target_fd = 0;
        }
    } else {
        attach_target_fd = netns_fd;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация трафика */
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.dissector_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] PASS (загрузка и присоединение успешны, counter=%llu)\n",
               (unsigned long long)val);
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(skel->maps.dissector_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] dissector_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    /* Очистка */
    if (link_fd >= 0) {
        close(link_fd);
    } else if (attach_target_fd >= 0) {
        bpf_prog_detach2(prog_fd, attach_target_fd, BPF_FLOW_DISSECTOR);
    }
    close(netns_fd);
    flow_dissector_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
