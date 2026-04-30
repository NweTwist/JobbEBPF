/* Userspace-программа для проверки BPF_PROG_TYPE_PERF_EVENT (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "perf_event.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(void)
{
    struct perf_event_bpf *skel;
    struct bpf_link *link = NULL;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err, pmu_fd;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = perf_event_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Открытие perf event (CPU clock, cpu 0) */
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_CPU_CLOCK,
        .sample_period = 100000,
        .sample_type = PERF_SAMPLE_RAW,
        .size = sizeof(attr),
    };
    pmu_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (pmu_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: perf_event_open: %s\n", strerror(errno));
        perf_event_bpf__destroy(skel);
        return 1;
    }

    link = bpf_program__attach_perf_event(skel->progs.count_perf_event, pmu_fd);
    if (!link) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: attach_perf_event: %s\n", strerror(errno));
        close(pmu_fd);
        perf_event_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация CPU-событий (busy loop ~100ms) */
    volatile int x = 0;
    for (int i = 0; i < 10000000; i++)
        x += i;
    printf("  [TRIGGER] OK\n");

    /* Небольшая пауза */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.perf_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        perf_event_bpf__destroy(skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(skel->maps.perf_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] perf_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    bpf_link__destroy(link);
    close(pmu_fd);
    perf_event_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
