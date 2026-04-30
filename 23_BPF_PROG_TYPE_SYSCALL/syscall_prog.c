/* Userspace-программа для проверки BPF_PROG_TYPE_SYSCALL (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_prog.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

int main(void)
{
    struct syscall_prog_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = syscall_prog_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* SYSCALL-тип не требует attach, запускаем через BPF_PROG_RUN */
    int prog_fd = bpf_program__fd(skel->progs.bpf_syscall_prog);

    printf("  [ATTACH] не требуется (BPF_PROG_RUN)\n");

    /* Вызов программы несколько раз */
    for (int i = 0; i < 5; i++) {
        LIBBPF_OPTS(bpf_test_run_opts, topts);
        err = bpf_prog_test_run_opts(prog_fd, &topts);
        if (err) {
            fprintf(stderr, "  [TRIGGER] ОШИБКА: bpf_prog_test_run_opts: %s\n", strerror(-err));
            syscall_prog_bpf__destroy(skel);
            return 1;
        }
    }
    printf("  [TRIGGER] OK (5 запусков)\n");

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.syscall_run_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val >= 5) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        syscall_prog_bpf__destroy(skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        LIBBPF_OPTS(bpf_test_run_opts, topts);
        err = bpf_prog_test_run_opts(prog_fd, &topts);
        if (err) {
            fprintf(stderr, "  [RT] WARN: bpf_prog_test_run_opts: %s\n", strerror(-err));
        }

        err = bpf_map__lookup_elem(skel->maps.syscall_run_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] syscall_run_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }

        sleep(1);
    }

    syscall_prog_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
