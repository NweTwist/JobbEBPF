/* Userspace-программа для проверки BPF_PROG_TYPE_SYSCALL (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_prog.skel.h"
#include "../common/keep_attached.h"

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct syscall_prog_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err;

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

    kbpf_wait_if_keep_attached(keep_attached);
    syscall_prog_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
