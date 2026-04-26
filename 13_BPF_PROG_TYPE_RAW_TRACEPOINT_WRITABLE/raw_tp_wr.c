/* Userspace-программа для проверки BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "raw_tp_wr.skel.h"

int main(void)
{
    struct raw_tp_wr_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Загрузка */
    skel = raw_tp_wr_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение (auto-attach по SEC("raw_tracepoint.w/sys_enter")) */
    err = raw_tp_wr_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(-err));
        raw_tp_wr_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация системных вызовов */
    system("ls /tmp > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Небольшая пауза */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.syscall_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        raw_tp_wr_bpf__destroy(skel);
        return 1;
    }

    raw_tp_wr_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
