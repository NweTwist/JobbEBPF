/* Userspace-программа для проверки BPF_PROG_TYPE_TRACEPOINT (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tp_openat.skel.h"

int main(void)
{
    struct tp_openat_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Загрузка */
    skel = tp_openat_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение (auto-attach по SEC("tracepoint/syscalls/sys_enter_openat")) */
    err = tp_openat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(-err));
        tp_openat_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация событий openat */
    int fd = open("/tmp/tp_test", O_RDONLY | O_CREAT, 0644);
    if (fd >= 0)
        close(fd);
    fd = open("/tmp/tp_test", O_RDONLY, 0);
    if (fd >= 0)
        close(fd);
    unlink("/tmp/tp_test");
    printf("  [TRIGGER] OK\n");

    /* Пауза для обработки событий */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.openat_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        tp_openat_bpf__destroy(skel);
        return 1;
    }

    tp_openat_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
