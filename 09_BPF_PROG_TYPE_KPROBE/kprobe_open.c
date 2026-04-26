/* Userspace-программа для проверки BPF_PROG_TYPE_KPROBE (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kprobe_open.skel.h"

int main(void)
{
    struct kprobe_open_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Загрузка */
    skel = kprobe_open_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение (auto-attach по SEC("kprobe/do_sys_openat2")) */
    err = kprobe_open_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(-err));
        kprobe_open_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация событий openat2 */
    int fd = open("/tmp/kprobe_test", O_RDONLY | O_CREAT, 0644);
    if (fd >= 0)
        close(fd);
    fd = open("/tmp/kprobe_test", O_RDONLY, 0);
    if (fd >= 0)
        close(fd);
    unlink("/tmp/kprobe_test");
    printf("  [TRIGGER] OK\n");

    /* Небольшая пауза для обработки событий */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.kprobe_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        kprobe_open_bpf__destroy(skel);
        return 1;
    }

    kprobe_open_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
