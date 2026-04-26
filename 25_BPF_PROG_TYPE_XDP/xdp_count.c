/* Userspace-программа для проверки BPF_PROG_TYPE_XDP (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_count.skel.h"

int main(void)
{
    struct xdp_count_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err;
    int ifindex;

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

    /* Очистка XDP */
    bpf_xdp_detach(ifindex, 0, NULL);
    xdp_count_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
