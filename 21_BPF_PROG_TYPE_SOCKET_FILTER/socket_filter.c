/* Userspace-программа для проверки BPF_PROG_TYPE_SOCKET_FILTER (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "socket_filter.skel.h"

int main(void)
{
    struct socket_filter_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err, raw_sock = -1;

    /* Загрузка */
    skel = socket_filter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Создание raw-сокета и присоединение BPF-фильтра */
    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: raw socket: %s\n", strerror(errno));
        socket_filter_bpf__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.count_packets);
    if (setsockopt(raw_sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: SO_ATTACH_BPF: %s\n", strerror(errno));
        close(raw_sock);
        socket_filter_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация трафика */
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Пауза для обработки */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.filter_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        close(raw_sock);
        socket_filter_bpf__destroy(skel);
        return 1;
    }

    close(raw_sock);
    socket_filter_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
