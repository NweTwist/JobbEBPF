/* Userspace-программа для проверки BPF_PROG_TYPE_SK_REUSEPORT (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk_reuseport.skel.h"

#define TEST_PORT 19877

int main(void)
{
    struct sk_reuseport_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    int err, prog_fd;
    int s1 = -1, s2 = -1, cli = -1;

    /* Загрузка */
    skel = sk_reuseport_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Создание первого reuseport сокета */
    s1 = socket(AF_INET, SOCK_STREAM, 0);
    if (s1 < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: socket: %s\n", strerror(errno));
        sk_reuseport_bpf__destroy(skel);
        return 1;
    }
    int opt = 1;
    setsockopt(s1, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(s1, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: bind s1: %s\n", strerror(errno));
        goto out;
    }
    listen(s1, 1);

    /* Присоединение BPF-программы через SO_ATTACH_REUSEPORT_EBPF */
    prog_fd = bpf_program__fd(skel->progs.count_reuseport);
    if (setsockopt(s1, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: SO_ATTACH_REUSEPORT_EBPF: %s\n", strerror(errno));
        goto out;
    }
    printf("  [ATTACH] OK\n");

    /* Создание второго reuseport сокета */
    s2 = socket(AF_INET, SOCK_STREAM, 0);
    if (s2 < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: socket s2: %s\n", strerror(errno));
        goto out;
    }
    setsockopt(s2, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    if (bind(s2, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: bind s2: %s\n", strerror(errno));
        goto out;
    }
    listen(s2, 1);

    /* Подключение клиента вызывает reuseport selection */
    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: client socket: %s\n", strerror(errno));
        goto out;
    }
    connect(cli, (struct sockaddr *)&addr, sizeof(addr));
    printf("  [TRIGGER] OK\n");

    usleep(100000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.reuseport_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu, err=%d)\n", (unsigned long long)val, err);
    }

out:
    if (cli >= 0) close(cli);
    if (s2 >= 0) close(s2);
    if (s1 >= 0) close(s1);
    sk_reuseport_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
