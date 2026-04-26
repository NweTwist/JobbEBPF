/* Userspace-программа для проверки BPF_PROG_TYPE_SOCK_OPS (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sock_ops.skel.h"
#include "../common/keep_attached.h"

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct sock_ops_bpf *skel;
    struct bpf_link *link = NULL;
    __u32 key = 0;
    __u64 val = 0;
    int err, cg_fd = -1;

    /* Загрузка */
    skel = sock_ops_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение к cgroup */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup: %s\n", strerror(errno));
        sock_ops_bpf__destroy(skel);
        return 1;
    }

    link = bpf_program__attach_cgroup(skel->progs.count_sock_ops, cg_fd);
    if (!link) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        sock_ops_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация событий sock_ops через TCP-соединение */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: socket: %s\n", strerror(errno));
        goto cleanup;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(12347),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: bind: %s\n", strerror(errno));
        close(srv);
        goto cleanup;
    }
    listen(srv, 1);

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: socket cli: %s\n", strerror(errno));
        close(srv);
        goto cleanup;
    }

    if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: connect: %s\n", strerror(errno));
        close(cli);
        close(srv);
        goto cleanup;
    }

    int acc = accept(srv, NULL, NULL);
    if (acc >= 0)
        close(acc);
    close(cli);
    close(srv);
    printf("  [TRIGGER] OK\n");

    /* Пауза для обработки событий */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.sockops_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        close(cg_fd);
        sock_ops_bpf__destroy(skel);
        return 1;
    }

cleanup:
    bpf_link__destroy(link);
    close(cg_fd);
    kbpf_wait_if_keep_attached(keep_attached);
    sock_ops_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
