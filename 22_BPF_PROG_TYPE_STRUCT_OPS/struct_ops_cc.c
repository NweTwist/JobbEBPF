/* Userspace-программа для проверки BPF_PROG_TYPE_STRUCT_OPS (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "struct_ops_cc.skel.h"

int main(void)
{
    struct struct_ops_cc_bpf *skel;
    struct bpf_link *link = NULL;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Загрузка */
    skel = struct_ops_cc_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение struct_ops (регистрация TCP congestion control) */
    link = bpf_map__attach_struct_ops(skel->maps.bpf_cc);
    if (!link) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        struct_ops_cc_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Генерация TCP-трафика с использованием bpf_cc */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: socket: %s\n", strerror(errno));
        goto cleanup;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(12348),
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

    /* Установка congestion control алгоритма bpf_cc */
    if (setsockopt(cli, IPPROTO_TCP, TCP_CONGESTION, "bpf_cc", sizeof("bpf_cc")) < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: TCP_CONGESTION: %s\n", strerror(errno));
        close(cli);
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
    if (acc < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: accept: %s\n", strerror(errno));
        close(cli);
        close(srv);
        goto cleanup;
    }

    /* Отправка данных для активации congestion control */
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    for (int i = 0; i < 10; i++)
        send(cli, buf, sizeof(buf), 0);

    /* Приём данных */
    while (recv(acc, buf, sizeof(buf), MSG_DONTWAIT) > 0)
        ;

    close(acc);
    close(cli);
    close(srv);
    printf("  [TRIGGER] OK\n");

    /* Пауза для обработки событий */
    usleep(50000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.ca_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        struct_ops_cc_bpf__destroy(skel);
        return 1;
    }

cleanup:
    bpf_link__destroy(link);
    struct_ops_cc_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
