/* Userspace-программа для проверки BPF_PROG_TYPE_SK_LOOKUP (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk_lookup.skel.h"
#include "../common/keep_attached.h"

#define TEST_PORT 19876

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct sk_lookup_bpf *skel;
    struct bpf_link *link = NULL;
    __u32 key = 0;
    __u64 val = 0;
    int err, netns_fd;
    int srv = -1, cli = -1;

    /* Загрузка */
    skel = sk_lookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Присоединение к network namespace */
    netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: открытие netns: %s\n", strerror(errno));
        sk_lookup_bpf__destroy(skel);
        return 1;
    }

    link = bpf_program__attach_netns(skel->progs.count_sk_lookup, netns_fd);
    close(netns_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: attach_netns: %s\n", strerror(errno));
        sk_lookup_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Создание слушающего сокета */
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: socket: %s\n", strerror(errno));
        goto out;
    }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: bind: %s\n", strerror(errno));
        goto out;
    }
    listen(srv, 1);

    /* Подключение клиента вызывает sk_lookup */
    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        fprintf(stderr, "  [TRIGGER] ОШИБКА: client socket: %s\n", strerror(errno));
        goto out;
    }
    connect(cli, (struct sockaddr *)&addr, sizeof(addr));
    printf("  [TRIGGER] OK\n");

    usleep(100000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.lookup_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu, err=%d)\n", (unsigned long long)val, err);
    }

out:
    if (cli >= 0) close(cli);
    if (srv >= 0) close(srv);
    if (link) bpf_link__destroy(link);
    kbpf_wait_if_keep_attached(keep_attached);
    sk_lookup_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
