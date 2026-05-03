/* Userspace-программа для проверки BPF_PROG_TYPE_SK_MSG (скелет libbpf) */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sk_msg.skel.h"
#include "../common/keep_attached.h"

#define TEST_PORT 18917

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

/* Создание пары TCP-сокетов через loopback */
static int create_tcp_pair(int *cli_fd, int *acc_fd)
{
    int srv, cli, acc;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int opt = 1;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return -1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv); return -1;
    }
    listen(srv, 1);

    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) { close(srv); return -1; }

    if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(cli); close(srv); return -1;
    }

    acc = accept(srv, NULL, NULL);
    close(srv);
    if (acc < 0) { close(cli); return -1; }

    *cli_fd = cli;
    *acc_fd = acc;
    return 0;
}

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct sk_msg_bpf *skel;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err, prog_fd, sockmap_fd;
    int cli_fd = -1, acc_fd = -1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Загрузка */
    skel = sk_msg_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: %s\n", strerror(errno));
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Создание TCP-пары */
    if (create_tcp_pair(&cli_fd, &acc_fd) < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: create_tcp_pair: %s\n", strerror(errno));
        sk_msg_bpf__destroy(skel);
        return 1;
    }

    /* Сначала присоединяем SK_MSG к sockmap, затем добавляем сокеты.
     * Порядок важен: psock-перехватчик активируется при добавлении сокета
     * в sockmap, к которому уже присоединена BPF-программа. */
    sockmap_fd = bpf_map__fd(skel->maps.sock_map);
    prog_fd = bpf_program__fd(skel->progs.count_sk_msg);
    err = bpf_prog_attach(prog_fd, sockmap_fd, BPF_SK_MSG_VERDICT, 0);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: bpf_prog_attach: %s\n", strerror(errno));
        goto out;
    }

    /* Добавление сокета в sockmap после присоединения программы */
    __u32 idx = 0;
    err = bpf_map_update_elem(sockmap_fd, &idx, &cli_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: sockmap update: %s\n", strerror(errno));
        goto out;
    }
    printf("  [ATTACH] OK\n");

    /* Отправка данных через TCP-сокет (вызывает SK_MSG verdict) */
    char buf[64] = "test_sk_msg_data";
    for (int i = 0; i < 3; i++) {
        if (send(cli_fd, buf, sizeof(buf), 0) < 0) {
            fprintf(stderr, "  [TRIGGER] ОШИБКА: send: %s\n", strerror(errno));
            goto out;
        }
        memset(buf, 0, sizeof(buf));
        recv(acc_fd, buf, sizeof(buf), 0);
    }
    printf("  [TRIGGER] OK\n");

    usleep(100000);

    /* Проверка счётчика */
    err = bpf_map__lookup_elem(skel->maps.msg_count, &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0) {
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    } else {
        printf("  [VERIFY] FAIL (counter=%llu, err=%d)\n", (unsigned long long)val, err);
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        char rt_buf[64] = "rt_sk_msg";
        if (send(cli_fd, rt_buf, sizeof(rt_buf), 0) < 0) {
            fprintf(stderr, "  [RT] WARN: send: %s\n", strerror(errno));
        } else {
            recv(acc_fd, rt_buf, sizeof(rt_buf), 0);
        }

        err = bpf_map__lookup_elem(skel->maps.msg_count, &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] msg_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }

        sleep(1);
    }

out:
    bpf_prog_detach(sockmap_fd, BPF_SK_MSG_VERDICT);
    if (cli_fd >= 0) close(cli_fd);
    if (acc_fd >= 0) close(acc_fd);
    kbpf_wait_if_keep_attached(keep_attached);
    sk_msg_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
