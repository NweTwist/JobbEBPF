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
#include "cgroup_sock_addr.skel.h"

int main(void)
{
    struct cgroup_sock_addr_bpf *skel;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Load */
    skel = cgroup_sock_addr_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА\n");
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Attach */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup (%s)\n", strerror(errno));
        cgroup_sock_addr_bpf__destroy(skel);
        return 1;
    }
    link = bpf_program__attach_cgroup(skel->progs.count_connect4, cg_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        cgroup_sock_addr_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Trigger: connect to 127.0.0.1:80 (will fail, but BPF fires) */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        connect(s, (struct sockaddr *)&addr, sizeof(addr));
        close(s);
    }
    printf("  [TRIGGER] OK\n");

    /* Verify */
    err = bpf_map__lookup_elem(skel->maps.connect4_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0)
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        close(cg_fd);
        cgroup_sock_addr_bpf__destroy(skel);
        return 1;
    }

    /* Cleanup */
    bpf_link__destroy(link);
    close(cg_fd);
    cgroup_sock_addr_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
