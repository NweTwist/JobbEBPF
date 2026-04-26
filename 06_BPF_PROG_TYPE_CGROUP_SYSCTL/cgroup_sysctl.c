#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_sysctl.skel.h"
#include "../common/keep_attached.h"

int main(int argc, char **argv)
{
    int keep_attached = kbpf_scan_keep_attached(argc, argv);
    struct cgroup_sysctl_bpf *skel;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    __u32 key = 0;
    __u64 val = 0;
    int err;

    /* Load */
    skel = cgroup_sysctl_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА\n");
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Attach */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup (%s)\n", strerror(errno));
        cgroup_sysctl_bpf__destroy(skel);
        return 1;
    }
    link = bpf_program__attach_cgroup(skel->progs.count_sysctl, cg_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        cgroup_sysctl_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    /* Trigger */
    system("sysctl net.ipv4.ip_forward > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Verify */
    err = bpf_map__lookup_elem(skel->maps.sysctl_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0)
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        close(cg_fd);
        cgroup_sysctl_bpf__destroy(skel);
        return 1;
    }

    /* Cleanup */
    bpf_link__destroy(link);
    close(cg_fd);
    kbpf_wait_if_keep_attached(keep_attached);
    cgroup_sysctl_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
