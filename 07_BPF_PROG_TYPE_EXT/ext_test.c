#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "target.skel.h"
#include "ext_replace.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

int main(void)
{
    struct target_bpf *target_skel = NULL;
    struct ext_replace_bpf *ext_skel = NULL;
    struct bpf_link *ext_link = NULL;
    unsigned int lo_ifindex;
    int target_fd;
    __u32 key = 0;
    __u64 val = 0;
    __u64 prev_val = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load target (XDP program with count_and_pass) */
    target_skel = target_bpf__open_and_load();
    if (!target_skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: target\n");
        return 1;
    }
    target_fd = bpf_program__fd(target_skel->progs.xdp_main);
    printf("  [LOAD] target OK (fd=%d)\n", target_fd);

    /* Open ext_replace skeleton, set attach target */
    ext_skel = ext_replace_bpf__open();
    if (!ext_skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА: ext_replace open\n");
        target_bpf__destroy(target_skel);
        return 1;
    }

    err = bpf_program__set_attach_target(ext_skel->progs.ext_count_and_pass,
                                         target_fd, "count_and_pass");
    if (err) {
        fprintf(stderr, "  [LOAD] ОШИБКА: set_attach_target (%s)\n", strerror(-err));
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }

    err = ext_replace_bpf__load(ext_skel);
    if (err) {
        fprintf(stderr, "  [LOAD] ОШИБКА: ext_replace load (%s)\n", strerror(-err));
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }
    printf("  [LOAD] ext_replace OK\n");

    /* Attach ext (freplace link) */
    ext_link = bpf_program__attach(ext_skel->progs.ext_count_and_pass);
    if (!ext_link || libbpf_get_error(ext_link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: freplace attach (%s)\n", strerror(errno));
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }
    printf("  [ATTACH] freplace OK\n");

    /* Attach target XDP to lo */
    lo_ifindex = if_nametoindex("lo");
    if (lo_ifindex == 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: lo не найден\n");
        bpf_link__destroy(ext_link);
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }

    err = bpf_xdp_attach(lo_ifindex, target_fd, 0, NULL);
    if (err) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: xdp attach lo (%s)\n", strerror(-err));
        bpf_link__destroy(ext_link);
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }
    printf("  [ATTACH] XDP на lo OK\n");

    /* Trigger */
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
    printf("  [TRIGGER] OK\n");

    /* Verify ext_count map */
    err = bpf_map__lookup_elem(ext_skel->maps.ext_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0)
        printf("  [VERIFY] PASS (ext_count=%llu)\n", (unsigned long long)val);
    else {
        printf("  [VERIFY] FAIL (ext_count=%llu)\n", (unsigned long long)val);
        bpf_xdp_detach(lo_ifindex, 0, NULL);
        bpf_link__destroy(ext_link);
        ext_replace_bpf__destroy(ext_skel);
        target_bpf__destroy(target_skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Нажмите Ctrl+C для остановки.\n");
    while (!stop) {
        err = bpf_map__lookup_elem(ext_skel->maps.ext_count,
                                   &key, sizeof(key), &val, sizeof(val), 0);
        if (err == 0) {
            unsigned long long delta = (unsigned long long)(val - prev_val);
            printf("  [RT] ext_count=%llu (+%llu)\n",
                   (unsigned long long)val, delta);
            prev_val = val;
        } else {
            printf("  [RT] WARN: не удалось прочитать счётчик (%d)\n", err);
        }
        sleep(1);
    }

    /* Cleanup */
    bpf_xdp_detach(lo_ifindex, 0, NULL);
    bpf_link__destroy(ext_link);
    ext_replace_bpf__destroy(ext_skel);
    target_bpf__destroy(target_skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
