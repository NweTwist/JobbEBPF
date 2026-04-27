#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cgroup_dev.skel.h"

struct dev_key {
    __u32 major;
    __u32 minor;
};

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static int read_line(const char *path, char *buf, size_t buf_sz)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    if (!fgets(buf, (int)buf_sz, f)) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

static int is_usb_block_device(const char *name, unsigned int *maj, unsigned int *min)
{
    char path[PATH_MAX];
    char line[128];
    char resolved[PATH_MAX];
    FILE *f;

    snprintf(path, sizeof(path), "/sys/block/%s/removable", name);
    if (read_line(path, line, sizeof(line)) < 0 || line[0] != '1')
        return 0;

    snprintf(path, sizeof(path), "/sys/block/%s/device", name);
    if (!realpath(path, resolved))
        return 0;
    if (!strstr(resolved, "/usb"))
        return 0;

    snprintf(path, sizeof(path), "/sys/block/%s/dev", name);
    f = fopen(path, "r");
    if (!f)
        return 0;
    if (fscanf(f, "%u:%u", maj, min) != 2) {
        fclose(f);
        return 0;
    }
    fclose(f);

    return 1;
}

static int sync_blocked_usb_devices(struct cgroup_dev_bpf *skel)
{
    DIR *dir;
    struct dirent *de;
    int newly_blocked = 0;

    dir = opendir("/sys/block");
    if (!dir)
        return -1;

    while ((de = readdir(dir)) != NULL) {
        struct dev_key key;
        unsigned int maj, min;
        __u8 value = 1;
        __u8 existing = 0;
        int err;

        if (de->d_name[0] == '.')
            continue;

        if (!is_usb_block_device(de->d_name, &maj, &min))
            continue;

        key.major = maj;
        key.minor = min;
        err = bpf_map__lookup_elem(skel->maps.blocked_devices,
                                   &key, sizeof(key),
                                   &existing, sizeof(existing),
                                   0);
        if (err == 0)
            continue;

        err = bpf_map__update_elem(skel->maps.blocked_devices,
                                   &key, sizeof(key),
                                   &value, sizeof(value),
                                   BPF_ANY);
        if (err) {
            fprintf(stderr, "  [USB MAP] ОШИБКА: %s (%s %u:%u)\n",
                    strerror(errno), de->d_name, maj, min);
            closedir(dir);
            return -1;
        }

        newly_blocked++;
        printf("  [USB MAP] block %s (%u:%u)\n", de->d_name, maj, min);
    }

    closedir(dir);
    return newly_blocked;
}

int main(void)
{
    struct cgroup_dev_bpf *skel;
    struct bpf_link *link = NULL;
    int cg_fd = -1;
    __u32 key = 0;
    __u64 val = 0;
    int blocked = 0;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load */
    skel = cgroup_dev_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "  [LOAD] ОШИБКА\n");
        return 1;
    }
    printf("  [LOAD] OK\n");

    /* Attach */
    cg_fd = open("/sys/fs/cgroup", O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: не удалось открыть cgroup (%s)\n", strerror(errno));
        cgroup_dev_bpf__destroy(skel);
        return 1;
    }
    link = bpf_program__attach_cgroup(skel->progs.cgroup_dev_filter, cg_fd);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "  [ATTACH] ОШИБКА: %s\n", strerror(errno));
        close(cg_fd);
        cgroup_dev_bpf__destroy(skel);
        return 1;
    }
    printf("  [ATTACH] OK\n");

    blocked = sync_blocked_usb_devices(skel);
    if (blocked < 0) {
        fprintf(stderr, "  [USB MAP] ОШИБКА: не удалось заполнить карту USB устройств\n");
        bpf_link__destroy(link);
        close(cg_fd);
        cgroup_dev_bpf__destroy(skel);
        return 1;
    }
    printf("  [USB MAP] READY (blocked=%d)\n", blocked);

    /* Trigger */
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0)
        close(fd);
    printf("  [TRIGGER] OK\n");

    /* Verify */
    err = bpf_map__lookup_elem(skel->maps.dev_access_count,
                               &key, sizeof(key), &val, sizeof(val), 0);
    if (err == 0 && val > 0)
        printf("  [VERIFY] PASS (counter=%llu)\n", (unsigned long long)val);
    else {
        printf("  [VERIFY] FAIL (counter=%llu)\n", (unsigned long long)val);
        bpf_link__destroy(link);
        close(cg_fd);
        cgroup_dev_bpf__destroy(skel);
        return 1;
    }

    printf("  [RUN] Программа активна. Вставьте USB-накопитель и проверьте доступ.\n");
    printf("  [RUN] Для завершения нажмите Ctrl+C.\n");
    while (!stop) {
        int new_blocked = sync_blocked_usb_devices(skel);
        if (new_blocked < 0)
            fprintf(stderr, "  [USB MAP] WARNING: ошибка обновления карты (%s)\n", strerror(errno));
        sleep(1);
    }

    /* Cleanup */
    bpf_link__destroy(link);
    close(cg_fd);
    cgroup_dev_bpf__destroy(skel);
    printf("  [CLEANUP] OK\n");
    return 0;
}
