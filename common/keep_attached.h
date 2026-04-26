#ifndef KEEP_ATTACHED_H
#define KEEP_ATTACHED_H

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t kbpf_keep_running = 1;

static void kbpf_keep_signal_handler(int sig)
{
    (void)sig;
    kbpf_keep_running = 0;
}

static int kbpf_scan_keep_attached(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--keep-attached") == 0 || strcmp(argv[i], "-k") == 0)
            return 1;
    }

    return 0;
}

static void kbpf_wait_if_keep_attached(int keep_attached)
{
    if (!keep_attached)
        return;

    kbpf_keep_running = 1;
    signal(SIGINT, kbpf_keep_signal_handler);
    signal(SIGTERM, kbpf_keep_signal_handler);

    printf("[PERSIST] keep-attached mode is enabled. Press Ctrl+C to detach and exit.\n");
    while (kbpf_keep_running)
        sleep(1);
}

#endif /* KEEP_ATTACHED_H */
