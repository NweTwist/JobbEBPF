/*
 * Загрузчик для perf_event.bpf.o
 * Подключает eBPF-программу к программному событию perf (CPU clock)
 * и выводит счётчик срабатываний каждую секунду.
 *
 * Компиляция:
 *   gcc -o perf_event_loader perf_event_loader.c -lbpf -lelf -lz
 *
 * Запуск:
 *   ./perf_event_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

static volatile int running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid,
                           int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd;
    int *perf_fds = NULL;
    int num_cpus;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) {
        fprintf(stderr, "Не удалось определить количество CPU\n");
        return 1;
    }

    /* Открытие объектного файла */
    obj = bpf_object__open("perf_event.bpf.o");
    if (!obj) {
        fprintf(stderr, "Ошибка открытия BPF-объекта\n");
        return 1;
    }

    /* Загрузка в ядро */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Ошибка загрузки BPF-объекта: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    /* Поиск программы */
    prog = bpf_object__find_program_by_name(obj, "count_perf_event");
    if (!prog) {
        fprintf(stderr, "Программа count_perf_event не найдена\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    /* Получение дескриптора карты */
    map_fd = bpf_object__find_map_fd_by_name(obj, "perf_count");
    if (map_fd < 0) {
        fprintf(stderr, "Карта perf_count не найдена\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Создание perf event на каждом CPU и подключение BPF-программы */
    perf_fds = calloc(num_cpus, sizeof(int));
    if (!perf_fds) {
        fprintf(stderr, "Ошибка выделения памяти\n");
        bpf_object__close(obj);
        return 1;
    }

    for (int i = 0; i < num_cpus; i++)
        perf_fds[i] = -1;

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_freq = 100;  /* 100 Гц */
    attr.freq = 1;
    attr.size = sizeof(attr);

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        int pfd = perf_event_open(&attr, -1, cpu, -1, 0);
        if (pfd < 0) {
            fprintf(stderr, "Ошибка perf_event_open для CPU %d\n", cpu);
            continue;
        }
        perf_fds[cpu] = pfd;

        err = ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd);
        if (err) {
            fprintf(stderr, "Ошибка подключения BPF к perf event на CPU %d\n", cpu);
            close(pfd);
            perf_fds[cpu] = -1;
            continue;
        }

        ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
    }

    printf("Программа загружена на %d CPU. Счётчик событий perf:\n", num_cpus);

    /* Цикл опроса счётчика */
    while (running) {
        __u32 key = 0;
        __u64 value = 0;

        err = bpf_map_lookup_elem(map_fd, &key, &value);
        if (err == 0)
            printf("  perf_count: %llu\n", value);

        sleep(1);
    }

    printf("\nОстановка...\n");

    /* Закрытие perf event */
    for (int i = 0; i < num_cpus; i++) {
        if (perf_fds[i] >= 0)
            close(perf_fds[i]);
    }
    free(perf_fds);

    bpf_object__close(obj);

    return 0;
}
