/*
 * Загрузчик для raw_tp_sched.bpf.o
 * Подключает eBPF-программу к raw tracepoint sched_switch
 * и выводит счётчик переключений контекста каждую секунду.
 *
 * Компиляция:
 *   gcc -o raw_tp_sched_loader raw_tp_sched_loader.c -lbpf -lelf -lz
 *
 * Запуск:
 *   ./raw_tp_sched_loader
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int map_fd;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Открытие объектного файла */
    obj = bpf_object__open("raw_tp_sched.bpf.o");
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
    prog = bpf_object__find_program_by_name(obj, "raw_tp_sched_switch");
    if (!prog) {
        fprintf(stderr, "Программа raw_tp_sched_switch не найдена\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Подключение к raw tracepoint */
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Ошибка подключения к raw tracepoint\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Получение дескриптора карты */
    map_fd = bpf_object__find_map_fd_by_name(obj, "sched_count");
    if (map_fd < 0) {
        fprintf(stderr, "Карта sched_count не найдена\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("Программа загружена. Счётчик переключений контекста:\n");

    /* Цикл опроса счётчика */
    while (running) {
        __u32 key = 0;
        __u64 value = 0;

        err = bpf_map_lookup_elem(map_fd, &key, &value);
        if (err == 0)
            printf("  sched_count: %llu\n", value);

        sleep(1);
    }

    printf("\nОстановка...\n");

    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
