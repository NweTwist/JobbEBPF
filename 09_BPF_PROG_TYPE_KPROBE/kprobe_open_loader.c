/*
 * Загрузчик для kprobe_open.bpf.o
 * Подключает eBPF-программу к kprobe функции do_sys_openat2
 * и выводит счётчик вызовов каждую секунду.
 *
 * Компиляция:
 *   gcc -o kprobe_open_loader kprobe_open_loader.c -lbpf -lelf -lz
 *
 * Запуск:
 *   ./kprobe_open_loader
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
    obj = bpf_object__open("kprobe_open.bpf.o");
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
    prog = bpf_object__find_program_by_name(obj, "kprobe_do_sys_openat2");
    if (!prog) {
        fprintf(stderr, "Программа kprobe_do_sys_openat2 не найдена\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Подключение к kprobe */
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Ошибка подключения к kprobe\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Получение дескриптора карты */
    map_fd = bpf_object__find_map_fd_by_name(obj, "kprobe_count");
    if (map_fd < 0) {
        fprintf(stderr, "Карта kprobe_count не найдена\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("Программа загружена. Счётчик вызовов do_sys_openat2:\n");

    /* Цикл опроса счётчика */
    while (running) {
        __u32 key = 0;
        __u64 value = 0;

        err = bpf_map_lookup_elem(map_fd, &key, &value);
        if (err == 0)
            printf("  kprobe_count: %llu\n", value);

        sleep(1);
    }

    printf("\nОстановка...\n");

    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
