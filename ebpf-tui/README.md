# ebpf-tui

Минимальный TUI-раннер для этого репозитория, адаптированный под модули `01..25_BPF_PROG_TYPE_*`.

Поддерживаются два режима выполнения для каждого модуля:

1) Скриптовый pipeline: **build → load → trace → test → unload** через `build.sh/load.sh/test.sh/unload.sh`.
2) PMI pipeline (fallback): если скриптов нет, команды читаются из `*_Программа_и_методика_испытаний.md` и выполняются последовательно (`bpftool`, `clang`, `gcc`, `./binary`) с проверкой маркера `[VERIFY] PASS`.

## Как это работает

- Раннер автоматически находит папки верхнего уровня вида `01_BPF_PROG_TYPE_* ... 25_BPF_PROG_TYPE_*`.
- Для каждой программы ожидаются скрипты в папке примера:
  - `build.sh` — собрать `.o` (обычно `clang -target bpf ...`)
  - `load.sh` — `bpftool prog load ...` + attach
  - `test.sh` — воспроизвести событие/трафик и проверить поведение
  - `unload.sh` — detach + очистить pinned объекты
- Во время `test.sh` раннер пишет `trace_pipe` в `trace.log`.

Если у вас нет `build.sh/load.sh/test.sh/unload.sh`, раннер будет работать через ПМИ markdown автоматически.

Если вы хотите использовать именно скрипты, можно сгенерировать их из `tutorials.md`:

```bash
python3 tools/gen_scripts_from_tutorials.py --repo-root .
```

Если вы уже генерировали скрипты ранее и хотите обновить их (например, добавить пролог генерации `vmlinux.h`), используйте `--force`:

```bash
python3 tools/gen_scripts_from_tutorials.py --repo-root . --force
```

## Запуск

```bash
cd ebpf-tui
cargo run --release
```

По умолчанию раннер сам определяет корень примеров. Если запуск идет из `ebpf-tui/`, автоматически используется родительский каталог (где находятся `01_BPF_PROG_TYPE_* ... 25_BPF_PROG_TYPE_*`).

Если вы запускаете из `ebpf-tui/`, а примеры лежат уровнем выше, можно явно указать корень репозитория:

```bash
cargo run --release -- --repo-root ..
```

Если чтение `trace_pipe` требует пароль sudo, проще всего:

```bash
sudo -E cargo run --release
```

## Конфиг

В корне репозитория можно создать `ebpf-tui.yaml`:

```yaml
trace_cmd: "sudo cat /sys/kernel/tracing/trace_pipe"
artifacts_dir: "artifacts"
```

## Логи

После запуска шагов логи пишутся в:

`artifacts/<program>/`

Файлы: `build.log`, `load.log`, `test.log`, `unload.log`, `trace.log`, `pmi.txt`.

Для ручной проверки модулей по отдельности дополнительно пишутся:

- `manual_build.log`
- `manual_load.log`
- `manual_test.log`
- `manual_unload.log`
- `manual_trace.log` (живой trace для проверки в другом окне)
- `manual_trace_start.log`, `manual_trace_stop.log`

Также для каждого прогона формируются:

- `status.log` — компактная статус-сводка в текстовом виде.
- `run_report.md` — структурированный отчёт по модулю и доступным логам.

## Интерфейс

- В правой части есть блок `Status` (последнее событие раннера).
- В `Status` в реальном времени показывается поток `stdout/stderr` выполняемых шагов
  (то же содержимое пишется в `artifacts/<program>/*.log` и `pmi.txt`).
- Ниже отображается `Module card` с микро-описанием выбранного модуля.
- В `Module card` показываются флаги `Attached` и `Trace`, чтобы видеть состояние модуля.
- В карточке есть простая ASCII-инфографика прогресса (`[###-----]` + проценты).
- Горячие клавиши:
  - `r` — auto pipeline (build→load→trace→test→unload)
  - `b` — только build выбранного модуля
  - `l` — только load/attach выбранного модуля
  - `x` — запустить trace в фоне (manual real-time)
  - `z` — остановить trace
  - `t` — только test выбранного модуля
  - `u` — только unload/detach выбранного модуля
  - `a` — auto для всех модулей
  - `s` — остановить текущий выполняемый шаг
  - `q` — выход

### Ручная проверка заказчиком

Рекомендуемый порядок для каждого модуля:

1. `b` (build)
2. `l` (attach к ядру)
3. `x` (включить trace)
4. В другом окне выполнить свои проверочные действия
5. При необходимости `t` (встроенный test)
6. `z` (остановить trace)
7. `u` (detach)
