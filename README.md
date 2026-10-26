# CMPH

CMPH 2.0.2 with CMake build support and a test harness for minimal perfect hashing. The
harness builds and checks a BDZ hash over a downloaded set of keys.

## Описание

CMPH 2.0.2 с поддержкой сборки через CMake и тестовым стендом для минимального совершенного
хеширования. Стенд строит и проверяет BDZ-хеш на скачанном наборе ключей.

Исходный код CMPH находится в `cmph-2.0.2/`. Верхнеуровневая программа `cmph-test` загружает по URL набор ключей по одному на строку, строит минимальную совершенную хеш-функцию BDZ, проверяет входные ключи и дополняет хеш 32-битной таблицей отпечатков для запросов по ключам, которых нет в исходном наборе.

Репозиторий является поддерживаемой оболочкой для сборки и тестирования CMPH, а не новой реализацией минимального совершенного хеширования. Он дает воспроизводимый способ собрать библиотеку, проверить ее на наборе ключей, загружаемом по URL, и выполнить случайные проверки отсутствующих ключей.

## Сборка

Нужны CMake и libcurl development files.

```sh
cmake --preset release
cmake --build --preset release
```

Основной тестовый бинарник:

```text
build/release/cmph-test
```

Вместе с ним CMake также собирает библиотеку CMPH и upstream tests/examples из `cmph-2.0.2/`.

## Тестовый стенд

```sh
./build/release/cmph-test <url> [--rand M]
```

`<url>` должен возвращать набор ключей по одному на строку. Программа:

1. скачивает список через libcurl;
1. строит BDZ minimal perfect hash;
1. создает 32-bit fingerprint table;
1. проверяет все исходные ключи;
1. выполняет случайные проверки отсутствующих ключей.

`--rand M` задает объем случайных probes, используемых для оценки false-positive rate fingerprint-слоя.

## Структура проекта

- `cmph-2.0.2/` - исходники CMPH 2.0.2 с CMake build;
- `src/cmph_test.c` - отдельный test harness;
- `CMakePresets.json` - debug/release presets верхнего проекта.
