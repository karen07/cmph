# CMPH

This repository contains CMPH 2.0.2 with CMake build support and a test harness for minimal perfect hashing.

The upstream CMPH sources live in `cmph-2.0.2/`. The top-level `cmph-test` program downloads a newline-separated key set from a URL, builds a BDZ minimal perfect hash, verifies the input keys, and combines the hash with a 32-bit fingerprint table for non-key probes.

The repository is a maintained build and test wrapper around CMPH rather than a new minimal-perfect-hashing implementation. It provides a repeatable way to build the library, exercise it with a URL-backed key set, and measure random non-key probes.

## Описание

Этот репозиторий содержит CMPH 2.0.2 с поддержкой сборки через CMake и тестовым стендом для минимального совершенного хеширования.

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

## Структура

- `cmph-2.0.2/` - исходники CMPH 2.0.2 с CMake build;
- `src/cmph_test.c` - отдельный test harness;
- `CMakePresets.json` - debug/release presets верхнего проекта.
