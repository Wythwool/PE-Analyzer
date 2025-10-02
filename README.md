# GL PE Analyzer

**GL PE Analyzer** — мощный инструмент для анализа PE-файлов (Windows Portable Executable).

## Возможности

* Полный дамп заголовков и секций, выявление аномалий (RWX, нулевой raw size, high entropy, невалидные timestamp'ы).
* Подсчёт хэшей: **MD5/SHA1/SHA256**, а также **imphash**, Rich Header hash, размер overlay.
* Анализ импортов/экспортов, ресурсов и TLS callbacks.
* Эвристики: подозрительные API, секции пакеров, редкие импорты.
* Извлечение строк (ASCII/UTF‑16), фильтрация URL, IP, путей реестра, файловых путей, mutex‑подобных строк.
* Анализ подписи (Authenticode): извлечение subjects/issuers, валидность.
* Поддержка YARA‑правил.
* Вывод: консоль, JSON и HTML отчёт.

## Установка

```bash
pip install pefile cryptography capstone yara-python
```

## Использование

Анализ одного файла:

```bash
python gl_pe_analyzer.py sample.exe
```

Рекурсивный анализ директории:

```bash
python gl_pe_analyzer.py ./binaries -r --json-out report.json --html-out report.html
```

Применение YARA:

```bash
python gl_pe_analyzer.py sample.exe --yara rules/
```

## Аргументы

* `-r, --recursive` — анализ директорий рекурсивно.
* `--json-out` — сохранить JSON отчёт.
* `--html-out` — сохранить HTML отчёт.
* `--yara` — путь к файлу или директории с YARA‑правилами.
* `--min-string-len` — минимальная длина строки (по умолчанию 4).
* `--max-strings` — максимальное количество сохраняемых строк (по умолчанию 2000).
* `--no-strings` — отключить извлечение строк.

## Примеры

Анализ и вывод отчёта:

```bash
python gl_pe_analyzer.py malware.dll --html-out analysis.html --json-out analysis.json
```

## Лицензия

MIT. Использовать только в образовательных и исследовательских целях.
