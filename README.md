# PE Analyzer

`pe-analyzer` is an offline Windows Portable Executable triage tool. It reads PE files as bytes, extracts structured metadata, highlights common anomalies, and writes analyst-friendly reports.

## Features

- DOS/NT header and section summaries
- MD5, SHA1, SHA256, imphash, Rich header hash when present
- imports, suspicious imports, exports, resources, data directories
- Authenticode certificate table presence and hash
- overlay detection and hashing
- ASCII and UTF-16LE strings with URL, IP, registry path, file path, and mutex-like filters
- optional YARA rule matching when `yara-python` is installed
- heuristic findings for RWX sections, high entropy, weird timestamps, entrypoint issues, overlays, few imports, unsigned files, and packer-like section names
- JSON, HTML, CSV, and Markdown output

The tool does not execute target files.

## Install

```bash
python -m pip install -e .[dev]
```

Optional YARA support:

```bash
python -m pip install -e .[yara]
```

## Usage

```bash
pe-analyzer scan sample.exe
pe-analyzer scan ./binaries -r --json-out report.json --html-out report.html
pe-analyzer scan sample.exe --csv-out findings.csv --md-out report.md
pe-analyzer scan sample.exe --yara rules/
```

Backward-compatible wrapper:

```bash
python oner.py sample.exe
```

Use `--fail-on high`, `--fail-on medium`, or `--fail-on low` to return exit code `3` when matching findings exist.

## Tests

```bash
ruff check .
ruff format --check .
pytest -q
python -m build
```

The tests generate a synthetic PE fixture and verify parser output, report writers, directory scanning, wrapper compatibility, and fail-on behavior.
