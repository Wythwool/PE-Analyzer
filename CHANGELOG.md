# Changelog

## Unreleased

## [0.2.0] - 2026-07-06
- Reworked the broken single-file MVP into an installable Python package.
- Added `pe-analyzer scan` with backward-compatible `python oner.py target.exe` usage.
- Added JSON, HTML, CSV, and Markdown reports.
- Added PE header, section, data directory, import, export, resource, signature, overlay, string, and optional YARA summaries.
- Added heuristic findings for weird timestamps, entrypoint issues, RWX sections, high entropy, overlays, suspicious imports, few imports, unsigned files, and large resource trees.
- Added synthetic PE fixture tests and CI on Windows/Linux.
