from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

from pe_analyzer.analyzer import AnalyzerOptions, analyze_many, analyze_one, discover_targets
from pe_analyzer.reports import write_csv, write_html, write_json, write_markdown


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def section_header(
    name: bytes,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_pointer: int,
    characteristics: int,
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\0"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        characteristics,
    )


def make_pe(path: Path) -> None:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_raw = 0x200
    data_raw = 0x400
    text = b"\xc3" + b"\x90" * 15
    text = text.ljust(file_alignment, b"\0")
    data = (
        b"https://example.test/payload\0"
        b"C:\\Windows\\Temp\\dropper.exe\0"
        b"Global\\DemoMutex\0" + b"A" * 90
    )
    data = data.ljust(file_alignment, b"\0")

    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,
        2,
        0,
        0,
        0,
        0xE0,
        0x010F,
    )
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        len(text),
        len(data),
        0,
        0x1000,
        0x1000,
        0x2000,
        0x400000,
        section_alignment,
        file_alignment,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,
        headers_size,
        0,
        3,
        0x8540,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional += b"\0" * (16 * 8)
    assert len(optional) == 0xE0

    sections = b"".join(
        [
            section_header(b".text", len(text), 0x1000, len(text), text_raw, 0x60000020),
            section_header(b".data", len(data), 0x2000, len(data), data_raw, 0xE0000040),
        ]
    )
    headers = bytes(dos) + b"PE\0\0" + file_header + optional + sections
    image = bytearray(headers_size + len(text) + len(data))
    image[: len(headers)] = headers
    image[text_raw : text_raw + len(text)] = text
    image[data_raw : data_raw + len(data)] = data
    image += b"OVERLAY-DATA"
    path.write_bytes(image)


def test_analyze_synthetic_pe(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    make_pe(sample)

    report = analyze_one(str(sample), AnalyzerOptions())
    rules = {finding.rule_id for finding in report.findings}

    assert report.ok
    assert report.pe["entrypoint_rva"] == "0x1000"
    assert report.overlay["present"] is True
    assert report.strings is not None
    assert "https://example.test/payload" in report.strings["urls"]
    assert "rwx_section" in rules
    assert "overlay_present" in rules
    assert "timestamp_weird" in rules


def test_reports_and_directory_discovery(tmp_path: Path) -> None:
    sample = tmp_path / "nested" / "sample.exe"
    sample.parent.mkdir()
    make_pe(sample)

    found = discover_targets([str(tmp_path)], recursive=True)
    assert found == [str(sample)]

    report = analyze_many(found, AnalyzerOptions())
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    csv_path = tmp_path / "findings.csv"
    md_path = tmp_path / "report.md"
    write_json(report, str(json_path))
    write_html(report, str(html_path))
    write_csv(report, str(csv_path))
    write_markdown(report, str(md_path))

    assert json.loads(json_path.read_text())["summary"]["files"] == 1
    assert "rwx_section" in csv_path.read_text()
    assert "<html" in html_path.read_text().lower()
    assert "| Files |" in md_path.read_text()


def test_cli_and_wrapper(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    make_pe(sample)
    json_path = tmp_path / "out.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pe_analyzer",
            "scan",
            str(sample),
            "--json-out",
            str(json_path),
            "--fail-on",
            "high",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 3
    assert json.loads(json_path.read_text())["summary"]["high"] >= 1

    wrapper = subprocess.run(
        [sys.executable, "oner.py", str(sample)],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(wrapper.stdout)["summary"]["files"] == 1
