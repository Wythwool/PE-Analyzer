from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict
from pathlib import Path

from .model import Report


def write_json(report: Report, path: str | None) -> str:
    text = json.dumps(asdict(report), ensure_ascii=False, indent=2)
    if path:
        write_text(path, text)
    return text


def write_csv(report: Report, path: str) -> None:
    handle = io.StringIO()
    writer = csv.DictWriter(
        handle,
        fieldnames=["file", "rule_id", "severity", "location", "value", "message"],
    )
    writer.writeheader()
    for file in report.files:
        for finding in file.findings:
            writer.writerow(
                {
                    "file": file.path,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "location": finding.location or "",
                    "value": finding.value or "",
                    "message": finding.message,
                }
            )
    write_text(path, handle.getvalue())


def write_markdown(report: Report, path: str) -> None:
    lines = [
        "# PE Analyzer report",
        "",
        f"Created: `{report.tool['created_at']}`",
        "",
        "| Files | Scanned | Errors | Findings | High | Medium | Low |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        (
            f"| {report.summary.files} | {report.summary.scanned} | {report.summary.errors} | "
            f"{report.summary.findings} | {report.summary.high} | {report.summary.medium} | "
            f"{report.summary.low} |"
        ),
        "",
        "| File | Rule | Severity | Location | Value | Message |",
        "|---|---|---|---|---|---|",
    ]
    for file in report.files:
        for finding in file.findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        cell(file.path),
                        f"`{finding.rule_id}`",
                        finding.severity,
                        cell(finding.location or ""),
                        cell(finding.value or ""),
                        cell(finding.message),
                    ]
                )
                + " |"
            )
    write_text(path, "\n".join(lines) + "\n")


def write_html(report: Report, path: str) -> None:
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>PE Analyzer report</title>",
        "<style>body{font-family:system-ui,Segoe UI,sans-serif;margin:2rem}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0}"
        "th,td{border:1px solid #ddd;padding:.45rem;text-align:left}"
        "th{background:#f5f5f5}.high{color:#b00020;font-weight:700}"
        ".medium{color:#8a5a00;font-weight:700}.low{color:#555}</style></head><body>",
        "<h1>PE Analyzer report</h1>",
        f"<p>Created: <code>{escape(report.tool['created_at'])}</code></p>",
        "<table><tr><th>Files</th><th>Scanned</th><th>Errors</th><th>Findings</th>"
        "<th>High</th><th>Medium</th><th>Low</th></tr>",
        (
            f"<tr><td>{report.summary.files}</td><td>{report.summary.scanned}</td>"
            f"<td>{report.summary.errors}</td><td>{report.summary.findings}</td>"
            f"<td>{report.summary.high}</td><td>{report.summary.medium}</td>"
            f"<td>{report.summary.low}</td></tr></table>"
        ),
    ]
    for file in report.files:
        parts.append(f"<h2>{escape(file.path)}</h2>")
        if not file.ok:
            parts.append(f"<p class='high'>{escape(file.error or 'scan failed')}</p>")
            continue
        parts.append(
            f"<p>SHA256: <code>{escape(file.hashes['sha256'])}</code> Size: {file.size} bytes</p>"
        )
        parts.append(
            "<h3>Sections</h3><table><tr><th>Name</th><th>VA</th><th>Raw</th><th>Entropy</th><th>R</th><th>W</th><th>X</th></tr>"
        )
        for section in file.sections:
            parts.append(
                "<tr>"
                f"<td>{escape(section['name'])}</td>"
                f"<td>{escape(section['virtual_address'])}</td>"
                f"<td>{escape(section['raw_size'])}</td>"
                f"<td>{escape(section['entropy'])}</td>"
                f"<td>{yes(section['read'])}</td><td>{yes(section['write'])}</td><td>{yes(section['execute'])}</td>"
                "</tr>"
            )
        parts.append("</table>")
        parts.append(
            "<h3>Findings</h3><table><tr><th>Rule</th><th>Severity</th><th>Location</th><th>Value</th><th>Message</th></tr>"
        )
        for finding in file.findings:
            parts.append(
                f"<tr class='{escape(finding.severity)}'>"
                f"<td>{escape(finding.rule_id)}</td><td>{escape(finding.severity)}</td>"
                f"<td>{escape(finding.location or '')}</td><td>{escape(finding.value or '')}</td>"
                f"<td>{escape(finding.message)}</td></tr>"
            )
        parts.append("</table>")
    parts.append("</body></html>")
    write_text(path, "\n".join(parts))


def write_text(path: str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def escape(value: object) -> str:
    return html.escape(str(value))


def yes(value: object) -> str:
    return "yes" if value else ""
