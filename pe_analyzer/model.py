from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    location: str | None = None
    value: str | None = None


@dataclass
class FileReport:
    path: str
    size: int
    ok: bool
    hashes: dict[str, str]
    error: str | None = None
    pe: dict[str, Any] = field(default_factory=dict)
    sections: list[dict[str, Any]] = field(default_factory=list)
    data_directories: list[dict[str, Any]] = field(default_factory=list)
    imports: dict[str, Any] = field(default_factory=dict)
    exports: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    signature: dict[str, Any] = field(default_factory=dict)
    overlay: dict[str, Any] = field(default_factory=dict)
    strings: dict[str, Any] | None = None
    yara: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class Summary:
    files: int
    scanned: int
    errors: int
    findings: int
    high: int
    medium: int
    low: int

    def meets(self, threshold: str) -> bool:
        if threshold == "high":
            return self.high > 0
        if threshold == "medium":
            return self.high + self.medium > 0
        if threshold == "low":
            return self.findings > 0
        return False


@dataclass(frozen=True)
class Report:
    tool: dict[str, str]
    summary: Summary
    files: list[FileReport]
