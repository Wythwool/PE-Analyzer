from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

from . import __version__
from .model import FileReport, Finding, Report, Summary

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yara = None  # type: ignore


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
    "ShellExecuteA",
    "ShellExecuteW",
    "RegSetValueA",
    "RegSetValueW",
    "RegCreateKeyA",
    "RegCreateKeyW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "WSASocketA",
    "WSASocketW",
    "connect",
    "send",
    "recv",
    "CreateServiceA",
    "CreateServiceW",
    "StartServiceA",
    "StartServiceW",
}

PACKER_SECTION_NAMES = {
    ".upx",
    ".aspack",
    ".mpress",
    ".petite",
    ".themida",
    ".y0da",
    ".kkrunchy",
}

URL_RE = re.compile(rb"https?://[\w\-./%?#=&:]+", re.I)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG_RE = re.compile(rb"HK(?:CR|CU|LM|U|CC)\\[\w\\/_.\-]+", re.I)
FILE_RE = re.compile(rb"[A-Za-z]:\\\\[\w .\\/\-()]+|/\w[\w ./\-()]+")
MUTEX_RE = re.compile(rb"(?:Global\\|Local\\)?[A-Za-z0-9_.-]{8,}Mutex[A-Za-z0-9_.-]*", re.I)


class AnalyzerOptions:
    def __init__(
        self,
        *,
        min_string_len: int = 4,
        max_strings: int = 2000,
        strings: bool = True,
        yara_path: str | None = None,
    ) -> None:
        self.min_string_len = min_string_len
        self.max_strings = max_strings
        self.strings = strings
        self.yara_path = yara_path


def analyze_many(paths: list[str], options: AnalyzerOptions) -> Report:
    rules = compile_yara(options.yara_path)
    files = [analyze_one(path, options, rules) for path in paths]
    findings = [finding for file in files for finding in file.findings]
    summary = Summary(
        files=len(files),
        scanned=sum(1 for file in files if file.ok),
        errors=sum(1 for file in files if not file.ok),
        findings=len(findings),
        high=sum(1 for finding in findings if finding.severity == "high"),
        medium=sum(1 for finding in findings if finding.severity == "medium"),
        low=sum(1 for finding in findings if finding.severity == "low"),
    )
    return Report(
        tool={
            "name": "pe-analyzer",
            "version": __version__,
            "created_at": dt.datetime.now(dt.UTC).isoformat(),
        },
        summary=summary,
        files=files,
    )


def analyze_one(path: str, options: AnalyzerOptions, yara_rules: Any = None) -> FileReport:
    file_path = Path(path)
    data = file_path.read_bytes()
    report = FileReport(
        path=str(file_path),
        size=len(data),
        ok=False,
        hashes={
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    )

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:
        report.error = f"PE parse failed: {exc}"
        report.findings.append(Finding("parse_error", "low", report.error))
        return report

    try:
        report.ok = True
        report.pe = pe_header(pe)
        report.sections = [section_info(section) for section in pe.sections]
        report.data_directories = data_directories(pe)
        report.imports = imports(pe)
        report.exports = exports(pe)
        report.resources = resources(pe)
        report.signature = signature(pe, data)
        report.overlay = overlay(pe, data)
        report.yara = yara_scan(yara_rules, data)
        if options.strings:
            report.strings = strings(data, options.min_string_len, options.max_strings)
        report.findings.extend(findings(pe, report))
    finally:
        pe.close()

    return report


def pe_header(pe: pefile.PE) -> dict[str, Any]:
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    timestamp = file_header.TimeDateStamp
    return {
        "machine": hex(file_header.Machine),
        "timestamp": timestamp,
        "timestamp_utc": timestamp_iso(timestamp),
        "characteristics": hex(file_header.Characteristics),
        "image_base": hex(optional.ImageBase),
        "entrypoint_rva": hex(optional.AddressOfEntryPoint),
        "subsystem": optional.Subsystem,
        "magic": hex(optional.Magic),
        "size_of_image": optional.SizeOfImage,
        "size_of_headers": optional.SizeOfHeaders,
        "dll_characteristics": hex(getattr(optional, "DllCharacteristics", 0)),
        "imphash": safe_call(lambda: pe.get_imphash()),
        "rich_sha256": rich_sha256(pe),
    }


def section_info(section: pefile.SectionStructure) -> dict[str, Any]:
    data = section.get_data()
    characteristics = section.Characteristics
    return {
        "name": clean_name(section.Name),
        "virtual_address": hex(section.VirtualAddress),
        "virtual_size": section.Misc_VirtualSize,
        "raw_pointer": hex(section.PointerToRawData),
        "raw_size": section.SizeOfRawData,
        "entropy": round(entropy(data), 3),
        "characteristics": hex(characteristics),
        "read": bool(characteristics & 0x40000000),
        "write": bool(characteristics & 0x80000000),
        "execute": bool(characteristics & 0x20000000),
    }


def data_directories(pe: pefile.PE) -> list[dict[str, Any]]:
    names = pefile.DIRECTORY_ENTRY
    by_index = {value: key for key, value in names.items()}
    output = []
    for index, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        if directory.VirtualAddress or directory.Size:
            output.append(
                {
                    "index": index,
                    "name": by_index.get(index, f"DIR_{index}"),
                    "rva": hex(directory.VirtualAddress),
                    "size": directory.Size,
                }
            )
    return output


def imports(pe: pefile.PE) -> dict[str, Any]:
    output: dict[str, Any] = {"dlls": [], "count": 0, "suspicious": []}
    suspicious = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return output

    total = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = decode_bytes(entry.dll)
        functions = []
        for imported in entry.imports:
            name = decode_bytes(imported.name) if imported.name else f"ord_{imported.ordinal}"
            functions.append(name)
            total += 1
            if name in SUSPICIOUS_APIS:
                suspicious.append(f"{dll}!{name}")
        output["dlls"].append({"dll": dll, "functions": functions})

    output["count"] = total
    output["suspicious"] = sorted(set(suspicious))
    return output


def exports(pe: pefile.PE) -> dict[str, Any]:
    output: dict[str, Any] = {"count": 0, "functions": []}
    entry = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not entry:
        return output
    functions = [
        decode_bytes(symbol.name) if symbol.name else f"ord_{symbol.ordinal}"
        for symbol in entry.symbols
    ]
    output["count"] = len(functions)
    output["functions"] = functions
    return output


def resources(pe: pefile.PE) -> dict[str, Any]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return {"count": 0, "types": []}

    names = []
    count = 0
    for entry in root.entries:
        count += resource_count(entry)
        names.append(resource_name(entry))
    return {"count": count, "types": sorted(set(names))}


def signature(pe: pefile.PE, data: bytes) -> dict[str, Any]:
    security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
    if directory.Size == 0:
        return {"present": False}

    offset = directory.VirtualAddress
    size = directory.Size
    cert = data[offset : offset + size]
    return {
        "present": True,
        "offset": hex(offset),
        "size": size,
        "sha256": hashlib.sha256(cert).hexdigest() if cert else None,
    }


def overlay(pe: pefile.PE, data: bytes) -> dict[str, Any]:
    start = pe.get_overlay_data_start_offset()
    if start is None or start >= len(data):
        return {"present": False, "offset": None, "size": 0, "sha256": None}
    blob = data[start:]
    return {
        "present": True,
        "offset": hex(start),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def strings(data: bytes, min_len: int, max_count: int) -> dict[str, Any]:
    ascii_values = ascii_strings(data, min_len)
    utf16_values = utf16le_strings(data, min_len)
    decoded = [value.decode(errors="ignore") for value in ascii_values + utf16_values]
    ips = []
    for raw in IP_RE.findall(data):
        value = raw.decode(errors="ignore")
        try:
            ipaddress.ip_address(value)
            ips.append(value)
        except ValueError:
            pass

    return {
        "count": len(decoded),
        "sample": decoded[:max_count],
        "urls": unique_decode(URL_RE.findall(data)),
        "ips": sorted(set(ips)),
        "registry": unique_decode(REG_RE.findall(data)),
        "files": unique_decode(FILE_RE.findall(data)),
        "mutex": unique_decode(MUTEX_RE.findall(data)),
    }


def findings(pe: pefile.PE, report: FileReport) -> list[Finding]:
    found: list[Finding] = []
    header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    entrypoint = optional.AddressOfEntryPoint

    if not plausible_timestamp(header.TimeDateStamp):
        found.append(
            Finding("timestamp_weird", "low", "Compile timestamp is outside the normal range")
        )

    if entrypoint == 0:
        found.append(Finding("entrypoint_zero", "medium", "AddressOfEntryPoint is zero"))
    elif not any(section_contains(section, entrypoint) for section in pe.sections):
        found.append(
            Finding("entrypoint_outside_sections", "high", "Entry point is not inside any section")
        )

    for section in report.sections:
        name = str(section["name"]).lower()
        if name in PACKER_SECTION_NAMES:
            found.append(Finding("packer_section_name", "medium", "Packer-like section name", name))
        if section["read"] and section["write"] and section["execute"]:
            found.append(
                Finding(
                    "rwx_section", "high", "Section is readable, writable, and executable", name
                )
            )
        if section["raw_size"] == 0 and section["virtual_size"] > 0:
            found.append(
                Finding(
                    "virtual_only_section",
                    "medium",
                    "Section has virtual size but no raw data",
                    name,
                )
            )
        if float(section["entropy"]) >= 7.2:
            found.append(
                Finding(
                    "high_entropy_section",
                    "medium",
                    "Section entropy is high",
                    name,
                    str(section["entropy"]),
                )
            )

    if report.overlay.get("present"):
        found.append(
            Finding(
                "overlay_present",
                "low",
                "File has overlay data",
                value=str(report.overlay.get("size")),
            )
        )

    suspicious_imports = report.imports.get("suspicious", [])
    for item in suspicious_imports:
        found.append(Finding("suspicious_import", "medium", "Suspicious imported API", value=item))

    if report.imports.get("count", 0) <= 5:
        found.append(Finding("few_imports", "low", "File imports very few APIs"))

    if report.signature.get("present") is False:
        found.append(Finding("unsigned", "low", "Authenticode signature is not present"))

    if report.resources.get("count", 0) > 100:
        found.append(Finding("many_resources", "low", "File has an unusually large resource tree"))

    return found


def discover_targets(targets: list[str], recursive: bool) -> list[str]:
    files: list[str] = []
    for target in targets:
        path = Path(target)
        if path.is_file():
            files.append(str(path))
            continue
        if not path.is_dir():
            continue
        iterator = path.rglob("*") if recursive else path.glob("*")
        files.extend(str(candidate) for candidate in iterator if candidate.is_file())

    selected = []
    for file in sorted(set(files), key=str.lower):
        if is_pe_like(file):
            selected.append(file)
    return selected


def is_pe_like(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def compile_yara(path: str | None) -> Any:
    if not path or yara is None:
        return None

    source = Path(path)
    try:
        if source.is_dir():
            filepaths = {
                str(rule.relative_to(source)).replace(os.sep, "_"): str(rule)
                for rule in source.rglob("*")
                if rule.suffix.lower() in {".yar", ".yara"}
            }
            return yara.compile(filepaths=filepaths) if filepaths else None
        return yara.compile(filepath=str(source))
    except Exception:
        return None


def yara_scan(rules: Any, data: bytes) -> list[dict[str, Any]]:
    if rules is None:
        return []
    try:
        matches = rules.match(data=data, timeout=5.0)
    except Exception as exc:
        return [{"error": str(exc)}]
    return [
        {"rule": match.rule, "tags": list(match.tags), "meta": dict(match.meta)}
        for match in matches
    ]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def plausible_timestamp(value: int) -> bool:
    try:
        stamp = dt.datetime.fromtimestamp(value, dt.UTC)
    except (OverflowError, OSError, ValueError):
        return False
    return (
        dt.datetime(1995, 1, 1, tzinfo=dt.UTC) <= stamp <= dt.datetime(2035, 12, 31, tzinfo=dt.UTC)
    )


def timestamp_iso(value: int) -> str | None:
    if not plausible_timestamp(value):
        return None
    return dt.datetime.fromtimestamp(value, dt.UTC).isoformat()


def section_contains(section: pefile.SectionStructure, rva: int) -> bool:
    size = max(section.Misc_VirtualSize, section.SizeOfRawData)
    return section.VirtualAddress <= rva < section.VirtualAddress + size


def ascii_strings(data: bytes, min_len: int) -> list[bytes]:
    output: list[bytes] = []
    current = bytearray()
    for value in data:
        if 32 <= value <= 126:
            current.append(value)
            continue
        if len(current) >= min_len:
            output.append(bytes(current))
        current.clear()
    if len(current) >= min_len:
        output.append(bytes(current))
    return output


def utf16le_strings(data: bytes, min_len: int) -> list[bytes]:
    output: list[bytes] = []
    current = bytearray()
    for index in range(0, len(data) - 1, 2):
        value = data[index]
        zero = data[index + 1]
        if zero == 0 and 32 <= value <= 126:
            current.append(value)
            continue
        if len(current) >= min_len:
            output.append(bytes(current))
        current.clear()
    if len(current) >= min_len:
        output.append(bytes(current))
    return output


def unique_decode(values: list[bytes]) -> list[str]:
    return sorted({value.decode(errors="ignore") for value in values})


def rich_sha256(pe: pefile.PE) -> str | None:
    try:
        rich = pe.parse_rich_header() or {}
        clear_data = rich.get("clear_data")
        return hashlib.sha256(clear_data).hexdigest() if clear_data else None
    except Exception:
        return None


def resource_count(entry: Any) -> int:
    directory = getattr(entry, "directory", None)
    if directory is None:
        return 1
    return sum(resource_count(child) for child in directory.entries)


def resource_name(entry: Any) -> str:
    if entry.name is not None:
        return str(entry.name)
    return str(entry.struct.Id)


def clean_name(value: bytes) -> str:
    return value.rstrip(b"\x00").decode(errors="replace")


def decode_bytes(value: bytes | None) -> str:
    return value.decode(errors="replace") if value else ""


def safe_call(func: Any) -> Any:
    try:
        return func()
    except Exception:
        return None
