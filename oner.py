#!/usr/bin/env python3
"""
GL PE Analyzer — компактная и злая утилита для разбора PE.
Печатает всё важное, даёт эвристики, умеет JSON/HTML и YARA. Без воды.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import stat
import struct
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

try:
    import pefile  # type: ignore
except Exception:
    print("[FATAL] pefile is required: pip install pefile", file=sys.stderr)
    raise

try:
    from cryptography.hazmat.primitives.serialization import pkcs7  # type: ignore
except Exception:
    pkcs7 = None  # type: ignore

try:
    import yara  # type: ignore
except Exception:
    yara = None  # type: ignore

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore
except Exception:
    Cs = None  # type: ignore

# === helpers ===

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def sha1(data: bytes) -> str: return hashlib.sha1(data).hexdigest()

def md5(data: bytes) -> str: return hashlib.md5(data).hexdigest()

def calc_entropy(data: bytes) -> float:
    if not data: return 0.0
    cnt = Counter(data); tot = float(len(data))
    return -sum((c/tot) * math.log2(c/tot) for c in cnt.values())

def looks_like_timestamp(ts: int) -> bool:
    try:
        d = dt.datetime.utcfromtimestamp(ts)
        return dt.datetime(1995, 1, 1) <= d <= dt.datetime(2035, 12, 31)
    except Exception:
        return False

SUSPICIOUS_APIS = {
    "VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx",
    "WriteProcessMemory","ReadProcessMemory","CreateRemoteThread",
    "NtAllocateVirtualMemory","NtWriteVirtualMemory","NtProtectVirtualMemory",
    "LoadLibraryA","LoadLibraryW","GetProcAddress","WinExec",
    "CreateProcessA","CreateProcessW","ShellExecuteA","ShellExecuteW",
    "RegSetValueA","RegSetValueW","RegCreateKeyA","RegCreateKeyW",
    "InternetOpenA","InternetOpenW","InternetConnectA","InternetConnectW",
    "WSASocketA","WSASocketW","connect","send","recv",
    "CreateServiceA","CreateServiceW","StartServiceA","StartServiceW",
}

PACKER_HINTS = {".upx",".aspack",".mpress",".petite",".themida",".y0da",".kkrunchy"}

URL_RE  = re.compile(rb"https?://[\w\-\./%\?#=&:]+", re.I)
IP_RE   = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG_RE  = re.compile(rb"HK(?:CR|CU|LM|U|CC)\\[\w\\/_.\-]+", re.I)
FILE_RE = re.compile(rb"[A-Za-z]:\\\\[\w .\\/\-\(\)]+|/\w[\w ./\-\(\)]+")
MUTEX_RE= re.compile(rb"Mutex|Mutant|Global\\|Local\\[\w\-]+", re.I)

# === PE plumbing ===

def read_file(p: str) -> bytes:
    with open(p, 'rb') as f: return f.read()

def overlay_info(pe: pefile.PE, data: bytes) -> Tuple[int, int]:
    last = 0
    for s in getattr(pe, 'sections', []) or []:
        end = s.PointerToRawData + s.SizeOfRawData
        if end > last: last = end
    return (last, len(data)-last) if last and last < len(data) else (-1, 0)

def section_info(s: pefile.SectionStructure) -> Dict[str, Any]:
    name = s.Name.rstrip(b"\x00").decode(errors='replace')
    return {
        "name": name,
        "virt_addr": hex(s.VirtualAddress),
        "virt_size": s.Misc_VirtualSize,
        "raw_ptr": hex(s.PointerToRawData),
        "raw_size": s.SizeOfRawData,
        "entropy": round(calc_entropy(s.get_data()), 3),
        "chars": hex(s.Characteristics),
        "rwx": {
            "R": bool(s.Characteristics & 0x40000000),
            "W": bool(s.Characteristics & 0x80000000),
            "X": bool(s.Characteristics & 0x20000000),
        },
    }

def rich_hash(pe: pefile.PE, data: bytes) -> Optional[str]:
    try:
        rich = pe.parse_rich_header() or {}
        cd = rich.get('clear_data')
        return sha256(cd) if cd else None
    except Exception:
        return None

def imports_summary(pe: pefile.PE) -> Dict[str, Any]:
    out = {"dlls": [], "count": 0, "suspicious": []}
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'): return out
    sus, total = [], 0
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dll = e.dll.decode(errors='ignore') if e.dll else ''
        funs = []
        for i in e.imports:
            nm = i.name.decode(errors='ignore') if i.name else f"ord_{i.ordinal}"
            funs.append(nm)
            if nm in SUSPICIOUS_APIS: sus.append(f"{dll}!{nm}")
        out["dlls"].append({"dll": dll, "functions": funs}); total += len(funs)
    out["count"], out["suspicious"] = total, sorted(sus)
    return out

def exports_summary(pe: pefile.PE) -> Dict[str, Any]:
    out = {"count": 0, "functions": []}
    try:
        if getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None):
            names = [(s.name.decode(errors='ignore') if s.name else f"ord_{s.ordinal}") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            out["count"], out["functions"] = len(names), names
    except Exception: pass
    return out

def tls_callbacks(pe: pefile.PE) -> List[str]:
    # Критично: TLS‑коллбеки часто используют для раннего кода
    try:
        if not getattr(pe, 'DIRECTORY_ENTRY_TLS', None): return []
        oh = pe.OPTIONAL_HEADER
        ptrs_va = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        if not ptrs_va: return []
        ptr_size = 8 if oh.Magic == 0x20B else 4
        data = pe.get_data(ptrs_va - oh.ImageBase, ptr_size * 32)
        out = []
        for i in range(0, len(data), ptr_size):
            chunk = data[i:i+ptr_size]
            if len(chunk) < ptr_size: break
            ptr = struct.unpack('<Q' if ptr_size == 8 else '<I', chunk)[0]
            if not ptr: break
            out.append(hex(ptr))
        return out
    except Exception:
        return []

def version_info(pe: pefile.PE) -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        for fi in getattr(pe, 'FileInfo', []) or []:
            if fi.Key == b'StringFileInfo':
                for st in fi.StringTable:
                    for k, v in st.entries.items():
                        info[k.decode(errors='ignore')] = v.decode(errors='ignore')
    except Exception: pass
    return info

def authenticode_peek(blob: bytes, pe: pefile.PE) -> Dict[str, Any]:
    # Никакой криптопроверки — только метаданные из PKCS#7
    res: Dict[str, Any] = {"present": False}
    try:
        secdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if secdir.Size == 0: return res
        off = secdir.VirtualAddress
        buf = blob[off:off + secdir.Size]
        if len(buf) < 8: return res
        length, rev, ctype = struct.unpack('<IHH', buf[:8])
        cert = buf[8:8+max(0, length-8)]
        res.update({"present": True, "revision": rev, "ctype": ctype, "length": length})
        if pkcs7:
            try:
                pk = pkcs7.load_der_pkcs7_signed_data(cert)
                subs, iss = [], []
                nb, na = None, None
                for c in (pk.certificates or []):
                    try:
                        subs.append(c.subject.rfc4514_string())
                        iss.append(c.issuer.rfc4514_string())
                        if not nb or c.not_valid_before < nb: nb = c.not_valid_before
                        if not na or c.not_valid_after  > na: na = c.not_valid_after
                    except Exception: pass
                res.update({
                    "subjects": list(dict.fromkeys(subs)),
                    "issuers": list(dict.fromkeys(iss)),
                    "validity": {"not_before": nb.isoformat() if nb else None, "not_after": na.isoformat() if na else None},
                })
            except Exception:
                res["pkcs7_parse_error"] = True
        return res
    except Exception:
        return res

def detect_anomalies(pe: pefile.PE, data: bytes) -> List[str]:
    issues: List[str] = []
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    if not looks_like_timestamp(fh.TimeDateStamp): issues.append("Weird compile timestamp")
    try:
        ep = oh.AddressOfEntryPoint
        if ep == 0: issues.append("Zero AddressOfEntryPoint")
        elif not any(s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData) for s in pe.sections):
            issues.append("EP not inside any section")
    except Exception: pass
    names = [s.Name.rstrip(b"\x00").decode(errors='ignore').lower() for s in pe.sections]
    if any(n in PACKER_HINTS for n in names): issues.append("Packer‑ish section name")
    for s in pe.sections:
        e = calc_entropy(s.get_data())
        if e >= 7.2: issues.append(f"High entropy in {s.Name.rstrip(b'\x00').decode(errors='ignore')} ({e:.2f})")
        c = s.Characteristics
        if (c & 0x40000000) and (c & 0x80000000) and (c & 0x20000000): issues.append(f"RWX section {s.Name.rstrip(b'\x00').decode(errors='ignore')}")
        if s.SizeOfRawData == 0 and s.Misc_VirtualSize != 0: issues.append(f"{s.Name.rstrip(b'\x00').decode(errors='ignore')} has VSize but zero RawSize")
    off, size = overlay_info(pe, data)
    if size > 0: issues.append(f"Overlay present ({size} bytes @ 0x{off:X})")
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            cnt = sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)
            if cnt <= 5: issues.append("Very few imports (<=5)")
    except Exception: pass
    return issues

def extract_strings(data: bytes, min_len: int = 4, max_count: int = 2000) -> Dict[str, Any]:
    def ascii_strings(b: bytes, n: int):
        out, cur = [], []
        for x in b:
            if 32 <= x <= 126: cur.append(x)
            else:
                if len(cur) >= n: out.append(bytes(cur))
                cur = []
        if len(cur) >= n: out.append(bytes(cur))
        return out
    def utf16le_strings(b: bytes, n: int):
        out, cur, i = [], [], 0
        while i + 1 < len(b):
            ch, z = b[i], b[i+1]
            if z == 0 and 32 <= ch <= 126: cur.append(ch); i += 2
            else:
                if len(cur) >= n: out.append(bytes(cur))
                cur = []; i += 2
        if len(cur) >= n: out.append(bytes(cur))
        return out
    asc, uni = ascii_strings(data, min_len), utf16le_strings(data, min_len)
    all_s = asc + uni
    urls = [s.decode(errors='ignore') for s in re.findall(URL_RE, data)][:200]
    ips: List[str] = []
    for raw in re.findall(IP_RE, data):
        ip = raw.decode(errors='ignore')
        try: ipaddress.ip_address(ip); ips.append(ip)
        except Exception: pass
    regs  = [s.decode(errors='ignore') for s in re.findall(REG_RE,  data)][:200]
    files = [s.decode(errors='ignore') for s in re.findall(FILE_RE, data)][:200]
    mutex = [s.decode(errors='ignore') for s in re.findall(MUTEX_RE, data)][:200]
    sample = [s.decode(errors='ignore') for s in all_s[:max_count]]
    return {"count": len(all_s), "sample": sample, "urls": urls, "ips": list(dict.fromkeys(ips)), "registry": regs, "files": files, "mutex": mutex}

# === YARA ===

def compile_yara(path: Optional[str]):
    if not path: return None
    if yara is None:
        print("[WARN] yara-python not installed; --yara ignored", file=sys.stderr)
        return None
    try:
        if os.path.isdir(path):
            mp = {}
            for root, _, files in os.walk(path):
                for f in files:
                    if f.lower().endswith((".yar",".yara")):
                        full = os.path.join(root, f)
                        mp[os.path.relpath(full, path).replace(os.sep, '_')] = full
            return yara.compile(filepaths=mp) if mp else None
        return yara.compile(filepath=path)
    except Exception as e:
        print(f"[WARN] YARA compile failed: {e}", file=sys.stderr)
        return None

def yara_scan(rules, data: bytes):
    if not rules: return []
    try:
        matches = rules.match(data=data, timeout=5.0)
        return [{"rule": m.rule, "tags": list(m.tags or []), "namespace": getattr(m, 'namespace', None), "meta": getattr(m, 'meta', {})} for m in matches]
    except Exception as e:
        return [{"error": f"yara match failed: {e}"}]

# === Disasm (EP only, короткая выжимка) ===

def ep_disasm(pe: pefile.PE, data: bytes, max_len: int = 64) -> List[str]:
    try:
        if Cs is None: return []
        oh = pe.OPTIONAL_HEADER
        ep_rva = oh.AddressOfEntryPoint
        off = pe.get_offset_from_rva(ep_rva)
        code = data[off:off+max_len]
        md = Cs(CS_ARCH_X86, CS_MODE_64 if oh.Magic == 0x20B else CS_MODE_32)
        md.detail = False
        out = []
        for i, ins in enumerate(md.disasm(code, oh.ImageBase + ep_rva)):
            if i >= 16: break
            out.append(f"{ins.address:016X}: {ins.mnemonic} {ins.op_str}")
        return out
    except Exception:
        return []

# === Core ===

def analyze_pe(path: str, yara_rules=None, args=None) -> Dict[str, Any]:
    data = read_file(path)
    res: Dict[str, Any] = {"path": path, "size": len(data), "mode": stat.filemode(os.stat(path).st_mode), "hashes": {"md5": md5(data), "sha1": sha1(data), "sha256": sha256(data)}, "ok": False}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        res["error"] = f"Not a PE or parse error: {e}"; return res
    try:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        r_hash = rich_hash(pe, data)
        ov_off, ov_sz = overlay_info(pe, data)
        imps, exps = imports_summary(pe), exports_summary(pe)
        tls = tls_callbacks(pe)
        ver = version_info(pe)
        sign = authenticode_peek(data, pe)
        try: ih = pe.get_imphash()
        except Exception: ih = None
        sections = [section_info(s) for s in pe.sections]
        issues = detect_anomalies(pe, data)
        strs = None if (args and args.no_strings) else extract_strings(data, args.min_string_len, args.max_strings)
        yr = yara_scan(yara_rules, data) if yara_rules else []
        ep = ep_disasm(pe, data)
        res.update({
            "ok": True,
            "pe": {
                "machine": hex(fh.Machine),
                "timedatestamp": int(fh.TimeDateStamp),
                "timestamp_iso": dt.datetime.utcfromtimestamp(fh.TimeDateStamp).isoformat() if looks_like_timestamp(fh.TimeDateStamp) else None,
                "characteristics": hex(fh.Characteristics),
                "imagebase": hex(getattr(oh, 'ImageBase', 0)),
                "entrypoint_rva": hex(getattr(oh, 'AddressOfEntryPoint', 0)),
                "subsystem": getattr(oh, 'Subsystem', None),
                "dll_characteristics": hex(getattr(oh, 'DllCharacteristics', 0)),
                "sizeofimage": getattr(oh, 'SizeOfImage', None),
                "magic": hex(getattr(oh, 'Magic', 0)),
            },
            "sections": sections,
            "imports": imps,
            "exports": exps,
            "tls_callbacks": tls,
            "version_info": ver,
            "signature": sign,
            "rich_hash": r_hash,
            "imphash": ih,
            "overlay": {"offset": ov_off, "size": ov_sz},
            "anomalies": issues,
            "strings": strs,
            "yara_matches": yr,
            "ep_disasm": ep,
        })
    finally:
        try: pe.close()
        except Exception: pass
    return res

# === HTML ===

def to_html(results: List[Dict[str, Any]]) -> str:
    def esc(x: Any) -> str: return html.escape(str(x))
    def table(rows: List[List[Any]]) -> str:
        out = ["<table>"]
        for i, r in enumerate(rows):
            tag = "th" if i == 0 else "td"
            out.append("<tr>" + ''.join(f"<{tag}>{esc(c)}</{tag}>" for c in r) + "</tr>")
        out.append("</table>")
        return '\n'.join(out)
    parts = [
        "<html><head><meta charset='utf-8'><title>GL PE Analyzer report</title>",
        "<style>body{font-family:ui-monospace,Consolas,Menlo,monospace;padding:16px;background:#0b0b0b;color:#ddd;}h1,h2{color:#fff}table{border-collapse:collapse;margin:10px 0;width:100%;}th,td{border:1px solid #333;padding:6px 8px;}th{background:#151515}code{background:#151515;padding:2px 4px;border-radius:4px}.ok{color:#6ee7b7}.bad{color:#f87171}.sec{margin-bottom:12px;padding:8px;border:1px solid #222;border-radius:8px;background:#0f0f0f}</style></head><body>",
        "<h1>GL PE Analyzer</h1>",
    ]
    for r in results:
        parts.append("<div class='sec'>")
        parts.append(f"<h2>{esc(r.get('path'))}</h2>")
        ok = r.get('ok')
        parts.append(f"<p>Status: <b class='{ 'ok' if ok else 'bad'}'>{'OK' if ok else 'ERROR'}</b> • Size: {r.get('size')} bytes • SHA256: <code>{esc(r['hashes']['sha256'])}</code></p>")
        if not ok:
            parts.append(f"<p class='bad'>{esc(r.get('error'))}</p>"); parts.append("</div>"); continue
        peh = r["pe"]
        parts.append(table([["ImageBase","EntryPoint","Timestamp","Subsystem","Magic"],[peh.get('imagebase'), peh.get('entrypoint_rva'), peh.get('timestamp_iso'), peh.get('subsystem'), peh.get('magic')]]))
        rows = [["Name","VA","VSize","RawPtr","RawSize","Entropy","R","W","X"]]
        for s in r.get('sections', []):
            rows.append([s['name'], s['virt_addr'], s['virt_size'], s['raw_ptr'], s['raw_size'], s['entropy'],'1' if s['rwx']['R'] else '', '1' if s['rwx']['W'] else '', '1' if s['rwx']['X'] else ''])
        parts.append("<h3>Sections</h3>" + table(rows))
        imp = r.get('imports', {})
        parts.append(f"<h3>Imports (total {imp.get('count',0)})</h3>")
        if imp.get('suspicious'): parts.append("<p><b>Suspicious APIs:</b> " + ', '.join(map(esc, imp['suspicious'])) + "</p>")
        for d in imp.get('dlls', [])[:50]:
            parts.append("<details><summary>" + esc(d['dll']) + f" ({len(d['functions'])})</summary><code>" + esc(', '.join(d['functions'][:200])) + "</code></details>")
        exp = r.get('exports', {})
        parts.append(f"<h3>Exports (total {exp.get('count',0)})</h3>")
        if exp.get('functions'): parts.append("<code>" + esc(', '.join(exp['functions'][:200])) + "</code>")
        sig = r.get('signature', {})
        parts.append("<h3>Authenticode</h3>")
        if sig.get('present'):
            parts.append("<p>Present. length=" + esc(sig.get('length')) + ", ctype=" + esc(sig.get('ctype')) + "</p>")
            subs = sig.get('subjects') or []
            if subs: parts.append("<p><b>Subjects:</b> " + ', '.join(map(esc, subs[:5])) + "</p>")
            if sig.get('validity'):
                v = sig['validity']; parts.append(f"<p>NotBefore: {esc(v.get('not_before'))} • NotAfter: {esc(v.get('not_after'))}</p>")
        else:
            parts.append("<p>Not present.</p>")
        parts.append("<h3>Meta</h3>" + table([["RichHash","ImpHash","OverlayOffset","OverlaySize"],[r.get('rich_hash'), r.get('imphash'), r.get('overlay',{}).get('offset'), r.get('overlay',{}).get('size')]]))
        if r.get('ep_disasm'): parts.append("<h3>Entry Point (disasm)</h3><pre>" + esc('\n'.join(r['ep_disasm'])) + "</pre>")
        if r.get('anomalies'): parts.append("<h3>Heuristics / Anomalies</h3><ul>" + ''.join(f"<li>{esc(x)}</li>" for x in r['anomalies']) + "</ul>")
        if r.get('yara_matches'): parts.append("<h3>YARA</h3><ul>" + ''.join(f"<li>{esc(m.get('rule'))} — tags: {esc(m.get('tags'))}</li>" for m in r['yara_matches']) + "</ul>")
        strs = r.get('strings') or {}
        if strs:
            parts.append(f"<h3>Strings (sample {min(200,len(strs.get('sample',[])))}/{html.escape(str(strs.get('count')))} )</h3>")
            parts.append("<details><summary>Sample</summary><pre>" + esc('\n'.join(strs.get('sample', [])[:200])) + "</pre></details>")
            if strs.get('urls'): parts.append("<details open><summary>URLs</summary><pre>" + esc('\n'.join(strs['urls'])) + "</pre></details>")
            if strs.get('ips'): parts.append("<details><summary>IPs</summary><pre>" + esc('\n'.join(strs['ips'])) + "</pre></details>")
            if strs.get('registry'): parts.append("<details><summary>Registry</summary><pre>" + esc('\n'.join(strs['registry'])) + "</pre></details>")
            if strs.get('files'): parts.append("<details><summary>File paths</summary><pre>" + esc('\n'.join(strs['files'])) + "</pre></details>")
            if strs.get('mutex'): parts.append("<details><summary>Mutex-like</summary><pre>" + esc('\n'.join(strs['mutex'])) + "</pre></details>")
        parts.append("</div>")
    parts.append("</body></html>")
    return '\n'.join(parts)

# === CLI ===

def walk_targets(paths: List[str], recursive: bool) -> List[str]:
    pool: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files: pool.append(os.path.join(root, f))
                if not recursive: break
        else:
            pool.append(p)
    picked: List[str] = []
    for fp in pool:
        try:
            with open(fp, 'rb') as f:
                sig = f.read(2)
                if sig == b'MZ' or fp.lower().endswith(('.exe','.dll','.sys','.ocx','.cpl')):
                    picked.append(fp)
        except Exception: pass
    return sorted(set(picked))

def parse_args(argv: Optional[List[str]] = None):
    ap = argparse.ArgumentParser(description="GL PE Analyzer — no‑nonsense PE introspection")
    ap.add_argument('targets', nargs='+', help='Files or directories to analyze')
    ap.add_argument('-r','--recursive', action='store_true', help='Recurse into directories')
    ap.add_argument('--json-out', help='Save JSON report to file')
    ap.add_argument('--html-out', help='Save HTML report to file')
    ap.add_argument('--yara', help='YARA rules file or directory (optional)')
    ap.add_argument('--min-string-len', type=int, default=4, help='Minimal string length (ASCII/UTF-16)')
    ap.add_argument('--max-strings', type=int, default=2000, help='Max strings to keep in sample')
    ap.add_argument('--no-strings', action='store_true', help='Disable strings extraction')
    return ap.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    yr = compile_yara(args.yara)
    files = walk_targets(args.targets, args.recursive)
    if not files:
        print("[!] No PE‑like files found."); return 1
    results = []
    for fp in files:
        try:
            r = analyze_pe(fp, yara_rules=yr, args=args)
            results.append(r)
            if not r.get('ok'):
                print(f"[ERR] {fp}: {r.get('error')}"); continue
            peh, ov = r['pe'], r.get('overlay', {})
            print(f"[OK] {fp} • EP {peh.get('entrypoint_rva')} • {len(r.get('sections',[]))} sec • imports {r['imports']['count']} • overlay {ov.get('size',0)}B")
            if r.get('anomalies'): print("      anomalies: " + '; '.join(r['anomalies']))
            if r['imports'].get('suspicious'): print("      suspicious APIs: " + ', '.join(r['imports']['suspicious'][:10]))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[ERR] {fp}: {e}")
    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f: json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[+] JSON saved: {args.json_out}")
    if args.html_out:
        html_doc = to_html(results)
        with open(args.html_out, 'w', encoding='utf-8') as f: f.write(html_doc)
        print(f"[+] HTML saved: {args.html_out}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
