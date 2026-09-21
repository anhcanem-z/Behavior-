# -*- coding: utf-8 -*-
"""smart_scanner — nâng cấp công cụ quét chuỗi trong .rodata/.data của file
.so/.elf (ELF32/64) theo 4 trụ cột:

  1. Lọc nhiễu thông minh (Smart Noise Filtering):
       Phân loại NGỮ NGHĨA từng chuỗi (endpoint, api_key, token, cipher,
       header, domain, log, comment, sample, symbol, library...) thay vì chỉ
       regex — tự phân biệt chuỗi nhạy cảm thật với chuỗi log/comment/dữ liệu
       mẫu; mỗi kết luận kèm lý do (reason).

  2. Phân tích luồng dữ liệu tĩnh (Static Data-flow Analysis):
       Truy vết tham chiếu từ vùng mã (.text) tới chuỗi trong .rodata/.data
       bằng ADRP+ADD (ARM64), LDR literal pool (ARM64), LEA RIP-relative
       (x86_64), mov imm64 (x86_64) hoặc quét địa chỉ tuyệt đối; gắn từng
       tham chiếu vào hàm chứa nó (symbol table) — phát hiện chuỗi bị ghép/
       encode động khi một hàm tham chiếu nhiều chuỗi + opcode xor/encode.

  3. Xác thực chéo offset (Cross-validation):
       Với mỗi offset nghi vấn, kiểm tra ngữ cảnh caller/callee qua đồ thị
       gọi (BL/CALL) + symbol table; đối chiếu với danh sách hàm hệ thống/
       compiler (std::, __cxa_*, _GLOBAL__sub_I, hàm thư viện C...) để loại
       cảnh báo giả (false positive) — báo cáo số FP đã loại.

  4. Trọng số rủi ro (Risk-based Weighting) + Confidence Score:
       Chuỗi chứa param động, tên miền lạ, header đặc biệt hoặc được JNI
       tham chiếu được cộng điểm; kết quả tổng hợp thành Confidence 0-100%
       kèm danh sách EVIDENCE cho từng finding + thông tin tái tạo (repro:
       sha256 file, tham số quét, thời gian) — 100% dữ liệu có bằng chứng.

Chạy:
    python3 patchx smart-scan FILE.SO
    python3 -m patchx_core.behavior.smart_scanner FILE.SO -o out.json

Chuỗi trong mã nguồn / tên file giữ nguyên gốc.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import struct
import tempfile
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .rodata_patcher import ElfReader, StringHit, RODATA_HINTS, SHF_ALLOC
from .smart_ontology import match_smart_behavior, get_behavior

TOOL_NAME = "patchx smart-scanner"
TOOL_VERSION = "1.0.0"

EM_ARM64 = 183
EM_X86_64 = 62

SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHN_UNDEF = 0
STT_FUNC = 2

PRINTABLE_RE = re.compile(rb"[ -~]{4,}")

# ---- nhóm danh mục ----
NOISE_CATEGORIES = {"log", "comment", "sample", "symbol", "library"}
FORMAT_CATEGORIES = {"format", "path", "domain", "other"}
SENSITIVE_CATEGORIES = {
    "private_key", "secret", "api_key", "token", "cipher",
    "endpoint", "header", "domain", "format", "path", "other",
}

BASE_RISK: Dict[str, int] = {
    "private_key": 98,
    "secret": 92,
    "api_key": 88,
    "token": 85,
    "cipher": 75,
    "endpoint": 72,
    "header": 60,
    "class": 35,
    "domain": 55,
    "format": 42,
    "path": 30,
    "other": 30,
    "symbol": 12,
    "library": 8,
    "log": 5,
    "comment": 2,
    "sample": 2,
}

# ---- mẫu tín hiệu nhạy cảm (kết hợp regex + ngữ nghĩa) ----
SIGNAL_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("aws_access_key", "api_key",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", "api_key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github_token", "token",
     re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,255}\b")),
    ("jwt", "token",
     re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("private_key", "private_key",
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("stripe_key", "api_key",
     re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("slack_token", "token",
     re.compile(r"\bxox[baprs]\-[0-9A-Za-z\-]{10,}\b")),
    ("bearer_token", "token",
     re.compile(r"\bBearer [A-Za-z0-9\-._~+/]+=*")),
]

PATH_PREFIXES = ("/", "./", "../", "res/", "assets/", "file:",
                 "out/", "src/", "build/", "external/", "frameworks/",
                 "vendor/", "system/", "kernel/", "bionic/", "dalvik/",
                 "art/", "android/", "com/", "org/")

KNOWN_HEADERS = {
    "authorization", "content-type", "accept", "user-agent",
    "accept-encoding", "accept-language", "cookie", "set-cookie",
    "host", "origin", "referer", "x-requested-with", "x-forwarded-for",
    "x-real-ip", "x-request-id", "x-csrf-token", "x-auth-token",
    "x-access-token", "api-key", "x-api-key", "bearer", "basic",
    "cache-control", "content-length", "content-encoding", "pragma",
    "connection", "upgrade", "sec-websocket-key", "sec-websocket-accept",
}

# ---- chuỗi runtime C++ / thư viện hệ thống ----
LIBRARY_MSG_RE = re.compile(
    r"(?:std::|map::at|vector::|basic_string|string::|set::|unordered_map::|"
    r"bad_alloc|length_error|out_of_range|logic_error|runtime_error|"
    r"what\(\)|__cxa_|_ZNKSt|_ZNSt|GCC:|GNU C\+\+|"
    r"libunwind|DWARF|DW_CFA_|DW_EH_|eh_frame|cxxabi|itanium_demangle|"
    r"type_info|assembler-arm|shrinkToSize|decltype|typename|"
    r"__float128|__int128|unsigned short|unsigned long long|imaginary|"
    r"funcrel pointer|not supported|search table|malformed DW_|"
    r"unsupported \.eh_frame)"
)

SYSTEM_FUNC_MARKERS = (
    "std::", "_ZN", "_ZNK", "__cxa_", "_GLOBAL__sub_I", "_GLOBAL__D_",
    "operator new", "operator delete", "__aeabi", "__android_log",
    "pthread_", "dlopen", "dlsym", "atexit", "abort", "exit",
    "_Unwind_", "main",
)

SAMPLE_MARKERS = (
    "example.com", "test", "sample", "dummy", "placeholder", "lorem",
    "localhost", "127.0.0.1", "192.168.", "10.0.0.", "123456", "password123",
    "changeme", "foo", "bar", "asdf", "qwerty", "testkey", "test_token",
    "test-api", "demo", "TODO", "FIXME",
)

# URL nằm trong thông báo lỗi/tài liệu/báo cáo lỗi của thư viện nguồn mở.
# Không phải endpoint giao tiếp thật của ứng dụng.
BENIGN_URL_MARKERS = (
    "bug report", "mailing list", "upload a sample", "contact the",
    "please submit", "gcc.gnu.org", "videolan.org", "ffmpeg-devel",
    "ffmpeg.org", "sourceware.org", "w3.org", "schema.org", "apache.org",
    "github.com", "gitlab.com",
)

LOG_MARKERS = (
    "[INFO]", "[DEBUG]", "[WARN]", "[ERROR]", "[TRACE]", "DEBUG:",
    "ERROR:", "WARNING:", "INFO:", "TRACE:", "warning:", "error:",
    "debug:", "info:", "logcat", "Log.", "LOGTAG", "thread:", "timeout",
    "failed", "success", "exception", "stacktrace", "StackTrace",
)

COMMENT_MARKERS = ("//", "/*", "*/", "#", ";", "TODO", "FIXME", "copyright",
                   "(c)", "license", "author", "@author", "@param",
                   "@return", "http://www.", "https://www.")

JNI_CLASS_RE = re.compile(
    r"^(?:[a-z][a-z0-9]{0,15}/)+[A-Z][a-zA-Z0-9_$]*$")


def _sign_extend(value: int, bits: int) -> int:
    """Mở rộng dấu số nguyên bits-bit."""
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def shannon_entropy(value: str) -> float:
    """Entropy Shannon (bits/char) — cao khi chuỗi giống mã hóa/ngẫu nhiên."""
    if not value:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for ch in value:
        counts[ch] += 1
    n = len(value)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def _has_dynamic_params(value: str) -> bool:
    """Phát hiện param động: %s/%d, {0}/{} placeholder, $var/${...}, \n..."""
    if re.search(r"%(?:[0-9$*]*[sdifxXeEgGc%])", value):
        return True
    if re.search(r"\{[0-9]+\}|(^|[^\{])\{\}|\\\{\{|\\\{\$", value):
        return True
    if re.search(r"\\\$\\\{?[A-Za-z_][A-Za-z0-9_]*|\\\$\([A-Za-z_]", value):
        return True
    if "\\n" in value or "\\t" in value or "\\r" in value:
        return True
    if re.search(r"\\d\{2,4\}|\\d\{1,3\}", value):
        return True
    return False


def _looks_like_header(value: str) -> bool:
    name = value.split(":", 1)[0].strip().lower()
    if name in KNOWN_HEADERS:
        return True
    if value.lower().startswith(("authorization", "x-api-key", "bearer ",
                                 "x-auth", "x-access")):
        return True
    return False


def _looks_like_symbol(value: str) -> bool:
    if len(value) > 200:
        return False
    if " " in value:
        return False
    if value.startswith(("_Z", "_ZN", "_ZNK", "_GLOBAL", "__cxa", "Java_")):
        return True
    if re.match(r"^N(?:St|S[0-9_])", value):
        return True
    if re.match(r"^N[0-9]+[A-Za-z0-9_]+E?$", value):
        return True
    if "itanium_demangle" in value or "__cxxabi" in value or "type_info" in value:
        return True
    if "::" in value or "$$" in value:
        return True
    if re.fullmatch(r"\.?[A-Za-z0-9_.@$]+", value) and len(value) >= 8:
        if value.startswith(".") or value.endswith(("@GLIBC", "@CXXABI")):
            return True
        if "_" in value and value[0].islower() and len(value) > 12:
            return True
    return False


def classify_string(value: str, section: str = "") -> Tuple[str, bool, str, List[str]]:
    """Phân loại ngữ nghĩa chuỗi -> (category, is_noise, reason, signals).

    Ưu tiên: tín hiệu regex nhạy cảm -> private key/secret -> URL/endpoint ->
    header -> chuỗi thư viện/symbol -> cipher (entropy) -> log -> comment ->
    sample -> format -> path -> other.
    """
    signals: List[str] = []
    v = value.strip()
    low = v.lower()

    for sig, cat, pat in SIGNAL_PATTERNS:
        if pat.search(v):
            return cat, False, "Khớp tín hiệu %s" % sig, [sig]

    if re.search(r"-----BEGIN|PRIVATE KEY|BEGIN RSA|BEGIN EC", v):
        return "private_key", False, "Khối khóa riêng (PEM)", ["private_key"]

    # Basic auth base64 — yêu cầu token chứa chữ số hoặc +/= (tránh false
    # positive như "Basic Animated Texture Profile")
    m = re.search(r"\bBasic ([A-Za-z0-9+/=]{8,})", v)
    if m and re.search(r"[0-9+/=]", m.group(1)):
        return "secret", False, "Basic auth base64", ["basic_auth"]

    # URL nằm trong câu thông báo lỗi/tài liệu -> nhiễu, không phải endpoint thật.
    if any(marker in low for marker in BENIGN_URL_MARKERS):
        return "log", True, "URL trong thông báo lỗi/tài liệu", ["benign_url"]

    # endpoint / domain / URL
    if re.search(r"://", v) or low.startswith(("http://", "https://")):
        if re.search(r"/[A-Za-z0-9_\-%.\?&=+]{2,}", v.split("://", 1)[-1]):
            signals.append("url_path")
        return ("endpoint", False,
                "URL endpoint (có scheme + đường dẫn)", signals)

    # header đặc biệt
    if _looks_like_header(v):
        return "header", False, "Header HTTP/đặc biệt", ["header"]

    # descriptor tên lớp JNI (FindClass/GetFieldID) — com/org/android/...
    if JNI_CLASS_RE.match(v):
        return "class", False, "Tên lớp JNI (descriptor)", ["class"]

    # đường dẫn tập tin (kiểm tra TRƯỚC cipher — đường dẫn build entropy cao)
    if v.startswith(PATH_PREFIXES):
        return "path", False, "Đường dẫn tập tin", ["path"]

    # chuỗi runtime C++ / thư viện hệ thống
    if LIBRARY_MSG_RE.search(v):
        return "library", True, "Chuỗi runtime C++/thư viện hệ thống", ["library"]

    # symbol (tên hàm/biến mã hóa)
    if _looks_like_symbol(v):
        return "symbol", True, "Tên symbol (hàm/biến mã hóa C++)", ["symbol"]

    # cipher/encoded: entropy cao + dài + charset base64/hex
    ent = shannon_entropy(v)
    if (len(v) >= 16 and ent >= 4.2
            and re.fullmatch(r"[A-Za-z0-9+/=_\-\.]+", v)):
        ratio_alnum = sum(1 for ch in v if ch.isalnum()) / len(v)
        if ratio_alnum >= 0.75:
            return "cipher", False, "Entropy cao (%.2f bits/char) — nghi mã hóa/token" % ent, ["cipher"]

    # log
    if any(m in low for m in LOG_MARKERS) or re.search(r"\[\w+\]", v):
        return "log", True, "Chuỗi log/debug", ["log"]

    # comment
    if any(m in v for m in COMMENT_MARKERS):
        return "comment", True, "Chuỗi chú thích/tài liệu", ["comment"]

    # sample/test
    if any(m in low for m in SAMPLE_MARKERS):
        return "sample", True, "Dữ liệu mẫu/test", ["sample"]

    # format có param động
    if _has_dynamic_params(v):
        return "format", False, "Chuỗi định dạng có param động", ["dynamic"]

    return "other", False, "Chuỗi khác", []


def enumerate_strings(reader: ElfReader, min_len: int = 6,
                      hints: Optional[Tuple[str, ...]] = None,
                      native: Optional[bool] = None,
                      engine_info: Optional[Dict[str, Any]] = None) -> List[StringHit]:
    """Trích mọi chuỗi ASCII in được trong các section .rodata/.data.

    Mặc định quét section có tên chứa rodata/data.rel.ro/.data (bỏ .dynstr/
    .strtab — đó là tên symbol, thuộc nhóm nhiễu symbol riêng).
    """
    if hints is None:
        hints = ("rodata", "data.rel.ro", ".data")
    hits: List[StringHit] = []
    for idx, sec in enumerate(reader.sections):
        name = reader.section_name(idx)
        if not (sec["flags"] & SHF_ALLOC):
            continue
        if not any(h in name for h in hints):
            continue
        if name in (".bss",):
            continue
        raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
        # Đường NEON: quét dải byte [0x20, 0x7E] bằng kernel C.
        # Lỗi biên dịch/nạp sẽ tự rơi về biểu thức chính quy Python (kết quả như nhau).
        runs: Optional[List[Tuple[int, int]]] = None
        if native is not False:
            try:
                from ..neon_scan import find_runs_native
                runs = find_runs_native(raw, 0x20, 0x7E, 4)
                if engine_info is not None:
                    engine_info["native"] = True
            except Exception as exc:  # noqa: BLE001
                if engine_info is not None:
                    engine_info["native"] = False
                    engine_info["error"] = str(exc)
                runs = None

        if runs is not None:
            for off, rlen in runs:
                value = raw[off:off + rlen].decode("ascii", "replace").strip()
                if len(value) < min_len:
                    continue
                hits.append(StringHit(
                    file_offset=sec["offset"] + off,
                    rva=sec["addr"] + off,
                    section=name, value=value,
                    size=rlen + 1, source="section",
                ))
        else:
            for m in PRINTABLE_RE.finditer(raw):
                value = m.group(0).decode("ascii", "replace").strip()
                if len(value) < min_len:
                    continue
                file_off = sec["offset"] + m.start()
                rva = sec["addr"] + m.start()
                hits.append(StringHit(
                    file_offset=file_off, rva=rva, section=name,
                    value=value, size=len(value) + 1, source="section",
                ))
    hits.sort(key=lambda h: (h.rva, h.file_offset))
    return hits


# =====================================================================
# 2. STATIC DATA-FLOW: symbol table + tham chiếu mã -> chuỗi
# =====================================================================

def _section_bytes(reader: ElfReader, idx: int) -> bytes:
    sec = reader.sections[idx]
    return reader.data[sec["offset"]:sec["offset"] + sec["size"]]


def _read_strtab_entry(reader: ElfReader, strtab: bytes, off: int) -> str:
    if off < 0 or off >= len(strtab):
        return ""
    end = strtab.find(b"\x00", off)
    if end < 0:
        end = len(strtab)
    return strtab[off:end].decode("utf-8", "replace")


def parse_symbols(reader: ElfReader) -> List[Dict[str, Any]]:
    """Parse .symtab/.dynsym -> symbol định nghĩa (FUNC/OBJECT) kèm dải địa chỉ."""
    syms: List[Dict[str, Any]] = []
    for idx, sec in enumerate(reader.sections):
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        entsize = sec["entsize"] or (24 if reader.is64 else 16)
        if entsize <= 0:
            continue
        strtab = _section_bytes(reader, sec["link"]) if 0 <= sec["link"] < len(reader.sections) else b""
        for off in range(sec["offset"], sec["offset"] + sec["size"], entsize):
            raw = reader.data[off:off + entsize]
            if len(raw) < entsize:
                break
            if reader.is64:
                (st_name, st_info, _st_other, st_shndx,
                 st_value, st_size) = struct.unpack(reader.endian + "IBBHQQ", raw[:24])
            else:
                (st_name, st_value, st_size, st_info,
                 _st_other, st_shndx) = struct.unpack(reader.endian + "IIIIBB", raw[:16])
            if st_shndx == SHN_UNDEF or st_value == 0:
                continue
            name = _read_strtab_entry(reader, strtab, st_name)
            if not name:
                continue
            kind = st_info & 0xF
            bind = st_info >> 4
            if kind not in (STT_FUNC, 0):
                continue
            syms.append({
                "name": name,
                "value": st_value,
                "size": st_size,
                "type": kind,
                "bind": bind,
                "section": st_shndx,
            })
    return syms


def _text_sections(reader: ElfReader) -> List[Dict[str, Any]]:
    """Các section thực thi (chứa mã) — nguồn để truy vết tham chiếu."""
    out = []
    for idx, sec in enumerate(reader.sections):
        if (sec["type"] == 1 and sec["flags"] & SHF_ALLOC
                and sec["flags"] & 0x4):  # SHF_EXECINSTR
            out.append({"index": idx, "name": reader.section_name(idx),
                        "addr": sec["addr"], "offset": sec["offset"],
                        "size": sec["size"]})
    return out


def _data_sections(reader: ElfReader) -> List[Dict[str, Any]]:
    """Section dữ liệu thật (ALLOC, không thực thi, tên data/rodata) — chỉ
    đích hợp lệ của tham chiếu chuỗi. KHÔNG gồm .dynstr/.strtab/.dynamic/
    .got (ô con trỏ) — tránh lẫn vùng mã như .text khi nằm xen dải địa chỉ."""
    out: List[Dict[str, Any]] = []
    for idx, sec in enumerate(reader.sections):
        name = reader.section_name(idx)
        if not (sec["flags"] & SHF_ALLOC):
            continue
        if sec["flags"] & 0x4:  # SHF_EXECINSTR
            continue
        if not (any(h in name for h in ("rodata", "data.rel.ro", ".data"))):
            continue
        out.append({"index": idx, "name": name, "addr": sec["addr"],
                    "offset": sec["offset"], "size": sec["size"]})
    return out


def _data_ranges(reader: ElfReader) -> List[Tuple[int, int, str]]:
    """Dải địa chỉ .rodata/.data — mục tiêu hợp lệ của tham chiếu."""
    return [(s["addr"], s["addr"] + s["size"], s["name"])
            for s in _data_sections(reader)]


def _data_target(reader: ElfReader, rva: int) -> Optional[Tuple[str, int]]:
    """Kiểm tra rva có nằm trong section dữ liệu thật không.
    Trả (tên section, file offset) hoặc None."""
    for s in _data_sections(reader):
        if s["addr"] <= rva < s["addr"] + s["size"]:
            return s["name"], s["offset"] + (rva - s["addr"])
    return None


def _pointer_slot(reader: ElfReader, rva: int) -> Optional[int]:
    """Nếu rva nằm trong .got/.got.plt/.data.rel.ro — trả file offset ô con trỏ."""
    for idx, sec in enumerate(reader.sections):
        name = reader.section_name(idx)
        if not (sec["flags"] & SHF_ALLOC):
            continue
        if "got" not in name and name != ".data.rel.ro":
            continue
        if sec["addr"] <= rva < sec["addr"] + sec["size"]:
            return sec["offset"] + (rva - sec["addr"])
    return None


def _resolve_ptr(reader: ElfReader, file_off: int) -> Optional[int]:
    """Đọc con trỏ 4/8 byte tại file offset -> giá trị địa chỉ (None nếu lỗi)."""
    wsize = 8 if reader.is64 else 4
    fmt = "<Q" if reader.is64 else "<I"
    if file_off is None or file_off < 0 or file_off + wsize > len(reader.data):
        return None
    return struct.unpack_from(fmt, reader.data, file_off)[0]


def _scan_arm64_refs(reader: ElfReader, sec: Dict[str, Any],
                     lo: int, hi: int) -> List[Dict[str, Any]]:
    """Truy vết ARM64: ADRP+ADD (thẳng) và LDR literal (qua literal pool)."""
    raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
    base = sec["addr"]
    refs: List[Dict[str, Any]] = []
    n = len(raw)
    i = 0
    while i + 4 <= n:
        b3 = raw[i + 3]
        insn = struct.unpack_from("<I", raw, i)[0]
        # ADRP
        if b3 & 0x1F == 0x10 and insn & 0x9F000000 == 0x90000000:
            immhi = (insn >> 5) & 0x7FFFF
            immlo = (insn >> 29) & 0x3
            # ADRP: imm 21-bit tính theo ĐƠN VỊ TRANG (4KB) — phải dịch << 12
            imm = _sign_extend((immhi << 2) | immlo, 21) << 12
            page = (base + i) & ~0xFFF
            target_page = page + imm
            rd = insn & 0x1F
            # tìm ADD xN, xN, #imm kế tiếp (cùng thanh ghi) trong 8 lệnh
            for j in range(i + 4, min(i + 4 * 9, n - 3), 4):
                jinsn = struct.unpack_from("<I", raw, j)[0]
                if (jinsn & 0xFF000000) == 0x91000000 and ((jinsn >> 5) & 0x1F) == rd:
                    imm12 = (jinsn >> 10) & 0xFFF
                    if jinsn & (1 << 22):
                        imm12 <<= 12
                    target = target_page + imm12
                    _emit_arm64_target(reader, refs, "adrp_add", base + i,
                                       sec["offset"] + i, target, lo, hi)
                    break
            i += 4
            continue
        # LDR (literal) Xt
        if b3 == 0x58 and insn & 0xFF000000 == 0x58000000:
            imm19 = (insn >> 5) & 0x7FFFF
            off = _sign_extend(imm19 << 2, 21)
            pool_rva = base + i + off
            try:
                foff, _name = reader.rva_to_file_offset(pool_rva)
            except ValueError:
                foff = -1
            if foff >= 0 and foff + 8 <= len(reader.data):
                val = struct.unpack_from("<Q", reader.data, foff)[0]
                if _data_target(reader, val):
                    refs.append({
                        "kind": "ldr_literal", "ref_rva": base + i,
                        "ref_offset": sec["offset"] + i, "target_rva": val,
                    })
            i += 4
            continue
        i += 4
    return refs


def _emit_arm64_target(reader: ElfReader, refs: List[Dict[str, Any]],
                       kind: str, ref_rva: int, ref_offset: int,
                       target: int, lo: int, hi: int) -> None:
    """Ghi ref khi target rơi vào dữ liệu; nếu rơi vào ô con trỏ (GOT/
    data.rel.ro) thì đọc con trỏ rồi ghi ref gián tiếp (adrp_add_got)."""
    if _data_target(reader, target):
        refs.append({"kind": kind, "ref_rva": ref_rva,
                     "ref_offset": ref_offset, "target_rva": target})
        return
    if not (lo <= target < hi):
        return
    got_off = _pointer_slot(reader, target)
    val = _resolve_ptr(reader, got_off)
    if val is not None and _data_target(reader, val):
        refs.append({"kind": kind + "_got", "ref_rva": ref_rva,
                     "ref_offset": ref_offset, "target_rva": val})


def _scan_x86_64_refs(reader: ElfReader, sec: Dict[str, Any],
                      lo: int, hi: int) -> List[Dict[str, Any]]:
    """Truy vết x86_64: LEA RIP-relative và mov r64, imm64."""
    raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
    base = sec["addr"]
    refs: List[Dict[str, Any]] = []
    n = len(raw)
    i = 0
    while i + 7 <= n:
        b0, b1, modrm = raw[i], raw[i + 1], raw[i + 2]
        # LEA r64, [rip+disp32]: REX.W + 0x8D + modrm mod=00 rm=101
        if b0 in (0x48, 0x4C, 0x49, 0x4D) and b1 == 0x8D and (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", raw, i + 3)[0]
            target = base + i + 7 + disp
            if _data_target(reader, target):
                refs.append({
                    "kind": "lea_rip", "ref_rva": base + i,
                    "ref_offset": sec["offset"] + i, "target_rva": target,
                })
            elif lo <= target < hi:
                got_off = _pointer_slot(reader, target)
                val = _resolve_ptr(reader, got_off)
                if val is not None and _data_target(reader, val):
                    refs.append({
                        "kind": "lea_rip_got", "ref_rva": base + i,
                        "ref_offset": sec["offset"] + i, "target_rva": val,
                    })
            i += 1
            continue
        # mov r64, imm64: 48 B8 + imm64
        if b0 == 0x48 and b1 == 0xB8:
            val = struct.unpack_from("<Q", raw, i + 2)[0]
            if lo <= val < hi:
                refs.append({
                    "kind": "mov_imm64", "ref_rva": base + i,
                    "ref_offset": sec["offset"] + i, "target_rva": val,
                })
            i += 1
            continue
        i += 1
    return refs


def _scan_absolute_refs(reader: ElfReader, sec: Dict[str, Any],
                        lo: int, hi: int) -> List[Dict[str, Any]]:
    """Quét địa chỉ tuyệt đối 4/8 byte trong mã (fallback ARM32/misc)."""
    raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
    base = sec["addr"]
    refs: List[Dict[str, Any]] = []
    wsize = 8 if reader.is64 else 4
    fmt = "<Q" if reader.is64 else "<I"
    for i in range(0, len(raw) - wsize + 1, 4):
        val = struct.unpack_from(fmt, raw, i)[0]
        if lo <= val < hi:
            refs.append({
                "kind": "absolute", "ref_rva": base + i,
                "ref_offset": sec["offset"] + i, "target_rva": val,
            })
    return refs


def scan_code_refs(reader: ElfReader) -> List[Dict[str, Any]]:
    """Truy vết mọi tham chiếu từ mã tới .rodata/.data theo kiến trúc ELF."""
    ranges = _data_ranges(reader)
    if not ranges:
        return []
    lo = min(r[0] for r in ranges)
    hi = max(r[1] for r in ranges)
    refs: List[Dict[str, Any]] = []
    for sec in _text_sections(reader):
        if reader.e_machine == EM_ARM64:
            refs.extend(_scan_arm64_refs(reader, sec, lo, hi))
        elif reader.e_machine == EM_X86_64:
            refs.extend(_scan_x86_64_refs(reader, sec, lo, hi))
        else:
            refs.extend(_scan_absolute_refs(reader, sec, lo, hi))
    refs.sort(key=lambda r: r["ref_rva"])
    return refs


def _symbols_by_range(symbols: List[Dict[str, Any]]) -> List[Tuple[int, int, str]]:
    """Dải [start, end) cho từng symbol hàm — symbol size=0 lấy biên tới symbol
    kế tiếp cùng section (lib stripped thường để size=0)."""
    syms = [s for s in symbols if s["value"] > 0]
    syms.sort(key=lambda s: (s["value"], s["size"]))
    out: List[Tuple[int, int, str]] = []
    for i, s in enumerate(syms):
        start = s["value"]
        if s["size"] > 0:
            end = start + s["size"]
        else:
            nxt = None
            for s2 in syms[i + 1:]:
                if s2["value"] > start and s2["section"] == s["section"]:
                    nxt = s2["value"]
                    break
            end = nxt if nxt is not None else start + 0x40
        if end <= start:
            end = start + 1
        out.append((start, end, s["name"]))
    return out


def _func_of(rva: int, ranges: List[Tuple[int, int, str]]) -> Optional[str]:
    for start, end, name in ranges:
        if start <= rva < end:
            return name
    return None


def _scan_calls(reader: ElfReader, text_secs: List[Dict[str, Any]],
                ranges: List[Tuple[int, int, str]]) -> List[Tuple[str, str]]:
    """Đồ thị gọi thô (caller -> callee) bằng BL (ARM64) / CALL rel32 (x86)."""
    calls: List[Tuple[str, str]] = []
    if reader.e_machine == EM_ARM64:
        for sec in text_secs:
            raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
            for i in range(0, len(raw) - 3, 4):
                insn = struct.unpack_from("<I", raw, i)[0]
                if insn & 0xFC000000 == 0x94000000:
                    imm26 = insn & 0x3FFFFFF
                    off = _sign_extend(imm26 << 2, 28)
                    target = sec["addr"] + i + off
                    caller = _func_of(sec["addr"] + i, ranges)
                    callee = _func_of(target, ranges)
                    if caller and callee and caller != callee:
                        calls.append((caller, callee))
    elif reader.e_machine == EM_X86_64:
        for sec in text_secs:
            raw = reader.data[sec["offset"]:sec["offset"] + sec["size"]]
            for i in range(len(raw) - 4):
                if raw[i] == 0xE8:
                    rel = struct.unpack_from("<i", raw, i + 1)[0]
                    target = sec["addr"] + i + 5 + rel
                    caller = _func_of(sec["addr"] + i, ranges)
                    callee = _func_of(target, ranges)
                    if caller and callee and caller != callee:
                        calls.append((caller, callee))
    return calls


def _jni_reachable(reader: ElfReader, symbols: List[Dict[str, Any]],
                   text_secs: List[Dict[str, Any]]) -> Set[str]:
    """Tập hàm chạm tới được từ entry JNI (Java_* / JNI_OnLoad) qua đồ thị gọi."""
    ranges = _symbols_by_range(symbols)
    calls = _scan_calls(reader, text_secs, ranges)
    graph: Dict[str, Set[str]] = defaultdict(set)
    for caller, callee in calls:
        graph[caller].add(callee)
    jni = {s["name"] for s in symbols if is_jni_func(s["name"])}
    reachable: Set[str] = set()
    stack = list(jni)
    while stack:
        f = stack.pop()
        if f in reachable:
            continue
        reachable.add(f)
        stack.extend(graph.get(f, ()))
    return reachable


def _is_system_context(func_name: Optional[str]) -> bool:
    if not func_name:
        return False
    return any(m in func_name for m in SYSTEM_FUNC_MARKERS)


def is_jni_func(func_name: Optional[str]) -> bool:
    """Nhận diện hàm JNI: tên Java_* / JNI_OnLoad, hoặc tên C++ mangled
    chứa tham số _JNIEnv (vd _ZN7lsplant2v24InitEP7_JNIEnvRKNS0_8InitInfoE)."""
    if not func_name:
        return False
    if func_name.startswith("Java_") or func_name in ("JNI_OnLoad", "JNI_OnUnload"):
        return True
    if any(m in func_name for m in ("P7_JNIEnv", "PN7_JNIEnv", "PSt14_JNIEnv")):
        return True
    return False


# =====================================================================
# 3b. NÂNG CẤP T4 (2026-09-19): phân tích bảng JNINativeMethod (RegisterNatives)
# Trên cùng nền parse_symbols + ElfReader đã có; không thêm module mới.
# =====================================================================

JAVA_ID_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,250}$")
JNI_SIG_RE = re.compile(r"^\(.*\)[VZBCSIJFD\[L]$")
PF_X = 0x1
PT_LOAD = 1


def _segment_regions(reader: ElfReader) -> List[Tuple[int, int, int]]:
    """Các dải (offset, end, flags) theo PT_LOAD; thiếu thì suy từ section."""
    out = [(seg["offset"], seg["offset"] + seg["filesz"], seg["flags"])
           for seg in reader.segments]
    if not out:
        out = [(sec["offset"], sec["offset"] + sec["size"], sec["flags"])
               for sec in reader.sections if sec["type"] == PT_LOAD]
    return out


def _in_exec_region(reader: ElfReader, file_off: int) -> bool:
    for off, end, flags in _segment_regions(reader):
        if off <= file_off < end and flags & PF_X:
            return True
    for sec in reader.sections:
        if (sec["flags"] & 0x4 and sec["offset"] <= file_off
                < sec["offset"] + sec["size"]):
            return True
    return False


def _read_utf8_cstr(reader: ElfReader, file_off: Optional[int],
                    limit: int = 256) -> Optional[str]:
    if file_off is None or file_off < 0 or file_off >= len(reader.data):
        return None
    end = reader.data.find(b"\x00", file_off, file_off + limit)
    if end < 0:
        end = min(len(reader.data), file_off + limit)
    try:
        return bytes(reader.data[file_off:end]).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _safe_rva_to_off(reader: ElfReader, rva: int) -> Optional[int]:
    try:
        return reader.rva_to_file_offset(rva)[0]
    except (ValueError, TypeError):
        return None


def scan_register_natives(reader: ElfReader) -> Dict[str, Any]:
    """Phân tích bảng JNINativeMethod: bộ ba con trỏ (tên, chữ ký, con trỏ hàm).

    Xác thực chéo: tên phải là định danh Java hợp lệ, chữ ký phải đúng mẫu
    mô tả JNI, con trỏ hàm phải trỏ vào vùng mã thực thi.
    """
    psize = 8 if reader.is64 else 4
    fmt = reader.endian + ("Q" if reader.is64 else "I")
    data = reader.data
    regions = _segment_regions(reader)
    has_register = any(s["name"] == "RegisterNatives"
                       for s in parse_symbols(reader))
    entries: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for off, end, flags in regions:
        if off <= 0 or flags & PF_X:
            continue
        for i in range(off, end - 3 * psize + 1, psize):
            if i in seen:
                continue
            seen.add(i)
            try:
                name_rva = struct.unpack_from(fmt, data, i)[0]
                sig_rva = struct.unpack_from(fmt, data, i + psize)[0]
                fn_rva = struct.unpack_from(fmt, data, i + 2 * psize)[0]
            except struct.error:
                continue
            if not (name_rva and sig_rva and fn_rva):
                continue
            name_off = _safe_rva_to_off(reader, name_rva)
            sig_off = _safe_rva_to_off(reader, sig_rva)
            fn_off = _safe_rva_to_off(reader, fn_rva)
            name = _read_utf8_cstr(reader, name_off)
            sig = _read_utf8_cstr(reader, sig_off, limit=128)
            if not name or not JAVA_ID_RE.match(name):
                continue
            if not sig or not JNI_SIG_RE.match(sig):
                continue
            if fn_off is None or not _in_exec_region(reader, fn_off):
                continue
            entries.append({
                "table_offset": i,
                "name": name,
                "signature": sig,
                "name_rva": name_rva,
                "signature_rva": sig_rva,
                "fn_rva": fn_rva,
                "fn_offset": fn_off,
            })
    return {
        "has_register_natives_symbol": has_register,
        "arch": "64" if reader.is64 else "32",
        "pointer_size": psize,
        "entries": entries,
        "count": len(entries),
    }


def render_frida_for_natives(rep: Dict[str, Any],
                             module_name: str = "MODULE") -> str:
    """Sinh kịch bản Frida hook theo RVA chính xác của từng hàm JNI."""
    lines = [
        "// Sinh tự động bởi patchx smart-scan --jni (T4 RegisterNatives)",
        "const MODULE = \"%s\";" % module_name,
        "const BASE = Module.findBaseAddress(MODULE);",
        "if (!BASE) throw new Error('không nạp được ' + MODULE);",
        "",
    ]
    for e in rep.get("entries", []):
        lines += [
            "// %s %s (bảng @ 0x%x)" % (e["name"], e["signature"], e["table_offset"]),
            "Interceptor.attach(BASE.add(0x%x), {" % e["fn_rva"],
            "  onEnter(args) { console.log('[JNI] %s(' + args[2] + ')'); }," % e["name"],
            "});",
            "",
        ]
    return "\n".join(lines)


def rewrite_native_fnptr(path: str | Path, table_offset: int,
                         new_rva: int, entry_index: int = 0,
                         backup_dir: Optional[str | Path] = None,
                         dry_run: bool = True) -> Dict[str, Any]:
    """Đổi con trỏ hàm JNI (fnPtr) tại bảng RegisterNatives — zero-drift.

    Chỉ ghi đè đúng một ô con trỏ (8/4 byte) tại offset đã xác định; giữ nguyên
    kích thước tệp; có sao lưu khi ghi thật. Không tự chọn mục tiêu — người
    dùng phải chỉ rõ new_rva.
    """
    reader = ElfReader(path)
    psize = 8 if reader.is64 else 4
    fmt = reader.endian + ("Q" if reader.is64 else "I")
    fn_off = table_offset + 2 * psize + entry_index * 3 * psize
    if fn_off + psize > len(reader.data):
        raise ValueError("Vị trí con trỏ hàm ngoài tệp: 0x%x" % fn_off)
    _ = _safe_rva_to_off(reader, new_rva)  # xác thực new_rva nằm trong vùng ánh xạ
    old_rva = struct.unpack_from(fmt, reader.data, fn_off)[0]
    rep = {"path": str(reader.path), "fnptr_offset": fn_off,
           "old_rva": old_rva, "new_rva": new_rva, "dry_run": dry_run}
    if old_rva == new_rva:
        rep["changed"] = False
        return rep
    if dry_run:
        rep["changed"] = True
        return rep
    fp = reader.path
    original = fp.read_bytes()
    data = bytearray(original)
    struct.pack_into(fmt, data, fn_off, new_rva)
    if backup_dir is not None:
        bdir = Path(backup_dir)
        bdir.mkdir(parents=True, exist_ok=True)
        bak = bdir / (fp.name + ".bak")
        if not bak.exists():
            bak.write_bytes(original)
    fp.write_bytes(bytes(data))
    rep["changed"] = True
    rep["backup"] = str(backup_dir) if backup_dir else None
    return rep


def _find_xor_encode(reader: ElfReader, ref: Dict[str, Any],
                     text_secs: List[Dict[str, Any]]) -> bool:
    """Phát hiện opcode xor/encode gần tham chiếu (dấu hiệu chuỗi bị mã hóa)."""
    span = 64
    for sec in text_secs:
        if sec["addr"] <= ref["ref_rva"] < sec["addr"] + sec["size"]:
            rel = ref["ref_rva"] - sec["addr"]
            start = max(0, rel - span)
            end = min(sec["size"], rel + span)
            raw = reader.data[sec["offset"] + start:sec["offset"] + end]
            if reader.e_machine == EM_ARM64:
                for i in range(0, len(raw) - 3, 4):
                    insn = struct.unpack_from("<I", raw, i)[0]
                    if (insn & 0x7F000000) in (0x52000000, 0x4A000000):  # EOR imm/reg
                        return True
                    if insn & 0xFF000000 == 0x91000000:  # ADD (ghép chuỗi)
                        pass
            elif reader.e_machine == EM_X86_64:
                if b"\x31" in raw or b"\x33" in raw or b"\x48\x83\xf0" in raw:
                    return True
            break
    return False


# =====================================================================
# 4. RISK WEIGHTING + CONFIDENCE SCORE
# =====================================================================

@dataclass
class Finding:
    hit: StringHit
    category: str = "other"
    noise: bool = False
    noise_reason: str = ""
    signals: List[str] = field(default_factory=list)
    entropy: float = 0.0
    dynamic_params: bool = False
    refs: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    validated: bool = False
    dynamic_build: bool = False
    behavior_id: str = "other_behavior"
    behavior_extra: List[str] = field(default_factory=list)
    risk: int = 0
    confidence: int = 0
    evidence: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rva": self.hit.rva,
            "file_offset": self.hit.file_offset,
            "section": self.hit.section,
            "value": self.hit.value,
            "size": self.hit.size,
            "category": self.category,
            "noise": self.noise,
            "noise_reason": self.noise_reason,
            "entropy": self.entropy,
            "dynamic_params": self.dynamic_params,
            "risk": self.risk,
            "confidence": self.confidence,
            "validated": self.validated,
            "dynamic_build": self.dynamic_build,
            "behavior": {
                "id": self.behavior_id,
                "label": get_behavior(self.behavior_id)["label"],
                "description": get_behavior(self.behavior_id)["description"],
                "suggestions": get_behavior(self.behavior_id)["suggestions"],
            },
            "behavior_extra": self.behavior_extra,
            "functions": sorted(set(self.functions)),
            "refs": self.refs,
            "evidence": self.evidence,
        }


def _add_evidence(f: Finding, etype: str, detail: str) -> None:
    if detail not in [e["detail"] for e in f.evidence]:
        f.evidence.append({"type": etype, "detail": detail})


def score_finding(f: Finding) -> None:
    """Tính risk + confidence từ category, refs, validation, entropy..."""
    risk = BASE_RISK.get(f.category, 30)
    boosts: List[str] = []
    reduces: List[str] = []

    if f.dynamic_params and f.category in ("endpoint", "format", "header"):
        risk += 12
        boosts.append("Param động trong chuỗi (+12)")
    if f.category == "endpoint":
        if re.search(r"[?&](?:key|token|api[_-]?key|secret|auth|sig|sign)=", f.hit.value, re.I):
            risk += 6
            boosts.append("Query string chứa tham số nhạy cảm (+6)")
        tld = re.search(r"\.([a-z]{2,})/?", f.hit.value.split("://", 1)[-1] if "://" in f.hit.value else f.hit.value)
        if tld and tld.group(1) not in ("com", "org", "net", "io", "app", "dev", "vn", "co", "info", "xyz", "me", "tech"):
            risk += 10
            boosts.append("Tên miền ít phổ biến (.%s) (+10)" % tld.group(1))
    if f.category == "header":
        low = f.hit.value.lower()
        if any(h in low for h in ("authorization", "api-key", "x-auth", "x-access", "bearer")):
            risk += 8
            boosts.append("Header đặc biệt (Authorization/X-Api-Key) (+8)")
    if re.search(r"(?i)(token|secret|password|passwd|apikey|api[_-]?key)", f.hit.value):
        risk += 10
        boosts.append("Từ khóa nhạy cảm trong chuỗi (+10)")
    if f.entropy >= 4.2 and f.category not in ("symbol", "path"):
        risk += 8
        boosts.append("Entropy cao (%.2f) (+8)" % f.entropy)

    nfuncs = len({r.get("function") for r in f.refs if r.get("function")})
    if nfuncs >= 2:
        risk += 5
        boosts.append("Tham chiếu từ %d hàm (+5)" % nfuncs)

    # --- giảm điểm (false positive) ---
    if f.category in NOISE_CATEGORIES:
        risk -= 10
        reduces.append("Nhóm nhiễu (-10)")
    if len(f.hit.value) < 8:
        risk -= 8
        reduces.append("Chuỗi ngắn (<8 ký tự) (-8)")
    if any(_is_system_context(r.get("function")) for r in f.refs):
        risk -= 12
        reduces.append("Chỉ tham chiếu từ hàm hệ thống/compiler (-12)")
    if not f.refs and f.category in ("format", "path", "other"):
        risk -= 8
        reduces.append("Không có tham chiếu tĩnh (-8)")

    f.risk = max(0, min(100, risk))

    # --- confidence: risk + bằng chứng ---
    conf = f.risk
    if f.refs:
        conf += 6
        _add_evidence(f, "dataflow",
                      "Tìm thấy %d tham chiếu từ mã (%s) — xem refs"
                      % (len(f.refs), ", ".join(sorted({r["kind"] for r in f.refs}))))
    if f.validated:
        conf += 10
        _add_evidence(f, "cross_validation",
                      "Xác thực chéo ĐẠT — hàm gọi thuộc luồng JNI")
    if f.dynamic_build:
        conf += 6
        _add_evidence(f, "dataflow",
                      "Nghi vấn endpoint/chuỗi ghép động từ nhiều phần")
    if nfuncs >= 2:
        conf += 4
    f.confidence = max(0, min(100, conf))
    for b in boosts:
        _add_evidence(f, "risk", b)
    for r in reduces:
        _add_evidence(f, "risk", r)


def _attach_refs(findings: List[Finding], refs: List[Dict[str, Any]],
                 symbols: List[Dict[str, Any]]) -> None:
    """Gắn tham chiếu (kèm hàm chứa) vào finding theo dải [rva, rva+size)."""
    ranges = _symbols_by_range(symbols)
    for r in refs:
        r["function"] = _func_of(r["ref_rva"], ranges)
        r["jni"] = is_jni_func(r["function"])
    for f in findings:
        f.refs = [r for r in refs
                  if f.hit.rva <= r["target_rva"] < f.hit.rva + f.hit.size]
        f.functions = [r["function"] for r in f.refs if r.get("function")]


def _detect_dynamic_build(findings: List[Finding]) -> None:
    """Nghi vấn chuỗi ghép động: hàm tham chiếu >=2 chuỗi và 1 trong số đó
    là endpoint/format — endpoint tạo dựng từ nhiều phần nhỏ không bị bỏ sót."""
    by_func: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        for fn in set(f.functions):
            by_func[fn].append(f)
    for fn, group in by_func.items():
        if len(group) < 2:
            continue
        has_ep = any(f.category in ("endpoint", "format") for f in group)
        if has_ep:
            for f in group:
                v = f.hit.value
                if f.category in ("endpoint", "format", "path", "domain") or any(ch in v for ch in ("/", "?", "&", "%", "{")):
                    f.dynamic_build = True


def _cross_validate(findings: List[Finding], jni_reachable: Set[str],
                    reader: ElfReader, text_secs: List[Dict[str, Any]]) -> int:
    """Xác thực chéo từng finding; trả số cảnh báo giả (FP) đã loại."""
    fp = 0
    for f in findings:
        if f.noise:
            fp += 1
            _add_evidence(f, "noise_filter",
                          "Lọc nhiễu: %s" % f.noise_reason)
            continue
        for r in f.refs:
            fn = r.get("function")
            if not fn:
                _add_evidence(f, "cross_validation",
                              "Tham chiếu nằm ngoài symbol — không xác định hàm gọi")
                continue
            if is_jni_func(fn):
                f.validated = True
                _add_evidence(f, "cross_validation",
                              "Gọi trực tiếp từ hàm JNI %s — ĐẠT" % fn)
            elif fn in jni_reachable:
                f.validated = True
                _add_evidence(f, "cross_validation",
                              "Hàm %s nằm trong chuỗi gọi từ JNI (caller/callee) — ĐẠT" % fn)
            elif _is_system_context(fn):
                fp += 1
                _add_evidence(f, "cross_validation",
                              "Hàm %s thuộc hệ thống/compiler — hạ trọng số (nghi FP)" % fn)
            else:
                _add_evidence(f, "cross_validation",
                              "Gọi từ hàm %s — chưa xác nhận liên quan JNI" % fn)
        if f.refs and _find_xor_encode(reader, f.refs[0], text_secs):
            _add_evidence(f, "dataflow",
                          "Opcode xor/encode gần tham chiếu — chuỗi có thể bị mã hóa động")
    return fp


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_so(path: str | Path, min_len: int = 6, min_risk: int = 0,
            show_noise: bool = False, scan_refs: bool = True,
            hints: Optional[Tuple[str, ...]] = None,
            native: Optional[bool] = None) -> Dict[str, Any]:
    """Quét thông minh một file .so/.elf — trả báo cáo JSON đầy đủ."""
    path = Path(path)
    reader = ElfReader(path)
    engine_info: Dict[str, Any] = {"native": False, "error": None}
    hits = enumerate_strings(reader, min_len=min_len, hints=hints,
                             native=native, engine_info=engine_info)

    findings: List[Finding] = []
    for h in hits:
        cat, noise, reason, signals = classify_string(h.value, h.section)
        f = Finding(hit=h, category=cat, noise=noise, noise_reason=reason,
                    signals=signals, entropy=shannon_entropy(h.value),
                    dynamic_params=_has_dynamic_params(h.value))
        findings.append(f)

    text_secs = _text_sections(reader)
    symbols = parse_symbols(reader)
    refs = scan_code_refs(reader) if scan_refs else []
    jni_reach: Set[str] = set()
    if scan_refs and text_secs:
        jni_reach = _jni_reachable(reader, symbols, text_secs)
    _attach_refs(findings, refs, symbols)
    _detect_dynamic_build(findings)
    fp_removed = _cross_validate(findings, jni_reach, reader, text_secs)

    for f in findings:
        score_finding(f)
        primary, extra = match_smart_behavior(
            f.category, validated=f.validated, dynamic_build=f.dynamic_build)
        f.behavior_id = primary
        f.behavior_extra = extra

    kept = [f for f in findings if not f.noise and f.risk >= min_risk]
    kept.sort(key=lambda f: (f.confidence, f.risk), reverse=True)
    noise_list = [f for f in findings if f.noise]

    high = sum(1 for f in kept if f.confidence >= 75)
    medium = sum(1 for f in kept if 50 <= f.confidence < 75)
    low = sum(1 for f in kept if f.confidence < 50)
    conf_avg = (round(sum(f.confidence for f in kept) / len(kept), 1)
                if kept else 0.0)

    report: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "repro": {
            "file": str(path),
            "file_sha256": sha256_file(path),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "params": {"min_len": min_len, "min_risk": min_risk,
                       "scan_refs": scan_refs,
                       "native": native,
                       "sections": list(hints or ("rodata", "data.rel.ro", ".data"))},
        },
        "summary": {
            "native_engine": "neon" if engine_info["native"] else "python",
            "native_engine_error": engine_info.get("error"),
            "total_strings": len(findings),
            "kept": len(kept),
            "noise_dropped": len(noise_list),
            "false_positive_removed": fp_removed,
            "refs_found": len(refs),
            "jni_refs": sum(1 for r in refs if r.get("jni")),
            "jni_functions": sorted({r.get("function") for r in refs
                                     if r.get("jni")}),
            "flagged_high": high,
            "flagged_medium": medium,
            "flagged_low": low,
            "confidence_avg": conf_avg,
        },
        "symbols": [s["name"] for s in symbols],
        "findings": [f.to_dict() for f in kept],
        "noise": [f.to_dict() for f in noise_list] if show_noise else [],
    }
    try:
        from .behavior_learner import learn_from_report
        learn_from_report(report, source=Path(path).name)
    except Exception:
        pass
    return report


def start_scan(target: str | Path, abi: Optional[str] = None,
               min_len: int = 6, min_risk: int = 60,
               show_noise: bool = False,
               keep_extract: bool = False,
               native: Optional[bool] = None) -> Dict[str, Any]:
    """start-scan — xử lý THƯ VIỆN .so (tách biệt khỏi `behavior` xử lý smali).

    Đầu vào: APK (trích lib/*.so), thư mục chứa .so, hoặc file .so.
    Quét từng lib bằng scan_so rồi TỔNG HỢP thành báo cáo đa lib.
    """
    target = Path(target)
    libs: List[Path] = []
    extract_root: Optional[Path] = None

    if target.is_dir():
        libs = [p for p in sorted(target.rglob("*.so"))]
    elif target.is_file() and target.suffix.lower() == ".so":
        libs = [target]
    elif target.is_file() and zipfile.is_zipfile(target):
        if keep_extract:
            base = Path(os.getcwd()) / "outputs" / "behavior" / "smart_scan" / "so_extract"
            extract_root = base / target.stem
            extract_root.mkdir(parents=True, exist_ok=True)
        else:
            extract_root = Path(tempfile.mkdtemp(prefix="patchx_startscan_"))
        with zipfile.ZipFile(target) as zf:
            for n in zf.namelist():
                if not (n.startswith("lib/") and n.endswith(".so")):
                    continue
                if abi and not n.startswith("lib/%s/" % abi):
                    continue
                dest = extract_root / n.replace("/", os.sep)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(n))
                libs.append(dest)
    else:
        raise ValueError(
            "Đầu vào phải là APK, thư mục chứa .so, hoặc file .so: %s" % target)

    if not libs:
        raise ValueError("Không tìm thấy lib .so nào trong %s" % target)

    def _scan_lib_worker(lib):
        rep: Dict[str, Any] = {"lib": str(lib), "lib_name": lib.name}
        try:
            single = scan_so(lib, min_len=min_len, min_risk=min_risk,
                             show_noise=show_noise, native=native)
            rep.update(single)
        except (ValueError, OSError) as exc:
            rep["error"] = str(exc)
        return rep

    if len(libs) <= 1:
        reports = [_scan_lib_worker(lib) for lib in libs]
    else:
        from patchx_core.pool import run_parallel
        reports = run_parallel(_scan_lib_worker, libs)

    ok = [r for r in reports if "error" not in r]
    s = {
        "libs_scanned": len(reports),
        "libs_ok": len(ok),
        "libs_errored": len(reports) - len(ok),
        "total_strings": sum(r["summary"]["total_strings"] for r in ok),
        "total_findings": sum(r["summary"]["kept"] for r in ok),
        "total_noise": sum(r["summary"]["noise_dropped"] for r in ok),
        "refs_found": sum(r["summary"]["refs_found"] for r in ok),
        "jni_refs": sum(r["summary"]["jni_refs"] for r in ok),
        "flagged_high": sum(r["summary"]["flagged_high"] for r in ok),
        "flagged_medium": sum(r["summary"]["flagged_medium"] for r in ok),
        "flagged_low": sum(r["summary"]["flagged_low"] for r in ok),
        "neon_libs": sum(1 for r in ok if r["summary"].get("native_engine") == "neon"),
        "python_libs": sum(1 for r in ok if r["summary"].get("native_engine") == "python"),
    }
    if ok:
        s["confidence_avg"] = round(
            sum(r["summary"]["confidence_avg"] for r in ok) / len(ok), 1)
    else:
        s["confidence_avg"] = 0.0

    top: List[Dict[str, Any]] = []
    for r in ok:
        for f in r["findings"]:
            item = dict(f)
            item["lib_name"] = r["lib_name"]
            item["lib_sha256"] = r["repro"]["file_sha256"][:16]
            top.append(item)
    top.sort(key=lambda x: (x["confidence"], x["risk"]), reverse=True)

    combined: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "mode": "start-scan",
        "repro": {
            "target": str(target),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "params": {"abi": abi, "min_len": min_len, "min_risk": min_risk,
                       "show_noise": show_noise, "native": native},
        },
        "summary": s,
        "top_findings": top[:50],
        "libs": reports,
    }

    if extract_root is not None and not keep_extract:
        shutil.rmtree(extract_root, ignore_errors=True)

    try:
        from .behavior_learner import learn_from_report
        learn_from_report(combined, source=target.name)
    except Exception:
        pass

    return combined


def render_start_scan_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# start-scan — quét thư viện .so (tổng hợp) — %s" % report["tool"],
        "",
        "| Mục | Giá trị |",
        "|---|---|",
        "| Đầu vào | `%s` |" % report["repro"]["target"],
        "| Thời gian | %s |" % report["repro"]["scan_time"],
        "| Tham số | `%s` |" % json.dumps(report["repro"]["params"],
                                         ensure_ascii=False),
        "| Lib | %d (OK %d · lỗi %d) |"
        % (s["libs_scanned"], s["libs_ok"], s["libs_errored"]),
        "| Chuỗi | %d | Finding: %d | Nhiễu: %d |"
        % (s["total_strings"], s["total_findings"], s["total_noise"]),
        "| Tham chiếu | %d (JNI: %d) |" % (s["refs_found"], s["jni_refs"]),
        "| Cao ≥75 | %d · TB: %d · Thấp: %d | TB confidence: %.1f%% |"
        % (s["flagged_high"], s["flagged_medium"], s["flagged_low"],
           s["confidence_avg"]),
        "",
        "## BẢNG TỔNG HỢP TÁC CHIẾN (Actionable Executive Summary)",
        "",
    ]
    top = report.get("top_findings", [])
    jni_top = [f for f in top if f.get("validated")]
    ep_top = [f for f in top if f.get("category") == "endpoint"]
    tamper_top = [f for f in top if any(k in str(f.get("value", "")).lower() for k in ("hook", "debug", "sig", "protect", "integrity", "tamper", "tracerpid"))]

    if jni_top:
        lines.append("### [TÁC CHIẾN] Luồng JNI trực tiếp có rủi ro:")
        for f in jni_top[:5]:
            lines.append("- **%s** (`%s`): `%s` (risk=%d, conf=%d%%)" % (
                f.get("lib_name", ""), f.get("behavior", {}).get("label", ""),
                str(f.get("value", ""))[:80], f.get("risk", 0), f.get("confidence", 0)))
        lines.append("")
    if ep_top:
        lines.append("### [TÁC CHIẾN] Endpoint / URL nhạy cảm phát hiện:")
        for f in ep_top[:5]:
            lines.append("- **%s**: `%s` (risk=%d, conf=%d%%)" % (
                f.get("lib_name", ""), str(f.get("value", ""))[:100],
                f.get("risk", 0), f.get("confidence", 0)))
        lines.append("")
    if tamper_top:
        lines.append("### [TÁC CHIẾN] Dấu hiệu can thiệp / Chống dịch ngược:")
        for f in tamper_top[:5]:
            lines.append("- **%s**: `%s`" % (f.get("lib_name", ""), str(f.get("value", ""))[:80]))
        lines.append("")
    if not (jni_top or ep_top or tamper_top):
        lines.append("_Không phát hiện rủi ro cấp thiết mức cao._\n")

    lines += [
        "## Top findings (xếp theo Confidence)",
        "",
    ]
    if not report["top_findings"]:
        lines.append("_Không có finding đạt ngưỡng._")
    for f in report["top_findings"]:
        lines += [
            "### [%d%%] %s · %s" % (f["confidence"], f["lib_name"],
                                    f["category"].upper()),
            "",
            "- rva=0x%x · %s · risk=%d · JNI=%s"
            % (f["rva"], f["section"], f["risk"],
               "ĐẠT" if f["validated"] else "chưa"),
            "- Hành vi: **%s** (%s)" % (f["behavior"]["label"],
                                        f["behavior"]["id"]),
            "- `%s`" % f["value"],
            "",
        ]
    lines.append("## Chi tiết từng lib")
    for r in report["libs"]:
        if "error" in r:
            lines.append("- **%s**: LỖI %s" % (r["lib_name"], r["error"]))
            continue
        sm = r["summary"]
        lines.append("- **%s** (%s…): %d finding · %d refs (%d JNI) · %d nhiễu"
                     % (r["lib_name"], r["repro"]["file_sha256"][:8],
                        sm["kept"], sm["refs_found"], sm["jni_refs"],
                        sm["noise_dropped"]))
    return "\n".join(lines)


# =====================================================================
# BÁO CÁO MARKDOWN
# =====================================================================

def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# Báo cáo quét thông minh (.rodata/.data) — %s" % report["tool"],
        "",
        "| Mục | Giá trị |",
        "|---|---|",
        "| File | `%s` |" % report["repro"]["file"],
        "| SHA-256 | `%s` |" % report["repro"]["file_sha256"],
        "| Thời gian | %s |" % report["repro"]["scan_time"],
        "| Tham số | `%s` |" % json.dumps(report["repro"]["params"], ensure_ascii=False),
        "| Tổng chuỗi | %d |" % s["total_strings"],
        "| Giữ lại | %d |" % s["kept"],
        "| Lọc nhiễu | %d |" % s["noise_dropped"],
        "| FP đã loại (cross-validation) | %d |" % s["false_positive_removed"],
        "| Tham chiếu tĩnh | %d (JNI: %d) |" % (s["refs_found"], s["jni_refs"]),
        "| Cao ≥75 | %d · Trung bình 50-74: %d · Thấp <50: %d |"
        % (s["flagged_high"], s["flagged_medium"], s["flagged_low"]),
        "| Confidence trung bình | %.1f%% |" % s["confidence_avg"],
        "",
        "## BẢNG TỔNG HỢP TÁC CHIẾN (Actionable Executive Summary)",
        "",
    ]
    findings = report.get("findings", [])
    jni_top = [f for f in findings if f.get("validated")]
    ep_top = [f for f in findings if f.get("category") == "endpoint"]
    tamper_top = [f for f in findings if any(k in str(f.get("value", "")).lower() for k in ("hook", "debug", "sig", "protect", "integrity", "tamper", "tracerpid"))]

    if jni_top:
        lines.append("### [TÁC CHIẾN] Luồng JNI trực tiếp có rủi ro:")
        for f in jni_top[:5]:
            lines.append("- `%s` (`%s`, risk=%d, conf=%d%%)" % (
                str(f.get("value", ""))[:80], f.get("behavior", {}).get("label", ""),
                f.get("risk", 0), f.get("confidence", 0)))
        lines.append("")
    if ep_top:
        lines.append("### [TÁC CHIẾN] Endpoint / URL nhạy cảm phát hiện:")
        for f in ep_top[:5]:
            lines.append("- `%s` (risk=%d, conf=%d%%)" % (
                str(f.get("value", ""))[:100], f.get("risk", 0), f.get("confidence", 0)))
        lines.append("")
    if tamper_top:
        lines.append("### [TÁC CHIẾN] Dấu hiệu can thiệp / Chống dịch ngược:")
        for f in tamper_top[:5]:
            lines.append("- `%s`" % str(f.get("value", ""))[:80])
        lines.append("")
    if not (jni_top or ep_top or tamper_top):
        lines.append("_Không phát hiện rủi ro cấp thiết mức cao._\n")

    lines += [
        "## Chi tiết các phát hiện",
        "",
    ]
    if not report["findings"]:
        lines.append("_Không có finding nào đạt ngưỡng._")
    for f in report["findings"]:
        lines += [
            "## [%d%%] rva=0x%x · %s · %s" % (f["confidence"], f["rva"],
                                              f["category"].upper(), f["section"]),
            "",
            "```",
            f["value"],
            "```",
            "",
            "- Risk: %d/100 · Entropy: %.2f · Param động: %s · Xác thực chéo: %s"
            % (f["risk"], f["entropy"], f["dynamic_params"],
               "ĐẠT" if f["validated"] else "chưa"),
        ]
        if f["functions"]:
            lines.append("- Hàm gọi: `%s`" % ", ".join(sorted(set(f["functions"]))))
        if f["dynamic_build"]:
            lines.append("- Nghi vấn ghép động (endpoint tạo từ nhiều phần).")
        lines.append("- Hành vi: **%s** (%s)" % (f["behavior"]["label"],
                                                 f["behavior"]["id"]))
        lines.append("  - %s" % f["behavior"]["description"])
        if f["behavior"]["suggestions"]:
            lines.append("  - Gợi ý: %s" % f["behavior"]["suggestions"][0])
        if f["behavior_extra"]:
            for bid in f["behavior_extra"]:
                b = get_behavior(bid)
                lines.append("- Hành vi bổ trợ: **%s** (%s)" % (b["label"], bid))
        lines.append("- Bằng chứng:")
        for e in f["evidence"]:
            lines.append("  - `%s`: %s" % (e["type"], e["detail"]))
        lines.append("")
    return "\n".join(lines)


# =====================================================================
# CLI
# =====================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patchx smart-scan",
        description="Quét chuỗi .rodata/.data thông minh: lọc nhiễu ngữ nghĩa "
                    "+ data-flow tĩnh + xác thực chéo + Confidence Score 0-100.",
    )
    p.add_argument("so", nargs="?", help="File .so/.elf cần quét")
    p.add_argument("--min-len", type=int, default=6,
                   help="Độ dài tối thiểu chuỗi (mặc định 6)")
    p.add_argument("--min-risk", type=int, default=0,
                   help="Chỉ giữ finding có risk >= giá trị này (mặc định 0)")
    p.add_argument("--show-noise", action="store_true",
                   help="Kèm danh sách chuỗi đã lọc nhiễu vào JSON/Markdown")
    p.add_argument("--no-refs", dest="scan_refs", action="store_false",
                   help="Tắt truy vết tham chiếu tĩnh (data-flow)")
    p.add_argument("-o", default=None, help="File JSON đầu ra (mặc định outputs/behavior/smart_scan/...)")
    p.add_argument("--md", default=None, help="File Markdown đầu ra (mặc định kèm theo JSON)")
    p.add_argument("--behaviors", action="store_true",
                   help="In từ điển hành vi (giống ontology.py) rồi thoát")
    p.add_argument("--jni", action="store_true",
                   help="Phân tích thêm bảng RegisterNatives (JNINativeMethod) trong .so")
    p.add_argument("--jni-frida", default=None, metavar="FILE",
                   help="Ghi kịch bản Frida hook theo RVA của các hàm JNI phát hiện được")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.behaviors:
        from .smart_ontology import render_behavior_catalog
        print(render_behavior_catalog())
        return 0
    try:
        report = scan_so(args.so, min_len=args.min_len,
                         min_risk=args.min_risk, show_noise=args.show_noise,
                         scan_refs=args.scan_refs)
    except (ValueError, OSError) as exc:
        print("[smart-scan] Lỗi: %s" % exc)
        return 2

    if getattr(args, "jni", False):
        reader = ElfReader(args.so)
        jni_rep = scan_register_natives(reader)
        report["jni_natives"] = jni_rep
        print("[smart-scan] Bảng RegisterNatives: symbol=%s · mục=%d"
              % (jni_rep["has_register_natives_symbol"], jni_rep["count"]))
        for e in jni_rep["entries"][:20]:
            print("  - %-28s %-16s fn=0x%x" % (e["name"], e["signature"], e["fn_rva"]))
        if getattr(args, "jni_frida", None):
            script = render_frida_for_natives(jni_rep,
                                              module_name=Path(args.so).name)
            p = Path(args.jni_frida)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(script, encoding="utf-8")
            print("[smart-scan] Đã ghi Frida hook:", p)

    s = report["summary"]
    print("[smart-scan] %s" % report["repro"]["file"])
    print("  SHA-256: %s" % report["repro"]["file_sha256"][:16] + "...")
    print("  Chuỗi: %d · Giữ: %d · Lọc nhiễu: %d · FP loại: %d"
          % (s["total_strings"], s["kept"], s["noise_dropped"],
             s["false_positive_removed"]))
    print("  Tham chiếu: %d (JNI: %d) · Cao: %d · TB: %d · Thấp: %d · TB confidence: %.1f%%"
          % (s["refs_found"], s["jni_refs"], s["flagged_high"],
             s["flagged_medium"], s["flagged_low"], s["confidence_avg"]))

    base = Path(args.o) if args.o else None
    md_path = Path(args.md) if args.md else None
    if base is None:
        out_dir = Path(os.getcwd()) / "outputs" / "behavior" / "smart_scan"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        stem = Path(args.so).name
        base = out_dir / ("%s_%s.json" % (stem, stamp))
        md_path = md_path or out_dir / ("%s_%s.md" % (stem, stamp))
    base = Path(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    print("[smart-scan] Đã ghi JSON:", base)
    if md_path is not None:
        md_path = Path(md_path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(report), encoding="utf-8")
        print("[smart-scan] Đã ghi Markdown:", md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
