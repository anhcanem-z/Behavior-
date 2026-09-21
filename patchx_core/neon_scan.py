# -*- coding: utf-8 -*-
"""neon_scan — Tăng tốc quét chuỗi nhị phân bằng NEON ARM64 (qua thư viện C).

- Biên dịch `_native_scan.c` bằng clang thành `.so` (lần đầu dùng).
- Hai kernel: tìm mẫu byte chính xác (find_all) + quét dải byte trong
  khoảng [lo, hi] (scan_runs — dùng cho chuỗi ASCII in được).
- Nếu không biên dịch được thì tự rơi về vòng quét Python (fallback).
- `benchmark` đo tốc độ GB/s thật của hai đường, không tự nhận con số ảo.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple


_C_LIB: Optional[str] = None
_C_LIB_ERR: Optional[str] = None


def _source_path() -> Path:
    return Path(__file__).with_name("_native_scan.c")


def compile_native() -> Optional[str]:
    """Biên dịch thư viện native; trả đường dẫn .so hoặc None nếu thất bại."""
    global _C_LIB, _C_LIB_ERR
    if _C_LIB:
        return _C_LIB
    src = _source_path()
    if not src.exists():
        _C_LIB_ERR = "thiếu %s" % src.name
        return None
    out_dir = Path(tempfile.gettempdir()) / "patchx_native"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:  # noqa: BLE001
        _C_LIB_ERR = "không tạo thư mục biên dịch: %s" % exc
        return None
    so = out_dir / "libpatchx_scan.so"
    cc = os.environ.get("CC") or "clang"
    try:
        subprocess.run(
            [cc, "-shared", "-O3", "-fPIC", "-o", str(so), str(src)],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        _C_LIB_ERR = "biên dịch thất bại (%s): %s" % (cc, exc)
        return None
    _C_LIB = str(so)
    return _C_LIB


def native_status() -> dict:
    """Trạng thái native: đã biên dịch được chưa, lỗi gì nếu có."""
    return {
        "library": _C_LIB,
        "error": _C_LIB_ERR,
        "source": str(_source_path()),
    }


def find_all_python(data: bytes, needle: bytes) -> List[int]:
    """Vòng quét Python thuần (fallback + mốc so sánh)."""
    if not needle:
        return []
    out: List[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def find_all_native(data: bytes, needle: bytes, max_matches: int = 1_000_000) -> List[int]:
    """Quét bằng thư viện native; lỗi thì rơi về Python để kết quả vẫn đúng."""
    so = compile_native()
    if not so:
        return find_all_python(data, needle)
    if not needle or not data:
        return []
    lib = ctypes.CDLL(so)
    est = data.count(needle) if needle else 0
    n = max(1, min(max_matches, est if est else 1))
    offsets = (ctypes.c_long * n)()
    lib.patchx_find_all.restype = ctypes.c_int
    lib.patchx_find_all.argtypes = [
        ctypes.c_char_p, ctypes.c_long,
        ctypes.c_char_p, ctypes.c_long,
        ctypes.POINTER(ctypes.c_long), ctypes.c_int,
    ]
    count = lib.patchx_find_all(data, len(data), needle, len(needle), offsets, n)
    return [offsets[i] for i in range(count)]


def find_runs_python(data: bytes, lo: int = 0x20, hi: int = 0x7E,
                     min_run: int = 4) -> List[Tuple[int, int]]:
    """Vòng quét dải byte Python thuần (fallback + mốc so sánh)."""
    out: List[Tuple[int, int]] = []
    n = len(data)
    i = 0
    while i < n:
        while i < n and not (lo <= data[i] <= hi):
            i += 1
        if i >= n:
            break
        start = i
        while i < n and lo <= data[i] <= hi:
            i += 1
        if i - start >= min_run:
            out.append((start, i - start))
    return out


def find_runs_native(data: bytes, lo: int = 0x20, hi: int = 0x7E,
                     min_run: int = 4) -> List[Tuple[int, int]]:
    """Quét dải byte bằng kernel NEON; lỗi thì rơi về Python."""
    so = compile_native()
    if not so:
        return find_runs_python(data, lo, hi, min_run)
    if not data:
        return []
    lib = ctypes.CDLL(so)
    cap = max(2, (len(data) // max(1, min_run)) + 2)
    arr = (ctypes.c_long * (cap * 2))()
    lib.patchx_scan_runs.restype = ctypes.c_long
    lib.patchx_scan_runs.argtypes = [
        ctypes.c_char_p, ctypes.c_long,
        ctypes.c_uint8, ctypes.c_uint8, ctypes.c_long,
        ctypes.POINTER(ctypes.c_long), ctypes.c_long,
    ]
    count = lib.patchx_scan_runs(data, len(data), lo, hi, min_run, arr, cap)
    count = max(0, min(int(count), cap))
    return [(arr[2 * i], arr[2 * i + 1]) for i in range(count)]


def _gbps(total_bytes: int, seconds: float) -> float:
    return (total_bytes / 1e9) / seconds if seconds > 0 else 0.0


def benchmark(size_mb: int = 64, needle: bytes = b"/system/bin/su",
              lo: int = 0x20, hi: int = 0x7E, min_run: int = 4,
              iterations: int = 5) -> dict:
    """Đo tốc độ thật (GB/s) native vs Python trên khối dữ liệu lớn.

    Dùng khối đệm native được cấp phát một lần để đo đúng sức mạnh của
    kernel NEON, không lẫn chi phí cấp phát/copy Python.
    """
    size = max(1, size_mb) * 1024 * 1024
    src = bytearray(size)
    # Trộn nội dung: 60% byte in được + 40% byte nhị phân, có chèn mẫu cần tìm.
    import random
    rnd = random.Random(0x5EED)
    for i in range(0, size, 64):
        blk = bytes(rnd.randrange(0x20, 0x7F) for _ in range(40))
        src[i:i + 40] = blk
    for i in range(0, size, 4096):
        src[i:i + len(needle)] = needle

    buf = ctypes.create_string_buffer(bytes(src), size)
    raw = buf.raw

    # Python: quét dải (finditer tương đương) + dò mẫu.
    t0 = time.perf_counter()
    for _ in range(iterations):
        py_runs = find_runs_python(raw, lo, hi, min_run)
        py_find = find_all_python(raw, needle)
    py_s = (time.perf_counter() - t0) / iterations

    so = compile_native()
    if not so:
        return {
            "native_available": False,
            "error": _C_LIB_ERR,
            "size_mb": size_mb,
            "python_gbps": round(_gbps(size * 2, py_s), 2),
            "native_gbps": None,
            "speedup": None,
            "runs_python": len(py_runs),
            "matches_python": len(py_find),
        }

    lib = ctypes.CDLL(so)
    cap = (size // max(1, min_run)) + 2
    arr = (ctypes.c_long * (cap * 2))()
    off = (ctypes.c_long * (size // max(1, len(needle)) + 2))()
    lib.patchx_scan_runs.restype = ctypes.c_long
    lib.patchx_scan_runs.argtypes = [
        ctypes.c_char_p, ctypes.c_long,
        ctypes.c_uint8, ctypes.c_uint8, ctypes.c_long,
        ctypes.POINTER(ctypes.c_long), ctypes.c_long,
    ]
    lib.patchx_find_all.restype = ctypes.c_int
    lib.patchx_find_all.argtypes = [
        ctypes.c_char_p, ctypes.c_long,
        ctypes.c_char_p, ctypes.c_long,
        ctypes.POINTER(ctypes.c_long), ctypes.c_int,
    ]

    t1 = time.perf_counter()
    n_runs = n_matches = 0
    for _ in range(iterations):
        n_runs = int(lib.patchx_scan_runs(raw, size, lo, hi, min_run, arr, cap))
        n_matches = int(lib.patchx_find_all(
            raw, size, needle, len(needle), off,
            min(len(off), size // len(needle) + 2)))
    nat_s = (time.perf_counter() - t1) / iterations

    same_runs = ([(arr[2 * i], arr[2 * i + 1]) for i in range(n_runs)] == py_runs)
    same_find = ([off[i] for i in range(n_matches)] == py_find)
    py_gbps = _gbps(size * 2, py_s)
    nat_gbps = _gbps(size * 2, nat_s)
    return {
        "native_available": True,
        "error": None,
        "library": so,
        "size_mb": size_mb,
        "python_gbps": round(py_gbps, 2),
        "native_gbps": round(nat_gbps, 2),
        "speedup": round(nat_gbps / py_gbps, 2) if py_gbps else None,
        "runs": n_runs,
        "matches": n_matches,
        "same_runs": same_runs,
        "same_find": same_find,
    }
