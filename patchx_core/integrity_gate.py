# -*- coding: utf-8 -*-
"""integrity_gate — MỘT cổng kiểm tra toàn vẹn duy nhất, xuyên mọi tầng (G1..G5).

Các lớp:
  G1 — Dấu vân tay & neo: SHA-256 trước/sau, khóa bản ghi.
  G2 — Cấu trúc: parse lại smali/DEX/ELF/APK sau khi sửa.
  G3 — Ngữ nghĩa: mô phỏng luồng lệnh (Micro-DEX) đối chiếu giá trị mong muốn.
  G4 — Hành vi: chạy lại máy phát hiện và so số liệu (chống hồi quy).
  G5 — Chống báo đạt giả: được chứng minh bằng test âm ở tests/run_tests.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ok(layer: str, evidence: Any, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"layer": layer, "ok": True, "evidence": evidence}
    if extra:
        out.update(extra)
    return out


def _fail(layer: str, reason: str, evidence: Any = None) -> Dict[str, Any]:
    return {"layer": layer, "ok": False, "reason": reason, "evidence": evidence}


def gate_g2_smali(path_or_text: str | Path) -> Dict[str, Any]:
    from .smali_validate import validate_file
    try:
        if isinstance(path_or_text, str) and ("\n" in path_or_text or path_or_text.startswith(".class")):
            text = path_or_text
        elif os.path.exists(str(path_or_text)):
            text = Path(path_or_text).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(path_or_text)
        errors, methods = validate_file(text)
        rep = {"errors": errors, "methods": methods}
        return _ok("G2-smali", rep) if not errors else _fail(
            "G2-smali", "cấu trúc smali lỗi: %s" % errors[:3], rep)
    except Exception as exc:  # noqa: BLE001
        return _fail("G2-smali", str(exc))


def gate_g2_dex(path: str | Path) -> Dict[str, Any]:
    from .dex_inplace import inspect_dex
    try:
        rep = inspect_dex(Path(path).read_bytes())
        return _ok("G2-dex", rep)
    except Exception as exc:  # noqa: BLE001
        return _fail("G2-dex", str(exc))


def gate_g2_elf(path: str | Path) -> Dict[str, Any]:
    from .behavior.rodata_patcher import ElfReader
    try:
        elf = ElfReader(str(path))
        return _ok("G2-elf", {
            "is64": elf.is64,
            "sections": len(elf.sections),
            "segments": len(elf.segments),
        })
    except Exception as exc:  # noqa: BLE001
        return _fail("G2-elf", str(exc))


def gate_g2_apk(path: str | Path) -> Dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
        if bad:
            return _fail("G2-apk", "zip hỏng tại %s" % bad)
        apksigner = subprocess.run(
            ["apksigner", "verify", "--verbose", str(path)],
            capture_output=True, text=True, timeout=120)
        if apksigner.returncode == 0:
            return _ok("G2-apk", {"zip_ok": True, "apksigner": "verify OK"})
        return _fail("G2-apk", (apksigner.stderr or apksigner.stdout)[:300])
    except FileNotFoundError:
        return _fail("G2-apk", "thiếu apksigner")
    except Exception as exc:  # noqa: BLE001
        return _fail("G2-apk", str(exc))


def gate_g3(method_text: str, expected: Any = True,
            label: str = "method") -> Dict[str, Any]:
    from .dex_emulator import verify_method_bypass
    try:
        res = verify_method_bypass(method_text)
        passed = res["verified"] == bool(expected)
        return _ok("G3", res, {"label": label, "expected": expected}) if passed else _fail(
            "G3", "kết quả mô phỏng %r != kỳ vọng %r" % (res.get("return_value"), expected), res)
    except Exception as exc:  # noqa: BLE001
        return _fail("G3", str(exc))


def gate_g4(tree: str, expected: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    from .smali_sem import detect_security_gates
    try:
        gates = detect_security_gates(str(tree))
        counts = {"security_gates": len(gates)}
        if expected:
            for key, want in expected.items():
                got = counts.get(key)
                if got is None or int(got) != int(want):
                    return _fail("G4", "số liệu '%s' lệch: %s != %s" % (key, got, want), counts)
        return _ok("G4", counts)
    except Exception as exc:  # noqa: BLE001
        return _fail("G4", str(exc))


def gate_target(path: str, layer: Optional[str] = None,
                g3_method: Optional[str] = None, g3_expected: Any = True,
                g4_expected: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Chạy các lớp phù hợp với loại tệp và trả kết luận duy nhất."""
    p = Path(path)
    checks: List[Dict[str, Any]] = []

    if p.is_file() and p.suffix == ".smali":
        checks.append(gate_g2_smali(p))
    elif p.is_file() and p.suffix in (".dex",) or (p.name.startswith("classes") and p.suffix == ""):
        checks.append(gate_g2_dex(p))
    elif p.is_file():
        with open(p, "rb") as fh:
            magic = fh.read(4)
        if magic == b"\x7fELF":
            checks.append(gate_g2_elf(p))
        elif zipfile.is_zipfile(p):
            checks.append(gate_g2_apk(p))
        else:
            checks.append(_fail("G2", "chưa nhận diện được loại tệp"))
    elif p.is_dir():
        from .smali_validate import validate_tree
        rep = validate_tree(p)
        bad = rep.get("errors") or rep.get("issues") or []
        checks.append(_ok("G2-smali-tree", rep) if not bad else _fail(
            "G2-smali-tree", "lỗi cây: %s" % bad[:3], rep))

    if g3_method:
        checks.append(gate_g3(g3_method, expected=g3_expected))
    if g4_expected is not None:
        checks.append(gate_g4(p, g4_expected))

    ok_all = all(c["ok"] for c in checks)
    return {
        "target": str(path),
        "verdict": "PASS" if ok_all else "FAIL",
        "layers": {c["layer"]: c for c in checks},
        "passed": sum(1 for c in checks if c["ok"]),
        "total": len(checks),
        "note": "G5 (chống báo đạt giả) được chứng minh bằng test âm "
                "test_integrity_gate trong tests/run_tests.py",
    }


def gate_tree(root: str) -> Dict[str, Any]:
    """Cổng toàn vẹn cho cây APK: kiểm smali + ELF trong lib/."""
    tree = Path(root)
    results: List[Dict[str, Any]] = []
    smali_files = sorted(tree.rglob("*.smali"))
    for fp in smali_files:
        results.append(gate_g2_smali(fp))
    for fp in sorted(tree.rglob("*.so")):
        results.append(gate_g2_elf(fp))
    ok_all = bool(results) and all(r["ok"] for r in results)
    return {
        "target": str(tree),
        "verdict": "PASS" if ok_all else "FAIL",
        "files_checked": len(results),
        "passed": sum(1 for r in results if r["ok"]),
        "failed": [r for r in results if not r["ok"]][:20],
    }


def gate_apk(apk: str) -> Dict[str, Any]:
    return {"target": apk, **gate_target(apk)}
