#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Báo cáo trạng thái tự động khi Codex online (bản behavior + Frida).

Quét nhanh hiện trạng toolkit (không chạy lệnh nặng, không cần thư viện
ngoài), so sánh với AGENTS_TRANG_THAI.md rồi in:
  A. Thông tin cơ bản
  B. Thành phần cần bổ sung (file báo cáo mới hơn mốc cập nhật)
  C. Sai lệch số liệu (file ghi vs thực tế trên đĩa)
  D. Khuyến nghị
Phạm vi: quy tắc toàn cục — trong thư mục làm việc hiện tại + các thư mục con
được đọc/ghi đầy đủ; ngoài phạm vi CHỈ ĐƯỢC ĐỌC (read-only). Script chỉ chạy
khi cwd nằm trong thư mục toolkit và chỉ đọc dữ liệu nội bộ.
"""

import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(ROOT, "AGENTS_TRANG_THAI.md")
REPORT_DIRS = [
    "outputs",
    "dist",
]

SKIP_DIR_NAMES = {
    "__pycache__", "cache", ".patchx", "build", "assets", "work",
}
MAX_DEPTH = 3


def read_json(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def count(rel_pattern):
    return len(glob.glob(os.path.join(ROOT, rel_pattern)))


def apk_tree_count():
    n = 0
    for d in glob.glob(os.path.join(ROOT, "outputs", "apk", "apk-trees", "*")):
        if os.path.isfile(os.path.join(d, "apktool.yml")):
            n += 1
    return n


def git_state():
    try:
        out = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0 or out.stdout.strip() != "true":
            return None
        branch = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or "?"
        n = subprocess.run(
            ["git", "-C", ROOT, "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or "?"
        head = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or ""
        remote = subprocess.run(
            ["git", "-C", ROOT, "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or ""
        desc = "{} commit{}".format(n, "" if n == "1" else "s")
        if head:
            desc += " (HEAD {})".format(head)
        return branch, desc, remote
    except Exception:
        return None


def status_date():
    try:
        with open(STATUS_FILE, encoding="utf-8") as fh:
            head = fh.read(600)
        m = re.search(r"Ngày cập nhật:\s*\*\*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2})?)", head)
        if m:
            val = m.group(1).strip()
            if " " in val:
                return datetime.strptime(val, "%Y-%m-%d %H:%M")
            return datetime.strptime(val, "%Y-%m-%d")
    except Exception:
        pass
    return None


def newer_reports(since):
    """File md/json trong các thư mục báo cáo, mtime >= since (mốc cập nhật)."""
    found = []
    if since is None:
        return found
    for d in REPORT_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        stack = [(base, 0)]
        while stack:
            root, depth = stack.pop()
            if depth > MAX_DEPTH:
                continue
            try:
                entries = os.scandir(root)
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIP_DIR_NAMES:
                            continue
                        stack.append((entry.path, depth + 1))
                    elif entry.name.endswith(".md") or entry.name.endswith(".json"):
                        p = entry.path
                        mtime = datetime.fromtimestamp(entry.stat().st_mtime)
                        if mtime >= since:
                            found.append((p, mtime))
                except OSError:
                    continue
    found.sort(key=lambda x: x[1], reverse=True)
    return found[:20]


def first_match(pattern, text):
    m = re.search(pattern, text)
    return m.groups() if m else None


def compare():
    """So sánh số liệu đang ghi trong AGENTS_TRANG_THAI.md với thực tế."""
    with open(STATUS_FILE, encoding="utf-8") as fh:
        doc = fh.read()

    actual = {
        "upgraded_zip": count("upgraded/*.zip"),
        "combos": count("combos/*.patch"),
        "combos_auto": count("combos_auto/*.patch"),
        "apk_trees": apk_tree_count(),
        "apks": count("Apks/*"),
    }
    audit = read_json("outputs/audit/audit.json")
    if audit:
        actual.update(audit_actual=audit)
    baseline = read_json("outputs/baseline/metrics.json")
    if baseline:
        actual.update(baseline_actual=baseline)
    combos_success = read_json("outputs/combos/combos_success.json")
    if isinstance(combos_success, list):
        actual["combos_success"] = len(combos_success)

    checks = [
        ("2.2 `upgraded/`", r"\|\s*`upgraded/`\s*\|.*?\*\*(\d+) zip\*\*",
         actual.get("upgraded_zip")),
        ("2.2 `combos/`", r"\|\s*`combos/`\s*\|.*?\*\*(\d+) hiện tại\*\*",
         actual.get("combos")),
        ("2.2 `combos_auto/`", r"\|\s*`combos_auto/`\s*\|.*?\*\*(\d+) hiện tại\*\*",
         actual.get("combos_auto")),
        ("2.2 `combos_success.json`", r"\|\s*`outputs/combos/`\s*\|.*?\*\*(\d+) lượt\*\*",
         actual.get("combos_success")),
        ("2.2 `Apks/`", r"\|\s*`Apks/`\s*\|.*?\*\*(\d+) APK\*\*",
         actual.get("apks")),
    ]
    mismatches = []
    for label, pattern, value in checks:
        if value is None:
            continue
        groups = first_match(pattern, doc)
        if groups and groups[0] != str(value):
            mismatches.append((label, groups[0], str(value)))
    return mismatches


def main():
    cwd = os.path.realpath(os.getcwd())
    root = os.path.realpath(ROOT)
    if cwd != root and not cwd.startswith(root + os.sep):
        print("BÁO CÁO TRẠNG THÁI: bỏ qua — phiên Codex hiện KHÔNG nằm trong")
        print("phạm vi thư mục làm việc toolkit ({}).".format(root))
        print("Chỉ báo tình trạng toolkit khi đang online trong thư mục làm")
        print("việc này + các thư mục con.")
        return 0

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    print("=== BÁO CÁO TRẠNG THÁI TỰ ĐỘNG (Codex online) ===")
    print("Thời điểm quét:", now)
    since = status_date()
    print("Mốc file trạng thái:", since.strftime("%Y-%m-%d") if since else "KHÔNG XÁC ĐỊNH")

    print()
    print("A. THÔNG TIN CƠ BẢN")
    g = git_state()
    if g:
        branch, desc, remote = g
        print("- Git: đã khởi tạo — nhánh {} · {} · remote {}".format(
            branch, desc, remote or "(chưa có remote)"))
    else:
        print("- Git: chưa khởi tạo (thay đổi cần backup thủ công)")

    baseline = read_json("outputs/baseline/metrics.json") or {}
    audit = read_json("outputs/audit/audit.json") or {}
    if baseline:
        print("- Test: {}/{} · Simulate: {}/{} · Golden: {}/{} · Build: {}s · errors: {}".format(
            baseline.get("test_pass", "?"), baseline.get("test_total", "?"),
            baseline.get("simulate_pass", "?"), baseline.get("simulate_total", "?"),
            baseline.get("golden_build_pass", "?"), baseline.get("golden_build_total", "?"),
            baseline.get("build_time_s", "?"), baseline.get("errors", "?")))
    if audit:
        print("- Audit ({}): {} patch — {} lỗi / {} cảnh báo / {} tự sửa được".format(
            audit.get("generated", "?"), audit.get("total", "?"),
            audit.get("errors", "?"), audit.get("warnings", "?"), audit.get("fixable", "?")))
    print("- Bộ patch: upgraded {} · combos {} · combos_auto {}".format(
        count("upgraded/*.zip"), count("combos/*.patch"), count("combos_auto/*.patch")))
    print("- APK: Apks/ {} · cây giải mã {} · combos_success {} lượt".format(
        count("Apks/*"), apk_tree_count(),
        len(read_json("outputs/combos/combos_success.json") or [])))
    print("- Behavior artifact: {} · Gadget APK: {}".format(
        count("outputs/behavior/artifacts/*"),
        count("outputs/behavior/gadget/*_signed.apk")))

    print()
    print("B. THÀNH PHẦN CẦN BỔ SUNG (file mới hơn mốc cập nhật)")
    newer = newer_reports(since)
    if newer:
        for p, mtime in newer:
            rel = os.path.relpath(p, ROOT)
            print("- {}  (mtime {})".format(rel, mtime.strftime("%Y-%m-%d %H:%M")))
    else:
        print("- Không có (hoặc chưa có mốc cập nhật hợp lệ).")

    print()
    print("C. SAI LỆCH SỐ LIỆU (file đang ghi vs thực tế trên đĩa)")
    mismatches = compare()
    if mismatches:
        for label, doc_val, real_val in mismatches:
            print("- {}: file ghi {} → thực tế {} (CẦN CẬP NHẬT mục này)".format(
                label, doc_val, real_val))
    else:
        print("- Không phát hiện sai lệch số liệu đã kiểm tra.")

    print()
    print("D. KHUYẾN NGHỊ")
    print("- Nếu mục B/C có kết quả: cập nhật ngay AGENTS_TRANG_THAI.md theo")
    print("  mục 0.2 (sửa số liệu + dòng Ngày cập nhật + mục 8), rồi báo cáo")
    print("  cho người dùng: thông tin cơ bản + các thành phần đã bổ sung.")
    print("- Muốn số đo mới nhất: chạy python3 -B tests/run_tests.py, patchx")
    print("  audit, patchx ci, patchx golden, baseline capture.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
