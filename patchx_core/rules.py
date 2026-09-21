#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patchx_core/rules.py — Tầng lõi quản lý và bảo toàn quy tắc toàn cục của Toolkit.

Mệnh lệnh từ User (2026-09-19):
- Những quy điều được áp dụng trên toàn cục phải lấy Toolkit làm gốc.
- Khi push lên git hoặc đóng gói xuất bản đều phải được xuất theo Toolkit như điều
  kiện bắt buộc để khi xuất bản vẫn giữ được đúng với bản gốc tối đa.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Tuple


MANDATORY_RULES = [
    "toolkit.md",                  # Tầng 2: Quy tắc phát triển Toolkit (Cốt lõi tối cao)
    "apk.md",                      # Tầng 2: Quy tắc sửa & xử lý APK/Target (Cốt lõi tối cao)
    "QUY_TAC_NGUOI_DUNG.md",       # Tầng tổng hợp toàn diện & Nguồn chuẩn duy nhất
    "GEMINI.md",                   # Tầng 3: Tệp ánh xạ đối chiếu Gemini CLI
    "CLAUDE.md",                   # Tầng 3: Tệp ánh xạ đối chiếu Claude CLI
    "AGENTS.md",                   # Tầng 3: Tệp ánh xạ đối chiếu Codex / Agents
    "KINH_NGHIEM_HOC_HOI.md",      # Kho tri thức kinh nghiệm học hỏi
]


def get_toolkit_root() -> str:
    """Trả về thư mục gốc của Toolkit."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def verify_rule_integrity(base_dir: str | None = None) -> Dict[str, any]:
    """
    Kiểm tra tính toàn vẹn của toàn bộ hệ thống quy tắc cốt lõi.
    Được gọi bởi doctor, package, và các pipeline xuất bản.
    """
    if base_dir is None:
        base_dir = get_toolkit_root()

    results = {
        "ok": True,
        "total": len(MANDATORY_RULES),
        "present": 0,
        "missing": [],
        "details": {}
    }

    for item in MANDATORY_RULES:
        full_path = os.path.join(base_dir, item)
        if os.path.exists(full_path):
            results["present"] += 1
            if os.path.isdir(full_path):
                file_count = len([f for f in os.listdir(full_path) if not f.startswith(".")])
                results["details"][item] = f"Thư mục ({file_count} tệp quy tắc nguồn chuẩn)"
            else:
                size = os.path.getsize(full_path)
                results["details"][item] = f"Tệp ({size} bytes)"
        else:
            results["ok"] = False
            results["missing"].append(item)
            results["details"][item] = "THIẾU (Không tìm thấy)"

    return results


def get_mandatory_rule_files(base_dir: str | None = None) -> List[str]:
    """
    Trả về danh sách tất cả các tệp quy tắc bắt buộc cần đưa vào gói đóng gói
    hoặc kiểm tra git.
    """
    if base_dir is None:
        base_dir = get_toolkit_root()

    rule_files = []
    for item in MANDATORY_RULES:
        full_path = os.path.join(base_dir, item)
        if os.path.isdir(full_path):
            for root, _, files in os.walk(full_path):
                for f in files:
                    if not f.startswith("."):
                        rel = os.path.relpath(os.path.join(root, f), base_dir)
                        rule_files.append(rel)
        elif os.path.isfile(full_path):
            rule_files.append(item)

    return sorted(rule_files)


def print_rule_status(base_dir: str | None = None) -> bool:
    """In trạng thái kiểm tra quy tắc cốt lõi ra màn hình dòng lệnh."""
    status = verify_rule_integrity(base_dir)
    print("\033[1m\033[95m[TẦNG LÕI TOOLKIT] Kiểm tra quy tắc cốt lõi hệ thống:\033[0m")
    for rule, info in status["details"].items():
        if "THIẾU" in info:
            print(f"  \033[91m✖ {rule}: {info}\033[0m")
        else:
            print(f"  \033[92m✔ {rule}: {info}\033[0m")

    if status["ok"]:
        print(f"\033[92m➔ Toàn bộ {status['present']}/{status['total']} quy tắc cốt lõi đã hiện diện đầy đủ, lấy Toolkit làm gốc.\033[0m\n")
    else:
        print(f"\033[91m➔ CẢNH BÁO: Thiếu {len(status['missing'])} quy tắc cốt lõi! Cần bổ sung trước khi xuất bản.\033[0m\n")

    return status["ok"]


if __name__ == "__main__":
    ok = print_rule_status()
    sys.exit(0 if ok else 1)
