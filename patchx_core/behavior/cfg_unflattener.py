# -*- coding: utf-8 -*-
"""Lớp giao diện cấp cao cho bộ máy gỡ phẳng luồng mã (bản chuẩn nằm ở core).

Bộ máy duy nhất được định nghĩa tại `patchx_core.cfg_unflatten` (nguồn chuẩn,
tránh trùng lặp logic). Module này chỉ là lớp giao diện mỏng phục vụ các mã
đang nhập theo đường `patchx_core.behavior.cfg_unflattener`.
"""

from __future__ import annotations

from typing import Dict, Optional

from ..cfg_unflatten import (
    detect_flattening,
    extract_switch_map,
    find_dead_blocks,
    linearize,
    trace_flattened_order,
    unflatten_smali,
)

__all__ = [
    "SymbolicState",
    "CFGUnflattener",
    "detect_flattening",
    "extract_switch_map",
    "trace_flattened_order",
    "find_dead_blocks",
    "linearize",
    "unflatten_smali",
]


class SymbolicState:
    """Trạng thái thanh ghi tượng trưng (tương thích API cũ)."""

    def __init__(self) -> None:
        self.registers: Dict[str, int] = {}

    def clone(self) -> "SymbolicState":
        new_state = SymbolicState()
        new_state.registers = self.registers.copy()
        return new_state


class CFGUnflattener:
    """Trình khử làm phẳng luồng mã — ủy quyền cho bộ máy chuẩn ở core."""

    def __init__(self, smali: str, min_cases: int = 2) -> None:
        self.smali = smali
        self.min_cases = min_cases
        self.result: Dict[str, object] = {}

    def find_dispatcher(self) -> bool:
        self.result = trace_flattened_order(self.smali)
        return bool(self.result.get("flattened"))

    def unflatten(self) -> int:
        """Gỡ phẳng; trả về số lượng khối chết + khối điều phối đã loại bỏ."""
        res = unflatten_smali(self.smali, min_cases=self.min_cases)
        self.result = res
        if not res.get("rewritten"):
            return 0
        removed = len(res.get("dead_blocks_removed") or [])
        if res.get("dispatcher_removed"):
            removed += 1
        return removed
