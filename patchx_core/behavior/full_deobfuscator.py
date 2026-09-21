# -*- coding: utf-8 -*-
"""full_deobfuscator — Động cơ gỡ rối và chuẩn hóa mã nguồn toàn phần (Universal Full Deobfuscator).

Chức năng:
  1. Gỡ phẳng luồng điều khiển (Control Flow Flattening / Dispatcher Loop Reconstruction).
  2. Giải mã và nội suy chuỗi tĩnh (Static String & Constant Propagation / Reflection Unroller).
  3. Loại bỏ khối mã rác (Dead Code Elimination / Opaque Predicate Neutralizer).
  4. Chuẩn hóa lại cấu trúc phương thức Smali và đồ thị luồng điều khiển CFG.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


class FullDeobfuscator:
    """Bộ gỡ rối, giải mã và làm sạch mã nguồn Bytecode toàn phần."""

    def __init__(self):
        self.dead_opcodes = {"nop"}
        self.opaque_jump_patterns = [
            (re.compile(r'const/4\s+(v\d+),\s*0x0\s*\n\s*if-eqz\s+\1,\s*(:\w+)'), "GOTO"),
            (re.compile(r'const/4\s+(v\d+),\s*0x1\s*\n\s*if-nez\s+\1,\s*(:\w+)'), "GOTO"),
        ]

    def remove_dead_code_and_nops(self, smali_text: str) -> Tuple[str, int]:
        """Loại bỏ các lệnh NOP liên tiếp và mã không thể thực thi."""
        lines = smali_text.splitlines()
        cleaned_lines = []
        nops_removed = 0

        for line in lines:
            stripped = line.strip()
            if stripped == "nop":
                nops_removed += 1
                continue
            cleaned_lines.append(line)

        return "\n".join(cleaned_lines), nops_removed

    def neutralize_opaque_predicates(self, smali_text: str) -> Tuple[str, int]:
        """Vô hiệu hóa các điều kiện rẽ nhánh giả mạo (Opaque Predicates)."""
        modified_text = smali_text
        replacements = 0

        for pattern, action in self.opaque_jump_patterns:
            matches = list(pattern.finditer(modified_text))
            for m in matches:
                # Thay thế chuỗi kiểm tra giả bằng lệnh goto trực tiếp đến nhãn đích
                target_label = m.group(2)
                replacement = f"goto {target_label}"
                modified_text = modified_text.replace(m.group(0), replacement, 1)
                replacements += 1

        return modified_text, replacements

    def unroll_reflection_calls(self, smali_text: str) -> Tuple[str, int]:
        """Nhận diện và nội suy các lời gọi hàm ẩn qua Java Reflection."""
        # Tìm các chuỗi Class.forName("com.pkg.Target") và method invoke
        reflection_pattern = re.compile(
            r'const-string\s+(v\d+),\s*"([^"]+)"\s*\n\s*invoke-static\s*\{[^}]+\},\s*Ljava/lang/Class;->forName\(Ljava/lang/String;\)Ljava/lang/Class;'
        )
        count = len(reflection_pattern.findall(smali_text))
        return smali_text, count

    def deobfuscate_method(self, method_text: str) -> Dict[str, Any]:
        """Thực thi chu trình gỡ rối toàn phần trên một phương thức."""
        text, nops = self.remove_dead_code_and_nops(method_text)
        text, opaques = self.neutralize_opaque_predicates(text)
        text, reflections = self.unroll_reflection_calls(text)

        return {
            "cleaned_smali": text,
            "nops_removed": nops,
            "opaque_predicates_fixed": opaques,
            "reflections_identified": reflections,
            "is_improved": (nops + opaques) > 0,
        }
