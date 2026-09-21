# -*- coding: utf-8 -*-
"""auto_gate_patcher — Tự động áp patch các Security Gates phát hiện bởi Zero-Workkey Taint Flow.

Khép kín chu trình Zero-Workkey:
  1. Đọc danh sách Security Gates từ smali_sem.detect_security_gates().
  2. Lọc các cổng logic có điểm tin cậy cao (Confidence >= min_confidence).
  3. Định vị tệp Smali và khối method tương ứng.
  4. Áp dụng chiến lược:
     - INVERT_BRANCH: Thay thế lệnh rẽ nhánh mục tiêu bằng lệnh đảo ngược (if-eqz <-> if-nez, ...).
     - RETURN_CONSTANT: Chèn 'const/4 v0, 0x1' + 'return v0' ở đầu method hoặc thay thế lệnh return.
  5. Xuất báo cáo tự động và lưu lịch sử can thiệp.
"""

from __future__ import annotations

import os
import re
import shutil
from typing import Any, Dict, List, Optional


def apply_security_gates(
    tree_dir: str,
    gates: Optional[List[Dict[str, Any]]] = None,
    min_confidence: float = 75.0,
    backup: bool = True,
) -> Dict[str, Any]:
    """Tự động can thiệp vào các cổng Security Gates trong cây Smali."""
    from .smali_sem import detect_security_gates

    if gates is None:
        gates = detect_security_gates(tree_dir, max_gates=50)

    applied = []
    skipped = []
    errors = []

    for gate in gates:
        conf = gate.get("confidence", 0.0)
        if conf < min_confidence:
            skipped.append({"gate": gate, "reason": f"Confidence {conf:.1f}% < {min_confidence:.1f}%"})
            continue

        rel_file = gate.get("file")
        if not rel_file:
            continue

        full_path = os.path.join(tree_dir, rel_file)
        if not os.path.isfile(full_path):
            found = False
            for root, _dirs, files in os.walk(tree_dir):
                if os.path.basename(rel_file) in files:
                    full_path = os.path.join(root, os.path.basename(rel_file))
                    found = True
                    break
            if not found:
                errors.append({"gate": gate, "error": f"Không tìm thấy tệp {rel_file}"})
                continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            from .smali_ast import parse_method_ast, SmaliAstMutator

            patch_info = gate.get("suggested_patch", {})
            ptype = patch_info.get("type")
            m_name = gate.get("method")
            modified_content = None

            # 1. Thử biến đổi bằng Smali AST Mutator trước (chính xác và chống rối mã 100%)
            if m_name:
                m_pattern = re.compile(
                    r"(?ms)^([ \t]*\.method[^\n]*\b" + re.escape(m_name) + r"\b[^\n]*\n.*?\n[ \t]*\.end\s+method)"
                )
                match = m_pattern.search(content)
                if match:
                    old_meth_text = match.group(1)
                    ast = parse_method_ast(old_meth_text)
                    if ast:
                        mutated = False
                        if ptype == "INVERT_BRANCH":
                            mutated = SmaliAstMutator.invert_first_matching_branch(ast)
                        elif ptype == "RETURN_CONSTANT":
                            mutated = SmaliAstMutator.bypass_security_check(ast)
                        if mutated:
                            new_meth_text = ast.render()
                            modified_content = content[:match.start(1)] + new_meth_text + content[match.end(1):]

            # 2. Cơ chế dự phòng (Fallback) nếu AST không khớp
            if not modified_content:
                if ptype == "INVERT_BRANCH":
                    target_branch = patch_info.get("target_branch")
                    inverted_branch = patch_info.get("inverted_branch")
                    if target_branch and inverted_branch and target_branch in content:
                        modified_content = content.replace(target_branch, inverted_branch, 1)

                elif ptype == "RETURN_CONSTANT":
                    val = patch_info.get("value", "0x1")
                    m_sig = gate.get("signature")
                    target_inst = patch_info.get("target_instruction")
                    target_branch = patch_info.get("target_branch")
                    inverted_branch = patch_info.get("inverted_branch")

                    if target_branch and inverted_branch and target_branch in content:
                        modified_content = content.replace(target_branch, inverted_branch, 1)
                    elif target_inst and target_inst in content:
                        reg = "v0"
                        replacement = f"const/4 {reg}, {val}\n    return {reg}"
                        modified_content = content.replace(target_inst, replacement, 1)
                    elif m_sig and m_sig in content:
                        m_idx = content.find(m_sig)
                        if m_idx != -1:
                            loc_match = re.search(r"(\s*\.(?:locals|registers)\s+\d+)", content[m_idx:])
                            if loc_match:
                                insert_pos = m_idx + loc_match.end()
                                bypass_code = f"\n    const/4 v0, {val}\n    return v0\n"
                                modified_content = content[:insert_pos] + bypass_code + content[insert_pos:]

            if modified_content and modified_content != content:
                if backup and not os.path.exists(full_path + ".bak"):
                    shutil.copy2(full_path, full_path + ".bak")
                with open(full_path, "w", encoding="utf-8") as fh:
                    fh.write(modified_content)

                # Kiểm chứng toán học tức thì bằng Micro DEX Emulator
                emul_verified = False
                emul_ret = None
                try:
                    from .dex_emulator import verify_method_bypass
                    test_text = new_meth_text if 'new_meth_text' in locals() and new_meth_text else modified_content
                    emul_res = verify_method_bypass(test_text)
                    emul_verified = emul_res.get("verified", False)
                    emul_ret = emul_res.get("return_value")
                except Exception:
                    pass

                applied.append({
                    "class": gate.get("class"),
                    "method": gate.get("method"),
                    "file": rel_file,
                    "type": ptype,
                    "confidence": conf,
                    "emulated_verified": emul_verified,
                    "emulated_return": emul_ret,
                })
            else:
                skipped.append({"gate": gate, "reason": "Không khớp mẫu can thiệp trực tiếp"})

        except Exception as e:
            errors.append({"gate": gate, "error": str(e)})

    return {
        "success": len(applied) > 0 or (len(gates) == 0),
        "total_gates": len(gates),
        "applied_count": len(applied),
        "applied": applied,
        "skipped_count": len(skipped),
        "errors_count": len(errors),
    }
