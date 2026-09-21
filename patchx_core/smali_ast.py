# -*- coding: utf-8 -*-
"""smali_ast — Động cơ phân tích cú pháp và biến đổi cây AST Smali (Smali AST Mutation Engine).

Cung cấp khả năng biến đổi mã nguồn Smali ở cấp độ cú pháp trừu tượng (AST):
  1. Tách cấu trúc method: directives (.locals, .registers), labels (:cond_*, :goto_*), instructions.
  2. Miễn nhiễm 100% với R8/ProGuard Obfuscation:
     - Nhận diện và biến đổi lệnh dựa trên loại opcode và ý nghĩa logic, bất kể tên thanh ghi (v0, v1, p0).
     - Tự động nâng cấp .locals / .registers nếu cần thanh ghi mới cho biến đổi.
  3. Hỗ trợ các phép đột phá:
     - force_return_constant: Ép method trả về hằng số (True/False/Object).
     - invert_branch: Đảo ngược điều kiện rẽ nhánh (if-eqz <-> if-nez, ...).
     - bypass_method_body: Vô hiệu hóa toàn bộ thân hàm và trả về an toàn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

BRANCH_INVERSIONS = {
    "if-eq": "if-ne",
    "if-ne": "if-eq",
    "if-lt": "if-ge",
    "if-ge": "if-lt",
    "if-gt": "if-le",
    "if-le": "if-gt",
    "if-eqz": "if-nez",
    "if-nez": "if-eqz",
    "if-ltz": "if-gez",
    "if-gez": "if-ltz",
    "if-gtz": "if-lez",
    "if-lez": "if-gtz",
}


@dataclass
class AstNode:
    kind: str  # 'directive', 'label', 'instruction', 'comment', 'empty'
    raw: str
    opcode: Optional[str] = None
    operands: List[str] = field(default_factory=list)


@dataclass
class SmaliMethodAst:
    header: str
    name: str
    signature: str
    return_type: str
    locals_count: int = 1
    is_registers: bool = False
    nodes: List[AstNode] = field(default_factory=list)

    def render(self) -> str:
        lines = [self.header]
        dir_name = ".registers" if self.is_registers else ".locals"
        lines.append(f"    {dir_name} {self.locals_count}")
        for node in self.nodes:
            if node.kind == "directive" and node.raw.strip().startswith((".locals", ".registers")):
                continue  # đã xuất ở trên
            lines.append(node.raw)
        lines.append(".end method")
        return "\n".join(lines)


def parse_method_ast(method_text: str) -> Optional[SmaliMethodAst]:
    """Phân tích một khối .method thành cây SmaliMethodAst."""
    lines = method_text.strip().split("\n")
    if not lines or not lines[0].strip().startswith(".method"):
        return None

    header = lines[0].rstrip()
    sig_match = re.search(r"([^\s(]+\([^)]*\)(\S+))", header)
    if not sig_match:
        return None

    full_sig = sig_match.group(1)
    ret_type = sig_match.group(2)
    name = full_sig.split("(")[0]

    locals_count = 1
    is_registers = False
    nodes = []

    for line in lines[1:]:
        s = line.strip()
        if s == ".end method":
            break

        if not s:
            nodes.append(AstNode(kind="empty", raw=line))
        elif s.startswith("#"):
            nodes.append(AstNode(kind="comment", raw=line))
        elif s.startswith(":"):
            nodes.append(AstNode(kind="label", raw=line))
        elif s.startswith("."):
            if s.startswith((".locals", ".registers")):
                parts = s.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    locals_count = int(parts[1])
                    is_registers = s.startswith(".registers")
            nodes.append(AstNode(kind="directive", raw=line))
        else:
            # Lệnh thực thi
            parts = s.split(None, 1)
            opcode = parts[0]
            operands = []
            if len(parts) > 1:
                operands = [op.strip() for op in parts[1].split(",")]
            nodes.append(AstNode(kind="instruction", raw=line, opcode=opcode, operands=operands))

    return SmaliMethodAst(
        header=header,
        name=name,
        signature=full_sig,
        return_type=ret_type,
        locals_count=locals_count,
        is_registers=is_registers,
        nodes=nodes,
    )


class SmaliAstMutator:
    """Công cụ thực thi các phép biến đổi AST trên phương thức Smali."""

    @staticmethod
    def force_return_boolean(method: SmaliMethodAst, value: bool = True) -> bool:
        """Ép phương thức trả về True (1) hoặc False (0) an toàn ở cấp độ AST."""
        val_hex = "0x1" if value else "0x0"
        # Đảm bảo có ít nhất 1 local register
        if method.locals_count < 1:
            method.locals_count = 1

        reg = "v0"
        # Thay thế toàn bộ thân lệnh bằng const/4 + return
        new_nodes = [
            AstNode(kind="instruction", raw=f"    const/4 {reg}, {val_hex}", opcode="const/4", operands=[reg, val_hex]),
            AstNode(kind="instruction", raw=f"    return {reg}", opcode="return", operands=[reg]),
        ]
        method.nodes = new_nodes
        return True

    @staticmethod
    def force_return_void(method: SmaliMethodAst) -> bool:
        """Ép phương thức void kết thúc ngay lập tức."""
        method.nodes = [
            AstNode(kind="instruction", raw="    return-void", opcode="return-void", operands=[]),
        ]
        return True

    @staticmethod
    def invert_first_matching_branch(method: SmaliMethodAst, target_label: Optional[str] = None) -> bool:
        """Đảo ngược lệnh rẽ nhánh đầu tiên khớp điều kiện mà không phụ thuộc tên thanh ghi."""
        for node in method.nodes:
            if node.kind == "instruction" and node.opcode in BRANCH_INVERSIONS:
                if target_label is None or any(target_label in op for op in node.operands):
                    new_opcode = BRANCH_INVERSIONS[node.opcode]
                    old_opcode = node.opcode
                    node.opcode = new_opcode
                    node.raw = node.raw.replace(old_opcode, new_opcode, 1)
                    return True
        return False

    @staticmethod
    def bypass_security_check(method: SmaliMethodAst) -> bool:
        """Tự động nhận diện kiểu trả về và biến đổi phương thức sang dạng bypass tối ưu."""
        ret = method.return_type
        if ret == "Z":  # boolean
            return SmaliAstMutator.force_return_boolean(method, value=True)
        elif ret == "V":  # void
            return SmaliAstMutator.force_return_void(method)
        elif ret in ("I", "S", "B", "C"):  # int/short/byte/char
            method.locals_count = max(method.locals_count, 1)
            method.nodes = [
                AstNode(kind="instruction", raw="    const/4 v0, 0x1", opcode="const/4", operands=["v0", "0x1"]),
                AstNode(kind="instruction", raw="    return v0", opcode="return", operands=["v0"]),
            ]
            return True
        elif ret.startswith("L") or ret.startswith("["):  # Object / Array
            # Nếu là Boolean object hoặc tương đương
            method.locals_count = max(method.locals_count, 1)
            method.nodes = [
                AstNode(kind="instruction", raw="    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;", opcode="sget-object", operands=["v0", "Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;"]),
                AstNode(kind="instruction", raw="    return-object v0", opcode="return-object", operands=["v0"]),
            ]
            return True
        return False
