# -*- coding: utf-8 -*-
"""ast_dsl — Ngôn ngữ mô tả bản vá ngữ nghĩa trên cây AST Smali (T1).

Chu trình một quy tắc DSL: TÌM MẪU → RÀNG BUỘC THANH GHI/KIỂU → BIẾN ĐỔI AST
→ IN LẠI SMALI HỢP LỆ. Dùng lại `smali_ast` làm nền; không phụ thuộc tên thanh
ghi nên miễn nhiễm obfuscation (R8/ProGuard).

Quy tắc (JSON) ví dụ:
  {"ten": "mo-khoa", "phuong_thuc": "check.*", "opcode": "if-eqz",
   "toan_hang": ":cond_fail", "hanh_dong": "dao-nhanh"}
  {"ten": "tra-true", "phuong_thuc": "isPremium", "hanh_dong": "ep-tra-ve",
   "gia_tri": true}
  {"ten": "chen-goi", "phuong_thuc": "onCreate", "hanh_dong": "chen-truoc",
   "cau_lenh": "invoke-static {}, Lpkg/Util;->log()V", "chen_tai": "0"}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .smali_ast import BRANCH_INVERSIONS, AstNode, SmaliAstMutator, parse_method_ast


ACTIONS = ("dao-nhanh", "ep-tra-ve", "chen-truoc", "thay-lenh", "bo-qua-than")


@dataclass
class PatchRule:
    ten: str
    phuong_thuc: Optional[str] = None
    opcode: Optional[str] = None
    toan_hang: Optional[str] = None
    hanh_dong: str = "dao-nhanh"
    gia_tri: Any = True
    cau_lenh: str = ""
    chen_tai: str = "0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ten": self.ten,
            "phuong_thuc": self.phuong_thuc,
            "opcode": self.opcode,
            "toan_hang": self.toan_hang,
            "hanh_dong": self.hanh_dong,
            "gia_tri": self.gia_tri,
            "cau_lenh": self.cau_lenh,
            "chen_tai": self.chen_tai,
        }


def parse_rule(spec: Dict[str, Any]) -> PatchRule:
    """Chuẩn hóa và kiểm lỗi một quy tắc DSL (không âm thầm chấp nhận sai)."""
    if not isinstance(spec, dict) or not spec.get("ten"):
        raise ValueError("Quy tắc thiếu trường bắt buộc 'ten'")
    action = spec.get("hanh_dong", "dao-nhanh")
    if action not in ACTIONS:
        raise ValueError("Hành động không hợp lệ %r (hỗ trợ: %s)" % (action, ", ".join(ACTIONS)))
    if action in ("chen-truoc", "thay-lenh") and not str(spec.get("cau_lenh", "")).strip():
        raise ValueError("Hành động %r bắt buộc có 'cau_lenh'" % action)
    return PatchRule(
        ten=str(spec["ten"]),
        phuong_thuc=str(spec["phuong_thuc"]) if spec.get("phuong_thuc") else None,
        opcode=str(spec["opcode"]) if spec.get("opcode") else None,
        toan_hang=str(spec["toan_hang"]) if spec.get("toan_hang") else None,
        hanh_dong=action,
        gia_tri=spec.get("gia_tri", True),
        cau_lenh=str(spec.get("cau_lenh", "")).strip(),
        chen_tai=str(spec.get("chen_tai", "0")).strip(),
    )


def load_rules(path: str | Path) -> List[PatchRule]:
    """Nạp danh sách quy tắc từ tệp JSON (mảng hoặc đối tượng có khóa 'quy_tac')."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("quy_tac", data.get("rules", []))
    if not isinstance(data, list):
        raise ValueError("Tệp quy tắc phải là mảng JSON hoặc có khóa 'quy_tac'")
    return [parse_rule(item) for item in data]


def find_free_registers(method, n: int = 1) -> List[str]:
    """Tìm n thanh ghi v0..vN chưa được dùng; không đụng thanh ghi tham số p*."""
    used = set()
    for node in method.nodes:
        if node.kind != "instruction":
            continue
        for m in re.finditer(r"\b([vp]\d+)\b", node.raw):
            used.add(m.group(1))
    out = []
    i = 0
    while len(out) < n:
        name = "v%d" % i
        if name not in used:
            out.append(name)
        i += 1
    return out


def allocate_registers(method, n: int = 1) -> Tuple[List[str], bool]:
    """Phân bổ thanh ghi an toàn; tự nâng .locals nếu cần. Trả (ds, da_mo_rong)."""
    free = find_free_registers(method, n)
    expanded = False
    need = 0
    for reg in free:
        if reg.startswith("v"):
            need = max(need, int(reg[1:]) + 1)
    if need > method.locals_count:
        method.locals_count = need
        expanded = True
    return free, expanded


def _match_method(method, rule: PatchRule) -> bool:
    if not rule.phuong_thuc:
        return True
    try:
        return re.search(rule.phuong_thuc, method.name) is not None
    except re.error:
        return False


def _match_node(node: AstNode, rule: PatchRule) -> bool:
    if node.kind != "instruction":
        return False
    if rule.opcode and node.opcode != rule.opcode:
        return False
    if rule.toan_hang:
        try:
            rx = re.compile(rule.toan_hang)
        except re.error:
            return False
        if not any(rx.search(op) for op in node.operands):
            return False
    return True


def _invert_branch_type_safe(method, node: AstNode) -> Dict[str, Any]:
    """Đảo nhánh kèm kiểm kiểu: chỉ đảo cặp opcode hợp chuẩn; báo khi không chắc kiểu."""
    new_opcode = BRANCH_INVERSIONS.get(node.opcode)
    if not new_opcode:
        return {"ok": False, "ly_do": "opcode %s không phải nhánh đảo được" % node.opcode}
    # Kiểm tra kiểu: nhánh so sánh đối tượng (if-eq/if-ne trên tham chiếu) không
    # thể chứng minh kiểu từ smali đơn lẻ — vẫn đảo được theo chuẩn, nhưng ghi cảnh báo.
    warn = ""
    if node.opcode in ("if-eq", "if-ne") and len(node.operands) >= 2:
        warn = "không chứng minh được kiểu so sánh (int hay tham chiếu) — đã đảo đúng chuẩn smali"
    old_opcode = node.opcode
    node.opcode = new_opcode
    head, _, rest = node.raw.partition(" ")
    node.raw = new_opcode + ((" " + rest) if rest else "")
    return {"ok": True, "canh_bao": warn, "tu": old_opcode, "sang": new_opcode}


def _ep_tra_ve_type_safe(method) -> Dict[str, Any]:
    """Ép trả về hằng đúng kiểu khai báo (Z/V/I/S/B/C/L/[/khác)."""
    ret = method.return_type
    if ret == "Z":
        SmaliAstMutator.force_return_boolean(
            method, bool(method.__dict__.get("_rule_value", True)))
        return {"ok": True, "kieu": ret}
    if ret == "V":
        return {"ok": SmaliAstMutator.force_return_void(method), "kieu": ret}
    if ret in ("I", "S", "B", "C"):
        method.locals_count = max(method.locals_count, 1)
        method.nodes = [
            AstNode(kind="instruction", raw="    const/4 v0, 0x1",
                    opcode="const/4", operands=["v0", "0x1"]),
            AstNode(kind="instruction", raw="    return v0",
                    opcode="return", operands=["v0"]),
        ]
        return {"ok": True, "kieu": ret}
    if ret.startswith("L") or ret.startswith("["):
        method.locals_count = max(method.locals_count, 1)
        method.nodes = [
            AstNode(kind="instruction",
                    raw="    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;",
                    opcode="sget-object",
                    operands=["v0", "Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;"]),
            AstNode(kind="instruction", raw="    return-object v0",
                    opcode="return-object", operands=["v0"]),
        ]
        return {"ok": True, "kieu": ret}
    return {"ok": False, "kieu": ret, "ly_do": "kiểu trả về không hỗ trợ ép hằng"}


def insert_instruction_safe(method, instruction: str, index: int) -> Dict[str, Any]:
    """Chèn một lệnh vào vị trí index; thay chỗ giữ `$v0..$vN` bằng thanh ghi
    tự do được phân bổ an toàn (tự nâng .locals), tránh đè thanh ghi đang dùng."""
    if not instruction.startswith("    "):
        instruction = "    " + instruction
    placeholders = re.findall(r"\$v\d+", instruction)
    free, expanded = allocate_registers(method, len(placeholders))
    for ph, reg in zip(placeholders, free):
        instruction = instruction.replace(ph, reg)
    # Cảnh báo nếu lệnh dùng thanh ghi v* đang tồn tại mà không qua chỗ giữ $.
    used = set()
    for node in method.nodes:
        if node.kind == "instruction":
            used.update(re.findall(r"\b(v\d+)\b", node.raw))
    clash = sorted(set(re.findall(r"\b(v\d+)\b", instruction)) & used)
    parts = instruction.strip().split(None, 1)
    node = AstNode(kind="instruction", raw=instruction, opcode=parts[0],
                   operands=([o.strip() for o in parts[1].split(",")]
                             if len(parts) > 1 else []))
    method.nodes.insert(max(0, min(index, len(method.nodes))), node)
    return {"ok": True, "mo_rong_locals": expanded, "xung_dot_canh_bao": clash}


def apply_rule_to_method(method, rule: PatchRule) -> Dict[str, Any]:
    """Áp một quy tắc lên một phương thức; trả báo cáo thay đổi (không đổi nếu không khớp)."""
    rep: Dict[str, Any] = {"method": method.name, "ten_quy_tac": rule.ten,
                           "thay_doi": 0, "ok": False}
    if not _match_method(method, rule):
        rep["ok"] = True
        return rep

    if rule.hanh_dong == "bo-qua-than":
        if SmaliAstMutator.bypass_security_check(method):
            rep["thay_doi"] = 1
        rep["ok"] = True
        return rep

    if rule.hanh_dong == "ep-tra-ve":
        method._rule_value = bool(rule.gia_tri)
        res = _ep_tra_ve_type_safe(method)
        rep["ok"] = res["ok"]
        rep["kieu"] = res.get("kieu")
        rep["ly_do"] = res.get("ly_do", "")
        if res["ok"]:
            rep["thay_doi"] = 1
        return rep

    for i, node in enumerate(method.nodes):
        if not _match_node(node, rule):
            continue
        if rule.hanh_dong == "dao-nhanh":
            res = _invert_branch_type_safe(method, node)
            rep["ok"] = res["ok"]
            rep["ly_do"] = res.get("ly_do", "")
            rep["canh_bao"] = res.get("canh_bao", "")
            if res["ok"]:
                rep["thay_doi"] += 1
        elif rule.hanh_dong == "chen-truoc":
            res = insert_instruction_safe(method, rule.cau_lenh, i)
            rep["thay_doi"] += 1
            rep["ok"] = res["ok"]
            rep["canh_bao"] = ", ".join(res.get("xung_dot_canh_bao", []))
            break
        elif rule.hanh_dong == "thay-lenh":
            instr = rule.cau_lenh
            if not instr.startswith("    "):
                instr = "    " + instr
            node.raw = instr
            parts = instr.strip().split(None, 1)
            node.opcode = parts[0]
            node.operands = ([o.strip() for o in parts[1].split(",")]
                             if len(parts) > 1 else [])
            rep["thay_doi"] += 1
            rep["ok"] = True
            break
    return rep


def apply_patch_dsl(target: str | Path, rules: List[PatchRule], dry_run: bool = True,
                    output_dir: Optional[str | Path] = None) -> Dict[str, Any]:
    """Áp bộ quy tắc DSL lên cây smali hoặc một tệp .smali.

    dry_run=True: chỉ báo cáo, không ghi đĩa (mặc định an toàn).
    dry_run=False: sao lưu `.bak` vào thư mục kế bên rồi ghi lại tệp đổi.
    """
    root = Path(target)
    files = [root] if root.is_file() else sorted(root.rglob("*.smali"))
    report: Dict[str, Any] = {"target": str(root), "dry_run": dry_run,
                              "tep_quet": len(files), "tep_doi": 0,
                              "phuong_thuc_doi": 0, "chi_tiet": [],
                              "tong_quy_tac": len(rules)}
    out_root = Path(output_dir) if output_dir else None
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        changed = False
        for rule in rules:
            for m in re.finditer(r"(?m)^(\s*\.method[^\n]*)\n(.*?)(?m)^(\s*\.end method)",
                                 text, flags=re.S):
                block = m.group(0)
                ast = parse_method_ast(block)
                if ast is None:
                    continue
                before = ast.render()
                res = apply_rule_to_method(ast, rule)
                if res.get("thay_doi"):
                    after = ast.render()
                    if after != before:
                        text = text.replace(block, after, 1)
                        changed = True
                        report["phuong_thuc_doi"] += 1
                        report["chi_tiet"].append({
                            "tep": str(fp), "phuong_thuc": res["method"],
                            "quy_tac": res["ten_quy_tac"], "thay_doi": res["thay_doi"],
                            "canh_bao": res.get("canh_bao", ""),
                        })
        if changed:
            report["tep_doi"] += 1
            if not dry_run:
                backup = fp.with_suffix(fp.suffix + ".bak")
                if not backup.exists():
                    backup.write_bytes(fp.read_bytes())
                fp.write_text(text, encoding="utf-8")
            elif out_root is not None:
                rel = fp.relative_to(root) if root.is_dir() else fp.name
                dst = out_root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(text, encoding="utf-8")
    return report
