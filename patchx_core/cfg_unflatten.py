# -*- coding: utf-8 -*-
"""cfg_unflatten — Phát hiện, gỡ phẳng và cắt tỉa mã chết cho mã trung gian bị làm phẳng.

Bộ máy hoàn chỉnh cho mẫu làm phẳng luồng điều khiển kinh điển của R8/DexGuard:
    dispatcher: packed-switch/sparse-switch trên một "thanh ghi trạng thái"
    mỗi khối case: const state, N -> goto dispatcher

Luồng xử lý:
  1. detect_flattening/extract_switch_map: nhận diện khối điều phối và bảng trạng thái.
  2. trace_flattened_order: lần vết chuỗi const của thanh ghi trạng thái để dựng lại
     thứ tự khối gốc.
  3. unflatten_smali: GHI LẠI thân phương thức thành luồng tuần tự thật — bỏ khối
     điều phối + bảng switch, đổi `const+goto dispatcher` thành nhảy/fall-through trực
     tiếp tới khối kế tiếp, và xóa các khối chết không ai tham chiếu.
  4. unflatten_file/unflatten_tree: áp dụng lên tệp/cây, có sao lưu trước khi ghi.

Phạm vi trung thực: bộ máy này là BỘ PHÂN TÍCH + VIẾT LẠI cục bộ, không sửa phần
ngoài thân phương thức, giữ nguyên tên nhãn/thanh ghi còn được tham chiếu.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


RE_SWITCH = re.compile(
    r"^\s*(packed|sparse)-switch\s+([vp]\d+)\s*,\s*:(\w+)", re.M)
RE_CONST = re.compile(
    r"^\s*(const(?:/4|/16|/high16)?)\s+([vp]\d+)\s*,\s*(0x[0-9a-fA-F]+|-?\d+)")
RE_GOTO = re.compile(r"^\s*(goto(?:/16|/32)?)\s+:(\w+)")
RE_LABEL = re.compile(r"^\s*:([A-Za-z0-9_$]+)")
RE_IF_LIKE = re.compile(r"^\s*if-")


def _dispatcher_label(lines: List[str]) -> Optional[str]:
    """Nhãn của KHỐI chứa lệnh packed/sparse-switch (đích của các lệnh goto).

    Phân biệt với nhãn bảng dữ liệu mà lệnh switch trỏ tới (`:goto_data`).
    """
    for i, line in enumerate(lines):
        if RE_SWITCH.match(line):
            for j in range(i, -1, -1):
                m = RE_LABEL.match(lines[j])
                if m:
                    return ":" + m.group(1)
            return None
    return None


def _split_blocks(smali: str) -> Dict[str, str]:
    """Tách thân phương thức thành các khối theo nhãn (label -> văn bản khối)."""
    labels: List[Tuple[int, str]] = []
    lines = smali.splitlines()
    in_switch_data = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(".packed-switch") or s.startswith(".sparse-switch"):
            in_switch_data = True
            continue
        if s.startswith(".end packed-switch") or s.startswith(".end sparse-switch"):
            in_switch_data = False
            continue
        if in_switch_data:
            continue
        if s.startswith(":") and not s.startswith("::"):
            labels.append((i, s.split()[0]))
    blocks: Dict[str, str] = {}
    for idx, (start, label) in enumerate(labels):
        end = labels[idx + 1][0] if idx + 1 < len(labels) else len(lines)
        blocks[label] = "\n".join(lines[start:end])
    return blocks


def detect_flattening(smali: str) -> bool:
    """Nhận diện dấu hiệu làm phẳng: switch + goto + ít nhất 2 nhãn case."""
    has_switch = bool(re.search(r"\b(packed|sparse)-switch\b", smali))
    has_goto = bool(re.search(r"\bgoto(?:_16|_32)?\b", smali))
    cases = extract_switch_map(smali)
    return bool(has_switch and has_goto and len(cases) >= 2)


def extract_switch_map(smali: str) -> Dict[int, str]:
    """Đọc bảng switch: trạng thái (số) -> nhãn khối."""
    out: Dict[int, str] = {}
    m = re.search(r"\.packed-switch\s+([\d\-]+|0x[0-9a-fA-F]+)", smali)
    if m:
        start = m.end()
        end = smali.find(".end packed-switch", start)
        block = smali[start:end if end >= 0 else len(smali)]
        first = int(m.group(1), 0)
        labels = re.findall(r":([A-Za-z0-9_$]+)", block)
        for i, lab in enumerate(labels):
            out[first + i] = ":" + lab
        return out
    m = re.search(r"\.sparse-switch\s*$", smali, re.M)
    if m:
        start = m.end()
        end = smali.find(".end sparse-switch", start)
        block = smali[start:end if end >= 0 else len(smali)]
        for key, lab in re.findall(r"(0x[0-9a-fA-F]+|-?\d+)\s*->\s*:([A-Za-z0-9_$]+)", block):
            out[int(key, 0)] = ":" + lab
    return out


def _block_lines(lines: List[str], start: int, end: int) -> List[str]:
    return lines[start:end]


def _last_instruction_idx(lines: List[str], end_exclusive: int) -> int:
    i = end_exclusive - 1
    while i >= 0:
        s = lines[i].strip()
        if s and not s.startswith("#") and not s.startswith(".") and not s.startswith(":"):
            return i
        i -= 1
    return -1


def _const_value(line: str, state_reg: str) -> Optional[int]:
    m = RE_CONST.match(line)
    if not m or m.group(2) != state_reg:
        return None
    return int(m.group(3), 0)


def trace_flattened_order(smali: str) -> Dict[str, object]:
    """Lần vết biến trạng thái để dựng lại thứ tự khối gốc (chỉ đọc)."""
    switch = RE_SWITCH.search(smali)
    if not switch:
        return {"flattened": False, "reason": "không có lệnh switch dispatcher", "order": []}
    state_reg = switch.group(2)
    dispatcher_label = _dispatcher_label(smali.splitlines())
    if not dispatcher_label:
        return {"flattened": False, "reason": "khối điều phối không có nhãn", "order": []}
    case_map = extract_switch_map(smali)
    if len(case_map) < 2:
        return {"flattened": False, "reason": "bảng switch không đủ case", "order": []}
    blocks = _split_blocks(smali)

    start = None
    for m in re.finditer(r"const(?:/4|/16|/high16)?\s+%s\s*,\s*(0x[0-9a-fA-F]+|-?\d+)" % state_reg, smali):
        start = int(m.group(1), 0)
        break
    if start is None or start not in case_map:
        return {"flattened": False, "reason": "không tìm thấy trạng thái khởi đầu", "order": []}

    order: List[str] = []
    seen: set = set()
    cur: Optional[int] = start
    max_hops = len(case_map) + 2
    while cur is not None and cur in case_map and cur not in seen and len(order) < max_hops:
        seen.add(cur)
        label = case_map[cur]
        order.append(label)
        block = blocks.get(label, "")
        nxt = None
        # Ưu tiên const cuối cùng trước goto dispatcher (chính xác hơn với khối dài).
        consts = [int(x, 0) for x in re.findall(
            r"const(?:/4|/16|/high16)?\s+%s\s*,\s*(0x[0-9a-fA-F]+|-?\d+)" % state_reg, block)]
        if consts:
            nxt = consts[-1]
        cur = nxt
    return {
        "flattened": len(order) >= 2,
        "state_register": state_reg,
        "dispatcher": dispatcher_label,
        "order": order,
        "complete": len(order) == len(case_map),
    }


def find_dead_blocks(smali: str) -> List[str]:
    """Nhãn được định nghĩa nhưng không có lệnh nhảy/goto nào trỏ tới."""
    defined = set(":" + x for x in re.findall(r"^\s*:([A-Za-z0-9_$]+)", smali, re.M))
    referenced: set = set()
    for line in smali.splitlines():
        s = line.strip()
        if not s or s.startswith(":") or s.startswith("."):
            continue
        for m in re.finditer(r":([A-Za-z0-9_$]+)", s):
            referenced.add(":" + m.group(1))
    referenced |= set(extract_switch_map(smali).values())
    return sorted(d for d in defined if d not in referenced)


def linearize(smali: str) -> Dict[str, object]:
    """Đầu ra tổng hợp: có bị flatten không + thứ tự khối + khối chết."""
    trace = trace_flattened_order(smali)
    return {
        "flattened": bool(trace.get("flattened")),
        "reason": trace.get("reason"),
        "state_register": trace.get("state_register"),
        "block_order": trace.get("order", []),
        "complete": trace.get("complete"),
        "dead_blocks": find_dead_blocks(smali),
    }


def _label_refs(lines: List[str]) -> set:
    """Tập nhãn được tham chiếu từ lệnh rẽ nhánh/goto/catch trong các dòng."""
    refs: set = set()
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(".catch"):
            refs.update(":" + x for x in re.findall(r":([A-Za-z0-9_$]+)", s))
            continue
        if s.startswith(".") or s.startswith(":"):
            continue
        if RE_GOTO.match(s) or RE_IF_LIKE.match(s):
            for m in re.finditer(r":([A-Za-z0-9_$]+)", s):
                refs.add(":" + m.group(1))
    return refs


def _switch_data_indices(lines: List[str]) -> Tuple[Optional[int], Optional[int]]:
    start = end = None
    for i, line in enumerate(lines):
        s = line.strip()
        if start is None and (s.startswith(".packed-switch") or s.startswith(".sparse-switch")):
            start = i
        elif start is not None and (s.startswith(".end packed-switch") or s.startswith(".end sparse-switch")):
            end = i
            break
    return start, end


def unflatten_smali(method_text: str, min_cases: int = 2) -> Dict[str, object]:
    """Gỡ phẳng một phương thức smali và trả văn bản đã viết lại (nếu áp dụng được)."""
    base = {
        "flattened": False, "complete": False, "rewritten": False,
        "state_register": None, "dispatcher": None, "case_count": 0,
        "order": [], "dead_blocks_removed": [], "dispatcher_removed": False,
        "text": method_text, "fallback_reason": None,
        "original_lines": method_text.count("\n") + 1,
        "new_lines": method_text.count("\n") + 1,
    }

    lines = method_text.splitlines()
    end_method = next(
        (i for i, l in enumerate(lines) if l.strip().startswith(".end method")),
        len(lines),
    )
    body = lines[:end_method]
    tail = lines[end_method:]

    switch = RE_SWITCH.search("\n".join(body))
    if not switch:
        base["fallback_reason"] = "không có lệnh switch dispatcher"
        return base
    state_reg = switch.group(2)
    dispatcher_label = _dispatcher_label(body)
    if not dispatcher_label:
        base["fallback_reason"] = "khối điều phối không có nhãn"
        return base
    case_map = extract_switch_map(method_text)
    if len(case_map) < min_cases:
        base["fallback_reason"] = "bảng switch dưới %d case" % min_cases
        return base

    label_to_idx: Dict[str, int] = {}
    labels: List[Tuple[int, str]] = []
    for i, line in enumerate(body):
        m = RE_LABEL.match(line)
        if m:
            name = ":" + m.group(1)
            if name not in label_to_idx:
                label_to_idx[name] = i
                labels.append((i, name))
    labels.sort()
    label_names = [n for _, n in labels]

    trace = trace_flattened_order(method_text)
    if not trace.get("flattened"):
        base["flattened"] = False
        base["fallback_reason"] = str(trace.get("reason"))
        return base
    order: List[str] = [str(x) for x in trace["order"]]
    complete = bool(trace.get("complete"))
    base.update({
        "flattened": True, "complete": complete,
        "state_register": state_reg, "dispatcher": dispatcher_label,
        "case_count": len(case_map), "order": order,
    })

    # Khối prologue: phần trước nhãn đầu tiên (nếu có mã thật).
    first_label_idx = labels[0][0] if labels else len(body)
    prologue = body[:first_label_idx]
    has_prologue_code = any(
        l.strip() and not l.strip().startswith(".")
        for l in prologue
    )

    emitted: List[str] = []
    emitted_labels: set = set()

    # 1. Prologue (giữ nguyên, chỉ bỏ cặp const+goto dispatcher ở đuôi nếu có).
    prologue_block = list(prologue)
    if has_prologue_code:
        prologue_block = _strip_tail_step(prologue_block, state_reg, dispatcher_label)
        emitted.extend(prologue_block)

    # 2. Các khối case theo thứ tự đã lần vết.
    for lbl in order:
        start = label_to_idx.get(lbl)
        if start is None:
            continue
        nxt = None
        for j, (idx, name) in enumerate(labels):
            if name == lbl:
                nxt = labels[j + 1][0] if j + 1 < len(labels) else len(body)
                break
        block_lines = _strip_tail_step(body[start:nxt], state_reg, dispatcher_label)
        if emitted and emitted[-1] != "":
            emitted.append("")
        emitted.extend(block_lines)
        emitted_labels.add(lbl)

    # 3. Khối còn lại vẫn được tham chiếu (handler .catch, nhánh if nội bộ...).
    referenced = _label_refs(body)
    extras: List[List[str]] = []
    for idx, name in labels:
        if name in emitted_labels or name == dispatcher_label:
            continue
        if name not in referenced and name not in case_map.values():
            continue  # khối chết: không ai nhảy tới, không nằm trong chuỗi case
        nxt = None
        for j, (jdx, nm) in enumerate(labels):
            if nm == name:
                nxt = labels[j + 1][0] if j + 1 < len(labels) else len(body)
                break
        block_lines = _strip_tail_step(body[idx:nxt], state_reg, dispatcher_label)
        if emitted and emitted[-1] != "":
            emitted.append("")
        emitted.extend(block_lines)
        extras.append(name)

    # 4. Dispatcher: chỉ giữ nếu còn ai nhảy tới nó sau khi đã tháo goto.
    dispatcher_refs = any(
        RE_GOTO.match(l.strip()) and (":" + RE_GOTO.match(l.strip()).group(2)) == dispatcher_label
        for l in emitted
    )
    dispatcher_removed = not dispatcher_refs
    if dispatcher_refs:
        dstart = label_to_idx.get(dispatcher_label)
        if dstart is None:
            dispatcher_refs = False
            dispatcher_removed = True
    if dispatcher_refs:
        nxt = None
        for j, (idx, name) in enumerate(labels):
            if name == dispatcher_label:
                nxt = labels[j + 1][0] if j + 1 < len(labels) else len(body)
                break
        if emitted and emitted[-1] != "":
            emitted.append("")
        emitted.extend(body[dstart:nxt])
        emitted_labels.add(dispatcher_label)

    # 5. Cắt tỉa khối chết (đã bị loại ở bước 3) — thống kê.
    dead = [
        name for _, name in labels
        if name not in emitted_labels and name != dispatcher_label
        and name not in referenced and name not in case_map.values()
    ]
    base["dead_blocks_removed"] = dead
    base["dispatcher_removed"] = dispatcher_removed

    # 6. Lắp ráp: bỏ bảng switch nếu dispatcher bị gỡ; giữ .end method.
    sw_start, sw_end = _switch_data_indices(body)
    new_body = list(emitted)
    if sw_start is not None and not dispatcher_removed:
        if new_body and new_body[-1] != "":
            new_body.append("")
        new_body.extend(body[sw_start:sw_end + 1])
    new_lines = new_body + tail

    # Bỏ dòng trống thừa liên tiếp ở đuôi trước .end method.
    text = "\n".join(new_lines)
    base.update({
        "rewritten": True,
        "text": text,
        "new_lines": text.count("\n") + 1,
    })
    return base


def _strip_tail_step(block_lines: List[str], state_reg: str,
                     dispatcher_label: str) -> List[str]:
    """Bỏ cặp `const state, N` + `goto :dispatcher` ở đuôi khối (nếu đúng mẫu)."""
    out = list(block_lines)
    if not out:
        return out
    last = _last_instruction_idx(out, len(out))
    if last < 0:
        return out
    goto_m = RE_GOTO.match(out[last].strip())
    if not goto_m or (":" + goto_m.group(2)) != dispatcher_label:
        return out
    del out[last]
    prev = _last_instruction_idx(out, len(out))
    if prev >= 0 and _const_value(out[prev].strip(), state_reg) is not None:
        del out[prev]
    return out


def unflatten_file(path: str, apply: bool = False, backup: bool = True,
                   min_cases: int = 2, backup_root: Optional[str] = None) -> Dict[str, object]:
    """Gỡ phẳng mọi phương thức trong một tệp .smali."""
    p = Path(path)
    original = p.read_text(encoding="utf-8", errors="replace")
    method_pat = re.compile(
        r"(?ms)(^[ \t]*\.method[^\n]*\n.*?^[ \t]*\.end[ \t]+method)")
    methods_ok = methods_total = 0
    rewritten_blocks: List[Dict[str, object]] = []
    pos = 0
    pieces: List[str] = []
    for m in method_pat.finditer(original):
        pieces.append(original[pos:m.start()])
        res = unflatten_smali(m.group(1), min_cases=min_cases)
        methods_total += 1
        if res.get("rewritten"):
            methods_ok += 1
            rewritten_blocks.append({
                "method": m.group(1).splitlines()[0].strip(),
                "case_count": res.get("case_count"),
                "complete": res.get("complete"),
                "dead_blocks_removed": res.get("dead_blocks_removed"),
                "lines_before": res.get("original_lines"),
                "lines_after": res.get("new_lines"),
            })
        pieces.append(res.get("text") if res.get("rewritten") else m.group(1))
        pos = m.end()
    pieces.append(original[pos:])
    new_text = "".join(pieces)

    report: Dict[str, object] = {
        "file": str(p),
        "methods_total": methods_total,
        "methods_unflattened": methods_ok,
        "applied": False,
        "backup": None,
        "details": rewritten_blocks,
    }
    if methods_ok and apply:
        if backup:
            root = Path(backup_root or "outputs/backup/unflatten")
            try:
                rel = p.resolve().relative_to(Path.cwd().resolve())
            except ValueError:
                rel = Path(p.name)  # tệp ngoài cây làm việc: lưu theo tên tệp
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup_file = dest.with_name(p.name + ".bak." + stamp)
            backup_file.write_text(original, encoding="utf-8")
            report["backup"] = str(backup_file)
        p.write_text(new_text, encoding="utf-8")
        report["applied"] = True
    return report


def unflatten_tree(root: str, apply: bool = False, limit: int = 0,
                   min_cases: int = 2, backup_root: Optional[str] = None) -> Dict[str, object]:
    """Gỡ phẳng toàn bộ tệp .smali trong cây (có giới hạn số phương thức)."""
    root_path = Path(root)
    files = sorted(root_path.rglob("*.smali"))
    per_file: List[Dict[str, object]] = []
    total_methods = unflattened_methods = 0
    applied_files = 0
    for fp in files:
        if limit and unflattened_methods >= limit:
            break
        rep = unflatten_file(fp, apply=apply, backup=True,
                             min_cases=min_cases, backup_root=backup_root)
        per_file.append(rep)
        total_methods += int(rep["methods_total"])
        unflattened_methods += int(rep["methods_unflattened"])
        if rep["applied"]:
            applied_files += 1
    return {
        "root": str(root_path),
        "files_scanned": len(files),
        "files_unflattened": sum(1 for r in per_file if r["methods_unflattened"]),
        "files_applied": applied_files,
        "methods_total": total_methods,
        "methods_unflattened": unflattened_methods,
        "applied": apply,
        "details": per_file,
    }
