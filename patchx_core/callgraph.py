# -*- coding: utf-8 -*-
"""callgraph — Dựng đồ thị cuộc gọi tĩnh từ cây mã trung gian (smali).

Chỉ đọc, nhanh: duyệt các tệp .smali, trích chữ ký `.method` và các lệnh
`invoke-*` để dựng cạnh người gọi -> người được gọi. Kết quả gồm:
  - nodes: danh sách phương thức (kèm số lời gọi đi/đến)
  - edges: danh sách cạnh gọi
  - top_callers / top_callees: xếp hạng theo mật độ gọi
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional


RE_METHOD = re.compile(r"^\s*\.method\s+([^\n]+)", re.M)
RE_INVOKE = re.compile(
    r"^\s*invoke-(?:virtual|super|direct|static|interface|virtual/range|"
    r"super/range|direct/range|static/range|interface/range|polymorphic|"
    r"polymorphic/range|custom|custom/range)\s+[^\n]*?->([^\s]+)",
    re.M,
)


def _short_method(sig: str) -> str:
    sig = sig.strip()
    return re.sub(r"\s+", " ", sig)[:160]


def _callee_key(ref: str) -> str:
    """Tách class->method thành khóa gọn."""
    ref = ref.strip()
    if "->" in ref:
        return ref
    return ref


def build_call_graph(
    tree_root: str,
    limit: int = 500,
    file_limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Duyệt cây smali và trả đồ thị cuộc gọi có giới hạn."""
    root = Path(tree_root)
    files = sorted(root.rglob("*.smali"))
    if file_limit:
        files = files[:file_limit]

    method_files: Dict[str, str] = {}
    edges: Counter = Counter()
    callee_count: Counter = Counter()
    caller_count: Counter = Counter()

    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in RE_METHOD.finditer(text):
            key = _short_method(m.group(1))
            method_files[key] = str(fp)
        for m in RE_INVOKE.finditer(text):
            target = _callee_key(m.group(1))
            callee_count[target] += 1

    # Cần duyệt lần hai để biết phương thức gọi nằm trong khối nào.
    current: Optional[str] = None
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            s = lines[i].strip()
            if s.startswith(".method"):
                current = _short_method(" ".join(s.split()[1:]))
                i += 1
                while i < len(lines) and lines[i].strip() != ".end method":
                    im = RE_INVOKE.match(lines[i])
                    if im:
                        target = _callee_key(im.group(1))
                        edges[(current, target)] += 1
                        caller_count[current] += 1
                    i += 1
            else:
                i += 1

    top_edges = edges.most_common(limit)
    nodes: List[Dict[str, Any]] = []
    seen: set = set()
    for (caller, callee), weight in top_edges:
        if caller not in seen:
            seen.add(caller)
            nodes.append({
                "id": caller,
                "out_degree": caller_count.get(caller, 0),
                "file": method_files.get(caller, ""),
            })
        if callee not in seen:
            seen.add(callee)
            nodes.append({
                "id": callee,
                "in_degree": callee_count.get(callee, 0),
                "file": method_files.get(callee, ""),
            })

    edge_list = [{"from": a, "to": b, "weight": w} for (a, b), w in top_edges]
    return {
        "root": str(root),
        "files_scanned": len(files),
        "methods_found": len(method_files),
        "edges_total": len(edge_list),
        "edges_shown": len(edge_list),
        "nodes": nodes[:limit],
        "edges": edge_list,
        "top_callees": [{"method": k, "calls": v}
                        for k, v in callee_count.most_common(25)],
        "top_callers": [{"method": k, "calls": v}
                        for k, v in caller_count.most_common(25)],
    }


def render_callgraph_text(report: Dict[str, Any]) -> str:
    """Bản tóm tắt văn bản dễ đọc của đồ thị cuộc gọi."""
    lines = [
        f"Đồ thị cuộc gọi: {report['root']}",
        f"Tệp quét: {report['files_scanned']} · phương thức: "
        f"{report['methods_found']} · cạnh hiển thị: {report['edges_shown']}",
        "",
        "Top phương thức được gọi nhiều nhất:",
    ]
    for item in report["top_callees"][:10]:
        lines.append(f"  {item['calls']:>6}  {item['method']}")
    lines.append("")
    lines.append("Top phương thức gọi đi nhiều nhất:")
    for item in report["top_callers"][:10]:
        lines.append(f"  {item['calls']:>6}  {item['method']}")
    lines.append("")
    lines.append("Mẫu cạnh gọi:")
    for e in report["edges"][:15]:
        lines.append(f"  {e['from'][:70]}  ->  {e['to'][:70]}")
    return "\n".join(lines)
