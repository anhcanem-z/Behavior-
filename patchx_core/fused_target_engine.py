# -*- coding: utf-8 -*-
"""fused_target_engine — Động cơ hợp nhất đa nguồn giữa Behavior Targets và Zero-Workkey Security Gates.

Cộng hưởng thông minh giữa 2 chiều phân tích:
  1. Chiều Hành vi (Behavior Ontology & CFG): Hiểu rõ ngữ cảnh nghiệp vụ, sự kiện UI, SDK thanh toán, mạng.
  2. Chiều Ngữ nghĩa sâu (Zero-Workkey Taint Flow): Lần vết thanh ghi từ API nhạy cảm đến điểm rẽ nhánh if-* / return.

Phân hạng mục tiêu (Target Tiering):
  - Hạng 1 (DUAL_CONFIRMED - 100%): Được CẢ HAI hệ thống độc lập cùng chỉ điểm -> Ưu tiên can thiệp số 1.
  - Hạng 2 (SECURITY_GATES - 80-90%): Cổng bảo vệ logic rẽ nhánh ẩn (chống R8 obfuscation).
  - Hạng 3 (BEHAVIOR_TARGETS - 50-80%): Điểm móc kiểm tra nghiệp vụ và hook Frida.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple


def _normalize_class(cls_name: str) -> str:
    """Chuẩn hóa class sang dạng Java chấm (com.example.Class)."""
    c = str(cls_name or "").strip()
    if c.startswith("L") and c.endswith(";"):
        c = c[1:-1]
    c = c.replace("/", ".").replace("\\", ".")
    if c.endswith(".smali"):
        c = c[:-6]
    return c


def fuse_analysis_targets(
    tree_dir: str,
    min_behavior_score: float = 0.50,
    min_gate_confidence: float = 70.0,
    max_gates: int = 50,
) -> Dict[str, Any]:
    """Hợp nhất toàn diện giữa Behavior Targets và Security Gates trên cây Smali."""
    from .behavior.detector import BehaviorDetector
    from .behavior.target import TargetAnalyzer
    from .smali_sem import detect_security_gates

    tree_path = os.path.abspath(tree_dir)
    t0 = time.monotonic()

    # 1. Quét Behavior Targets
    detector = BehaviorDetector(tree_path)
    behaviors = detector.scan()
    analyzer = TargetAnalyzer(tree_path)
    raw_targets = analyzer.analyze(behaviors)
    ranked_targets = analyzer.rank_targets(raw_targets, min_score=min_behavior_score)

    # 2. Quét Zero-Workkey Security Gates
    gates = detect_security_gates(tree_path, max_gates=max_gates)

    # 3. Tạo bảng tra cứu method của Security Gates
    gate_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for g in gates:
        norm_cls = _normalize_class(g.get("class", ""))
        m_name = g.get("method", "")
        if norm_cls and m_name:
            gate_map[(norm_cls, m_name)] = g

    fused_targets: List[Dict[str, Any]] = []
    matched_gate_keys: Set[Tuple[str, str]] = set()

    # 4. Duyệt qua Behavior Targets và đối chiếu chéo
    for t in ranked_targets:
        norm_cls = _normalize_class(t.class_name)
        m_name = t.method
        key = (norm_cls, m_name)

        if key in gate_map:
            # GIAO THOA KÉP: DUAL_CONFIRMED!
            matched_gate_keys.add(key)
            gate = gate_map[key]
            fused_targets.append({
                "tier": "DUAL_CONFIRMED",
                "tier_rank": 1,
                "confidence": 1.0,
                "class": t.class_name,
                "class_clean": norm_cls,
                "method": m_name,
                "category": t.category,
                "strategy": "DUAL_EXECUTION",  # Vừa vá Smali vừa hook Frida
                "suggested_patch": gate.get("suggested_patch"),
                "taint_source": gate.get("taint_source"),
                "decision_branch": gate.get("decision_branch"),
                "frida_hookable": t.is_frida_hookable(),
                "file": gate.get("file") or t.details.get("file", ""),
                "description": (
                    f"Xác thực kép: Behavior [{t.category}] kết hợp Taint Flow rẽ nhánh "
                    f"[{gate.get('decision_branch')}]"
                ),
            })
        else:
            fused_targets.append({
                "tier": "BEHAVIOR_TARGET",
                "tier_rank": 3,
                "confidence": round(t.confidence, 3),
                "class": t.class_name,
                "class_clean": norm_cls,
                "method": m_name,
                "category": t.category,
                "strategy": "DYNAMIC_FRIDA_HOOK",
                "suggested_patch": None,
                "taint_source": None,
                "decision_branch": None,
                "frida_hookable": t.is_frida_hookable(),
                "file": t.details.get("file", ""),
                "description": f"Mục tiêu hành vi: {t.category} ({len(t.evidence)} bằng chứng)",
            })

    # 5. Bổ sung các Security Gates chưa có trong Behavior (bù đắp phần R8 làm mờ)
    for g in gates:
        norm_cls = _normalize_class(g.get("class", ""))
        m_name = g.get("method", "")
        key = (norm_cls, m_name)
        if key not in matched_gate_keys and g.get("confidence", 0.0) >= min_gate_confidence:
            fused_targets.append({
                "tier": "SECURITY_GATE",
                "tier_rank": 2,
                "confidence": round(g.get("confidence", 75.0) / 100.0, 3),
                "class": g.get("class"),
                "class_clean": norm_cls,
                "method": m_name,
                "category": g.get("category", "zero_workkey_gate"),
                "strategy": "STATIC_SMALI_GATE",  # Tự vá logic Invert Branch
                "suggested_patch": g.get("suggested_patch"),
                "taint_source": g.get("taint_source"),
                "decision_branch": g.get("decision_branch"),
                "frida_hookable": True,
                "file": g.get("file", ""),
                "description": f"Cổng bảo vệ Zero-Workkey: Taint từ {g.get('taint_source')}",
            })

    # 6. Sắp xếp mục tiêu theo độ ưu tiên giảm dần
    fused_targets.sort(key=lambda x: (x["tier_rank"], -x["confidence"]))
    elapsed = round(time.monotonic() - t0, 3)

    dual_count = sum(1 for x in fused_targets if x["tier"] == "DUAL_CONFIRMED")
    gate_count = sum(1 for x in fused_targets if x["tier"] == "SECURITY_GATE")
    behavior_count = sum(1 for x in fused_targets if x["tier"] == "BEHAVIOR_TARGET")

    return {
        "tree": tree_path,
        "elapsed_seconds": elapsed,
        "summary": {
            "total_fused": len(fused_targets),
            "dual_confirmed": dual_count,
            "security_gates": gate_count,
            "behavior_targets": behavior_count,
        },
        "targets": fused_targets,
    }


def apply_fused_targets(
    tree_dir: str,
    fused_result: Optional[Dict[str, Any]] = None,
    min_confidence: float = 0.70,
    backup: bool = True,
) -> Dict[str, Any]:
    """Tự động can thiệp vào các mục tiêu Target đã được xác định (thay thế Editor truyền thống)."""
    from .auto_gate_patcher import apply_security_gates
    tree_path = os.path.abspath(tree_dir)
    if fused_result is None:
        fused_result = fuse_analysis_targets(tree_path)

    targets = fused_result.get("targets", [])
    applicable_gates = []
    applied_targets = []
    skipped = []

    for t in targets:
        conf = float(t.get("confidence", 0.0))
        if conf < min_confidence:
            skipped.append({"target": t, "reason": f"Confidence {conf:.2f} < {min_confidence:.2f}"})
            continue

        tier = t.get("tier")
        if tier in ("DUAL_CONFIRMED", "SECURITY_GATE"):
            gate_data = {
                "class": t.get("class"),
                "method": t.get("method"),
                "file": t.get("file"),
                "confidence": conf * 100.0 if conf <= 1.0 else conf,
                "suggested_patch": t.get("suggested_patch"),
                "decision_branch": t.get("decision_branch"),
                "taint_source": t.get("taint_source"),
            }
            applicable_gates.append(gate_data)
            applied_targets.append(t)
        elif tier == "BEHAVIOR_TARGET":
            applied_targets.append(t)

    patch_res = {"applied_count": 0, "applied": [], "errors": []}
    if applicable_gates:
        patch_res = apply_security_gates(
            tree_path,
            gates=applicable_gates,
            min_confidence=min_confidence * 100.0 if min_confidence <= 1.0 else min_confidence,
            backup=backup,
        )

    return {
        "tree": tree_path,
        "total_targets": len(targets),
        "applied_targets_count": len(applied_targets),
        "static_gates_applied": patch_res.get("applied_count", 0),
        "applied_details": patch_res.get("applied", []),
        "errors": patch_res.get("errors", []),
        "skipped": skipped,
    }


def generate_fused_frida_script(fused_result: Dict[str, Any], out_script: Optional[str] = None) -> str:
    """Sinh kịch bản Frida hook đa tầng dựa trên danh sách Target."""
    lines = [
        "// == Generated by PatchX Fused Target Engine ==",
        "// Target-Driven Dynamic Hooking",
        "",
        "Java.perform(function() {",
        "    console.log('[*] PatchX Fused Targets Hooking started...');",
        "",
    ]

    hooked_methods = set()
    for t in fused_result.get("targets", []):
        if not t.get("frida_hookable", True):
            continue
        cls = t.get("class_clean", "")
        method = t.get("method", "")
        if not cls or not method:
            continue
        key = (cls, method)
        if key in hooked_methods:
            continue
        hooked_methods.add(key)

        tier = t.get("tier", "")
        category = t.get("category", "")
        lines.append(f"    // [{tier}] {category} -> {cls}.{method}")
        lines.append("    try {")
        lines.append(f"        var targetClass = Java.use('{cls}');")
        lines.append(f"        if (targetClass && targetClass['{method}']) {{")
        lines.append(f"            targetClass['{method}'].overloads.forEach(function(overload) {{")
        lines.append("                overload.implementation = function() {")
        lines.append(f"                    console.log('[+] Hit: {cls}.{method}');")
        if "pro" in category.lower() or "vip" in category.lower() or "license" in category.lower():
            lines.append("                    return true; // Bypass Gate")
        elif "debug" in category.lower() or "root" in category.lower():
            lines.append("                    return false; // Hide Root/Debug")
        else:
            lines.append("                    return this[overload.methodName].apply(this, arguments);")
        lines.append("                };")
        lines.append("            });")
        lines.append("        }")
        lines.append("    } catch (e) {")
        lines.append(f"        // Hook failed or class not loaded: {cls}")
        lines.append("    }")
        lines.append("")

    lines.append("    console.log('[*] PatchX Fused Targets installed.');")
    lines.append("});")
    lines.append("")

    content = "\n".join(lines)
    if out_script:
        os.makedirs(os.path.dirname(os.path.abspath(out_script)), exist_ok=True)
        with open(out_script, "w", encoding="utf-8") as fh:
            fh.write(content)
    return content


def render_fused_targets_markdown(fused_result: Dict[str, Any]) -> str:
    """Xuất báo cáo định dạng Markdown trực quan."""
    summary = fused_result.get("summary", {})
    targets = fused_result.get("targets", [])
    lines = [
        "# Báo cáo Mục tiêu Hợp nhất (Fused Target Matrix)",
        "",
        f"- **Cây Smali**: `{fused_result.get('tree', '')}`",
        f"- **Tổng số mục tiêu**: **{summary.get('total_fused', 0)}**",
        f"- **Hạng 1 (DUAL_CONFIRMED)**: `{summary.get('dual_confirmed', 0)}` (Ưu tiên số 1)",
        f"- **Hạng 2 (SECURITY_GATE)**: `{summary.get('security_gates', 0)}` (Cổng rẽ nhánh Zero-Workkey)",
        f"- **Hạng 3 (BEHAVIOR_TARGET)**: `{summary.get('behavior_targets', 0)}` (Mục tiêu nghiệp vụ)",
        f"- **Thời gian phân tích**: `{fused_result.get('elapsed_seconds', 0)}s`",
        "",
        "## Danh sách Mục tiêu Phân hạng",
        "",
        "| STT | Phân hạng | Lớp (Class) | Phương thức (Method) | Độ tin cậy | Chiến lược can thiệp |",
        "|---|---|---|---|---|---|",
    ]

    for idx, t in enumerate(targets, 1):
        tier_badge = f"**{t['tier']}**"
        lines.append(
            f"| {idx} | {tier_badge} | `{t.get('class_clean', '')}` | `{t.get('method', '')}` | {round(t.get('confidence', 0.0)*100, 1)}% | `{t.get('strategy', '')}` |"
        )
    return "\n".join(lines)

