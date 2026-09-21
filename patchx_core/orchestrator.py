# -*- coding: utf-8 -*-
"""orchestrator — Autopilot điều phối tự hành 1-chạm, chạy trên động cơ DAG.

Quy trình "autopilot" (đăng ký vào Sổ bộ quy trình mẫu):
    intake -> prepare -> decompile(tùy chọn) -> integrity-decouple -> auto-gate
    -> network-bypass(tùy chọn) -> native-patch(tùy chọn) -> cfg-unflatten(tùy chọn)
    -> micro-dex-verify -> package-build -> report

Mỗi khâu đều đo thời gian, ghi kết quả vào báo cáo và tự sao lưu trước khi ghi.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .dag import DAGNode, NodeStatus, PipelineDAG
from .pipeline_registry import PipelineDefinition, get_pipeline_registry


def _is_tree(path: str) -> bool:
    return os.path.isdir(path)


def _extract_libs_from_apk(apk_path: str, out_dir: str) -> str:
    """Trích lib/*.so từ APK vào thư mục, trả đường dẫn thư mục gốc lib."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                dest = out / name.replace("/", os.sep)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
    return str(out)


def _step_intake(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .intake import run_intake
    art = ctx["artifact_path"]
    out = os.path.join(ctx["output_dir"], "intake")
    os.makedirs(out, exist_ok=True)
    if os.path.isdir(art):
        rep = {"target": art, "kind": "tree", "skipped": True,
               "note": "đầu vào là cây đã giải mã, bỏ qua kiểm kê tệp nén"}
    else:
        rep = run_intake(art, out)
    has_native = False
    if os.path.isfile(art) and zipfile.is_zipfile(art):
        with zipfile.ZipFile(art) as zf:
            has_native = any(n.startswith("lib/") and n.endswith(".so")
                             for n in zf.namelist())
    return {"intake_report": rep, "has_native": has_native}


def _step_prepare(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    """Nếu đầu vào là APK: tạo bản làm việc riêng để không đụng bản gốc."""
    art = ctx["artifact_path"]
    if os.path.isfile(art):
        work_dir = Path(ctx["output_dir"]) / "work"
        work_dir.mkdir(parents=True, exist_ok=True)
        work_apk = work_dir / Path(art).name
        shutil.copy2(art, work_apk)
        ctx["artifact_path"] = str(work_apk)
        return {"working_artifact": str(work_apk), "copied": True}
    return {"working_artifact": art, "copied": False}


def _step_decompile(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    art = ctx["artifact_path"]
    if not ctx.get("decompile") or not os.path.isfile(art):
        return {"decompiled": False}
    tree = os.path.join(ctx["output_dir"], "tree")
    apktool = shutil.which("apktool") or shutil.which("apktool.jar")
    if not apktool:
        return {"decompiled": False, "error": "không tìm thấy apktool"}
    if os.path.isdir(tree):
        shutil.rmtree(tree, ignore_errors=True)
    proc = subprocess.run(
        ["apktool", "d", "-f", art, "-o", tree],
        capture_output=True, text=True, timeout=1800)
    if proc.returncode != 0:
        return {"decompiled": False, "error": (proc.stderr or proc.stdout)[:500]}
    ctx["tree_dir"] = tree
    return {"decompiled": True, "tree_dir": tree}


def _step_integrity(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .integrity_decoupler import decouple_integrity
    target = ctx.get("tree_dir") or ctx["artifact_path"]
    rep = decouple_integrity(
        target,
        orig_apk=ctx.get("orig_apk"),
        new_apk=ctx.get("new_apk"),
        so_dir=ctx.get("so_dir"),
        out_dir=os.path.join(ctx["output_dir"], "integrity"),
        spearheads=tuple(ctx.get("spearheads") or (1, 2, 3, 4)),
        dry_run=bool(ctx.get("dry_run")),
    )
    return {"integrity_report": rep}


def _step_auto_gate(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .auto_gate_patcher import apply_security_gates
    target = ctx.get("tree_dir") or ctx["artifact_path"]
    rep = apply_security_gates(target)
    return {"auto_gate_report": rep}


def _step_network(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .network_breakthrough import apply_network_bypass
    target = ctx.get("tree_dir") or ctx["artifact_path"]
    rep = apply_network_bypass(
        target, output_dir=os.path.join(ctx["output_dir"], "network"))
    network_apk = (rep.get("nsc_enabler") or {}).get("output_apk")
    return {"network_report": rep, "network_apk": network_apk}


def _step_native(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .behavior.native_mutator import auto_mutate_native
    art = ctx["artifact_path"]
    so_dir = ctx.get("so_dir")
    if not so_dir:
        if os.path.isfile(art) and zipfile.is_zipfile(art):
            so_dir = _extract_libs_from_apk(
                art, os.path.join(ctx["output_dir"], "native", "lib"))
        elif os.path.isdir(art):
            so_dir = os.path.join(art, "lib")
    if not so_dir or not os.path.isdir(so_dir):
        return {"native_report": None, "native_error": "không tìm thấy thư viện mã máy"}
    rep = auto_mutate_native(
        so_dir,
        output_dir=os.path.join(ctx["output_dir"], "native"),
        apply_disk=not ctx.get("dry_run"),
        gen_frida=True,
    )
    return {"native_report": rep}


def _step_unflatten(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .cfg_unflatten import unflatten_tree
    target = ctx.get("tree_dir") or ctx["artifact_path"]
    if not os.path.isdir(target):
        return {"unflatten_report": None}
    rep = unflatten_tree(
        target,
        apply=not ctx.get("dry_run"),
        limit=int(ctx.get("unflatten_limit") or 0),
        min_cases=2,
        backup_root=os.path.join(ctx["output_dir"], "backup", "unflatten"),
    )
    return {"unflatten_report": rep}


def _step_micro_dex(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .dex_emulator import verify_method_bypass
    int_rep = ctx.get("integrity_report") or {}
    texts = int_rep.get("patched_method_texts") or []
    verified = failed = 0
    details = []
    for item in texts:
        res = verify_method_bypass(item.get("text") or "")
        details.append({
            "file": item.get("file"),
            "method": item.get("method"),
            "verified": res["verified"],
            "return_value": res["return_value"],
            "cycles": res.get("cycles"),
        })
        if res["verified"]:
            verified += 1
        else:
            failed += 1
    return {"micro_dex_report": {
        "total": len(texts),
        "verified": verified,
        "failed": failed,
        "details": details[:200],
    }}


def _step_package(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    from .apk_fast_repack import sign_repacked_apk
    art = ctx["artifact_path"]
    out = ctx["output_dir"]
    if os.path.isdir(art):
        unsigned = os.path.join(out, "patched-unsigned.apk")
        apktool = shutil.which("apktool")
        if not apktool:
            return {"packaging": {"success": False, "error": "không tìm thấy apktool"},
                    "patched_apk": None}
        proc = subprocess.run(
            ["apktool", "b", art, "-o", unsigned],
            capture_output=True, text=True, timeout=1800)
        if proc.returncode != 0:
            raise RuntimeError("apktool build thất bại: %s"
                               % (proc.stderr or proc.stdout)[:500])
    else:
        unsigned = ctx.get("network_apk") or art
    sign_res = sign_repacked_apk(unsigned)
    if not sign_res.get("signed"):
        raise RuntimeError("ký số thất bại: %s" % sign_res.get("error"))
    return {
        "packaging": {
            "success": bool(sign_res.get("signed")),
            "unsigned_apk": unsigned,
            "sign": sign_res,
        },
        "patched_apk": unsigned if sign_res.get("signed") else unsigned,
    }


def _step_report(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
    out_dir = ctx.get("output_dir", ".")
    summary_data = {
        "artifact": ctx.get("artifact_path"),
        "pipeline": ctx.get("pipeline_name", "autopilot"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "has_native": ctx.get("has_native", False),
        "patched_apk": ctx.get("patched_apk"),
        "integrity": ctx.get("integrity_report"),
        "network": ctx.get("network_report"),
        "native": ctx.get("native_report"),
        "micro_dex": ctx.get("micro_dex_report"),
        "packaging": ctx.get("packaging"),
    }
    rep_json = os.path.join(out_dir, "autopilot_report.json")
    with open(rep_json, "w", encoding="utf-8") as fh:
        json.dump(summary_data, fh, ensure_ascii=False, indent=2)
    return {"autopilot_report_json": rep_json}


# (tên, mô tả, hàm, phụ thuộc, điều kiện, outputs, optional)
AUTOPILOT_STEPS: List[Tuple[str, str, Callable, set, Optional[Callable], List[str], bool]] = [
    ("ap-intake", "Tiếp nhận và kiểm kê tệp đầu vào", _step_intake, set(), None, ["intake_report", "has_native"], False),
    ("ap-prepare", "Tạo bản làm việc riêng cho APK", _step_prepare, {"ap-intake"}, None, ["working_artifact"], False),
    ("ap-decompile", "Giải mã APK thành cây mã trung gian", _step_decompile, {"ap-prepare"},
     lambda c: bool(c.get("decompile")) and os.path.isfile(c["artifact_path"]),
     ["decompiled", "tree_dir"], True),
    ("ap-integrity", "Triệt tiêu kiểm soát toàn vẹn 4 tầng", _step_integrity, {"ap-prepare"},
     None, ["integrity_report"], False),
    ("ap-auto-gate", "Vá cổng kiểm tra bảo vệ tự động", _step_auto_gate, {"ap-integrity"},
     lambda c: (os.path.isdir(c.get("tree_dir") or c["artifact_path"])) and not c.get("dry_run"),
     ["auto_gate_report"], True),
    ("ap-network", "Vô hiệu hóa NSC/SSL pinning tầng mạng", _step_network, {"ap-prepare"},
     lambda c: bool(c.get("network")) and not c.get("dry_run"),
     ["network_report", "network_apk"], True),
    ("ap-native", "Đột biến zero-drift thư viện mã máy", _step_native, {"ap-prepare"},
     lambda c: bool(c.get("native_patch")) and not c.get("dry_run"),
     ["native_report"], True),
    ("ap-unflatten", "Gỡ phẳng luồng mã và cắt tỉa khối chết", _step_unflatten, {"ap-prepare"},
     lambda c: bool(c.get("unflatten")) and os.path.isdir(c.get("tree_dir") or c["artifact_path"]),
     ["unflatten_report"], True),
    ("ap-micro-dex", "Kiểm chứng mã con đã vá trả đúng giá trị", _step_micro_dex,
     {"ap-integrity"}, None, ["micro_dex_report"], True),
    ("ap-package", "Đóng gói và ký số ứng dụng xuất xưởng", _step_package,
     {"ap-micro-dex", "ap-auto-gate", "ap-network", "ap-native", "ap-unflatten"},
     lambda c: bool(c.get("package", True)) and not c.get("dry_run"),
     ["patched_apk", "packaging"], True),
    ("ap-report", "Tổng hợp báo cáo autopilot", _step_report, {"ap-package"},
     None, ["autopilot_report_json"], False),
]


def ensure_autopilot_pipeline():
    """Đăng ký bước + quy trình autopilot vào Sổ bộ (chỉ một lần mỗi tiến trình)."""
    reg = get_pipeline_registry()
    if reg.has_pipeline("autopilot"):
        return reg.get_pipeline("autopilot")

    for name, desc, fn, deps, cond, outputs, optional in AUTOPILOT_STEPS:
        if not reg.get_step(name):
            reg.register_step(DAGNode(
                name=name,
                description=desc,
                depends_on=set(deps),
                condition=cond,
                inputs=[],
                outputs=list(outputs),
                action=fn,
                cost="FAST",
                optional=optional,
                tags=["autopilot"],
            ))

    dag = PipelineDAG(name="autopilot",
                      description="Tự hành 1-chạm: tiếp nhận -> vá toàn vẹn -> mạng -> native -> kiểm chứng -> đóng gói")
    order = ["ap-intake", "ap-prepare", "ap-decompile", "ap-integrity", "ap-auto-gate",
             "ap-network", "ap-native", "ap-unflatten", "ap-micro-dex",
             "ap-package", "ap-report"]
    for name in order:
        dag.add_node(reg.get_step(name))
    reg.register_pipeline(PipelineDefinition(
        name="autopilot",
        description="Tự hành 1-chạm toàn trình có kế hoạch DAG: vá toàn vẹn, mạng, native, kiểm chứng mã con, đóng gói và ký số",
        dag=dag,
        tags=["autopilot", "tự_hành", "toàn_trình"],
    ))
    return reg.get_pipeline("autopilot")


class AutopilotOrchestrator:
    """Bộ điều phối tự hành 1-chạm chạy trên DAG."""

    def __init__(
        self,
        target: str,
        out_dir: str,
        spearheads: Tuple[int, ...] = (1, 2, 3, 4),
        dry_run: bool = False,
        so_dir: Optional[str] = None,
        orig_apk: Optional[str] = None,
        new_apk: Optional[str] = None,
        network: bool = False,
        native_patch: bool = False,
        unflatten: bool = False,
        unflatten_limit: int = 0,
        decompile: bool = False,
        package: bool = True,
    ) -> None:
        self.target = os.path.abspath(target)
        self.out_dir = out_dir
        self.spearheads = spearheads
        self.dry_run = dry_run
        self.so_dir = so_dir
        self.orig_apk = orig_apk
        self.new_apk = new_apk
        self.network = network
        self.native_patch = native_patch
        self.unflatten = unflatten
        self.unflatten_limit = unflatten_limit
        self.decompile = decompile
        self.package = package

    def run_full_pipeline(self) -> Dict[str, Any]:
        pipe = ensure_autopilot_pipeline()
        ctx = {
            "spearheads": self.spearheads,
            "dry_run": self.dry_run,
            "so_dir": self.so_dir,
            "orig_apk": self.orig_apk,
            "new_apk": self.new_apk,
            "network": self.network,
            "native_patch": self.native_patch,
            "unflatten": self.unflatten,
            "unflatten_limit": self.unflatten_limit,
            "decompile": self.decompile,
            "package": self.package,
        }
        res = pipe.execute(
            self.target,
            output_dir=self.out_dir,
            context_overrides=ctx,
            dry_run=False,
            stop_on_fail=False,
        )
        steps: List[Dict[str, Any]] = []
        for name in pipe.dag.toposort():
            rec = res.records.get(name)
            if rec is None:
                continue
            steps.append({
                "name": name,
                "ok": rec.status in (NodeStatus.SUCCESS, NodeStatus.WARN),
                "skipped": rec.status == NodeStatus.SKIPPED,
                "error": rec.error_message,
                "elapsed_ms": int((rec.elapsed_seconds or 0) * 1000),
            })
        final_ctx = dict(res.context)
        report: Dict[str, Any] = {
            "mode": "dry-run" if self.dry_run else "apply",
            "target": self.target,
            "verdict": res.verdict,
            "steps": steps,
            "elapsed_seconds": round(res.elapsed_seconds, 3),
            "time": round(res.elapsed_seconds, 3),
            "plan": {
                "order": pipe.dag.toposort(),
                "levels": pipe.dag.get_execution_levels(),
                "mermaid": pipe.dag.to_mermaid(),
            },
            "patched_apk": final_ctx.get("patched_apk"),
            "integrity": final_ctx.get("integrity_report"),
            "network": final_ctx.get("network_report"),
            "native": final_ctx.get("native_report"),
            "unflatten": final_ctx.get("unflatten_report"),
            "micro_dex": final_ctx.get("micro_dex_report"),
            "packaging": final_ctx.get("packaging"),
        }
        report_path = os.path.join(self.out_dir, "report.json")
        os.makedirs(self.out_dir, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        report["report_path"] = report_path
        return report
