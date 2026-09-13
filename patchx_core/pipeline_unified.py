# -*- coding: utf-8 -*-
"""pipeline_unified — Engine Điều Phối Pipeline Thống Nhất cho PatchX.

Tích hợp và tinh gọn các pipeline phân mảnh thành hệ thống luồng chuẩn hóa:
  1. intake: Tiếp nhận artifact (APK/APKS/XAPK/AAB), kiểm kê DEX/ABI/chữ ký (Zero-Extraction).
  2. fast: 1-Click Fast-Path: DEX + AXML + ARSC + gỡ chữ ký cũ + zipalign + sign debug (< 0.5s).
  3. behavior: Phân tích hành vi tĩnh (Smali AST) + sinh hook Frida + tích hợp Gadget.
  4. native: Quét nhị phân .so + SHA-256 cert spoof + rodata in-place patch.
  5. combo: Active learning tự động sinh combo patch tối ưu từ lịch sử thành công.
  6. auto (hybrid): Luồng tự động thông minh: Intake -> Phân tích -> Fast-Path -> Native Bypass -> Sign -> Report.

Mọi luồng đều xuất báo cáo chuẩn: pipeline_report.json và pipeline_report.md.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence


SCHEMA = "patchx.pipeline-unified/v1"


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class UnifiedPipeline:
    """Điều phối và thực thi các pipeline thống nhất của PatchX."""

    def __init__(self, artifact_path: str, output_dir: Optional[str] = None):
        self.artifact = os.path.abspath(artifact_path)
        self.output_dir = os.path.abspath(output_dir or os.path.join(
            os.path.dirname(self.artifact), "pipeline_out"
        ))
        os.makedirs(self.output_dir, exist_ok=True)
        from patchx_core.blackboard import SharedBlackboard
        self.blackboard = SharedBlackboard({"artifact_path": self.artifact})

    def run(self, mode: str = "auto", **kwargs) -> Dict[str, Any]:
        """Thực thi pipeline theo mode chỉ định."""
        start_time = time.monotonic()
        report: Dict[str, Any] = {
            "schema": SCHEMA,
            "artifact": {
                "path": self.artifact,
                "name": os.path.basename(self.artifact),
                "size": os.path.getsize(self.artifact) if os.path.exists(self.artifact) else 0,
            },
            "mode": mode,
            "started_at": _now(),
            "stages": [],
            "verdict": "PENDING",
            "outputs": {},
            "elapsed_seconds": 0.0,
        }

        try:
            if mode == "intake":
                self._run_intake_stage(report, **kwargs)
            elif mode == "semantic":
                self._run_semantic_stage(report, **kwargs)
            elif mode == "fast":
                self._run_fast_stage(report, **kwargs)
            elif mode == "behavior":
                self._run_behavior_stage(report, **kwargs)
            elif mode == "native":
                self._run_native_stage(report, **kwargs)
            elif mode == "combo":
                self._run_combo_stage(report, **kwargs)
            elif mode == "auto":
                self._run_auto_hybrid_stage(report, **kwargs)
            elif mode == "gadget":
                self._run_gadget_stage(report, **kwargs)
            else:
                raise ValueError(f"Chế độ pipeline không hợp lệ: '{mode}'. Chọn: auto, intake, semantic, fast, behavior, native, combo, gadget.")

            # Tính verdict tổng quát
            failed_stages = [s["name"] for s in report["stages"] if s.get("status") == "FAIL"]
            if failed_stages:
                report["verdict"] = "FAILED"
                report["failed_stages"] = failed_stages
            else:
                report["verdict"] = "SUCCESS"

        except Exception as exc:
            report["verdict"] = "ERROR"
            report["error"] = str(exc)

        finally:
            report["elapsed_seconds"] = round(time.monotonic() - start_time, 3)
            report["finished_at"] = _now()
            self._write_reports(report)

        return report

    def _run_intake_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage 1: Intake & Capability Assessment."""
        from patchx_core.intake import run_intake
        intake_dir = os.path.join(self.output_dir, "intake")
        res = run_intake(self.artifact, intake_dir, include_tools=True)
        report["stages"].append({
            "name": "intake_triage",
            "status": "PASS" if res.get("summary", {}).get("verdict") != "NOT_ANDROID_ARTIFACT" else "FAIL",
            "details": res.get("summary", {}),
            "structure": res.get("structure", {}),
        })
        report["outputs"]["intake_json"] = res.get("outputs", {}).get("json")

        struct = res.get("structure", {})
        abis = struct.get("abis", [])
        self.blackboard.post("artifact_structure", struct, origin="intake")
        self.blackboard.post("abis", abis, origin="intake")
        self.blackboard.post("has_native", len(abis) > 0, origin="intake")

        # Tự động kích hoạt Phân tích toàn diện & Khai phá từ điển động (Open-Ended Discovery)
        try:
            from patchx_core.comprehensive_analyzer import UniversalDiscoveryEngine
            disc_dir = os.path.join(self.output_dir, "discovery")
            disc_engine = UniversalDiscoveryEngine(self.artifact, output_dir=disc_dir)
            disc_res = disc_engine.run_full_discovery()
            self.blackboard.post("universal_findings", disc_res, origin="discovery")
            self.blackboard.post("dynamic_lexicon", disc_res.get("lexicon_mined", {}), origin="discovery")
            self.blackboard.post("sensitive_assets", disc_res.get("assets_sensitive", {}), origin="discovery")
            if disc_res.get("morphological_gates"):
                self.blackboard.post("morphological_gates", disc_res["morphological_gates"], origin="discovery")
            report["stages"].append({
                "name": "universal_discovery",
                "status": "PASS",
                "summary": disc_res.get("summary", {}),
            })
        except Exception as exc:
            report["stages"].append({
                "name": "universal_discovery",
                "status": "WARN",
                "reason": str(exc),
            })

    def _run_fast_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage 2: Fast-Path 1-Click Repack."""
        from patchx_core.apk_fast_repack import fast_patch_and_repack
        out_apk = kwargs.get("out_apk") or os.path.join(
            self.output_dir, f"fast_patched_{os.path.basename(self.artifact)}"
        )
        dex_str = kwargs.get("dex_str_replaces") or {}
        dex_hex = kwargs.get("dex_hex_replaces") or {}
        axml_str = dict(kwargs.get("axml_replaces") or {})
        if kwargs.get("bypass_nsc", True):
            axml_str.setdefault("networkSecurityConfig", "disabledSecConfig")
        arsc_str = kwargs.get("arsc_replaces") or {}

        dex_replacements = [(k, v, False) for k, v in dex_str.items()] + [(k, v, True) for k, v in dex_hex.items()]
        axml_replacements = [(k, v) for k, v in axml_str.items()]
        arsc_replacements = [(k, v) for k, v in arsc_str.items()]

        explicit_patterns = bool(dex_replacements or kwargs.get("axml_replaces") or arsc_replacements)
        allow_empty = kwargs.get("allow_empty", not explicit_patterns)
        t0 = time.monotonic()
        stats = fast_patch_and_repack(
            self.artifact,
            dex_replacements=dex_replacements if dex_replacements else None,
            axml_replacements=axml_replacements if axml_replacements else None,
            arsc_replacements=arsc_replacements if arsc_replacements else None,
            output_apk=out_apk,
            strip_signatures=True,
            allow_empty=allow_empty,
        )
        elapsed = round(time.monotonic() - t0, 3)

        status = "PASS" if stats.get("success") else "FAIL"
        report["stages"].append({
            "name": "fast_path_repack",
            "status": status,
            "elapsed": elapsed,
            "stats": stats,
            "output_apk": out_apk,
        })
        if stats.get("success"):
            report["outputs"]["patched_apk"] = out_apk

    def _run_behavior_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage 3: Behavior & Frida Scripting."""
        from patchx_core.behavior.pipeline import run_frida_pipeline
        tree_dir = self.artifact
        if os.path.isfile(self.artifact):
            apk_name = os.path.splitext(os.path.basename(self.artifact))[0]
            candidate_tree = os.path.join(
                os.path.dirname(self.output_dir), "apk", "apk-trees", f"{apk_name}_src"
            )
            if os.path.isdir(candidate_tree):
                tree_dir = candidate_tree
            else:
                report["stages"].append({
                    "name": "behavior_analysis",
                    "status": "SKIP",
                    "reason": f"Cần cây giải mã smali cho behavior-pipeline. Đặt cây tại: {candidate_tree}",
                })
                return

        out_b = os.path.join(self.output_dir, "behavior")
        b_res = run_frida_pipeline(
            tree_dir,
            out_dir=out_b,
            auto_patch=kwargs.get("auto_patch", False),
            build_apk=kwargs.get("build_apk", False),
            min_score=kwargs.get("min_score", 0.65),
            interactive=False,
        )
        report["stages"].append({
            "name": "behavior_analysis",
            "status": "PASS" if b_res.get("ok") else "WARN",
            "summary": b_res.get("summary", {}),
            "targets_count": len(b_res.get("targets", [])),
        })
        report["outputs"]["frida_hook"] = b_res.get("artifacts", {}).get("hook_script")
        self.blackboard.post("behavior_targets", b_res.get("targets", []), origin="behavior")
        self.blackboard.post("smali_tree", tree_dir, origin="behavior")

    def _run_native_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage 4: Native .so Analysis & Signature Spoofing."""
        from patchx_core.signature_spoof import multi_layer_spoof_pipeline
        orig_apk = kwargs.get("orig_apk") or self.artifact
        target_apk = kwargs.get("target_apk") or self.artifact
        frida_out = os.path.join(self.output_dir, "native_sig_spoof.js")

        try:
            res = multi_layer_spoof_pipeline(
                orig_apk,
                so_dir=kwargs.get("so_dir"),
                new_cert_apk=target_apk,
                frida_script_out=frida_out,
            )
            report["stages"].append({
                "name": "native_signature_spoof",
                "status": "PASS" if res.get("frida_script") else "WARN",
                "stats": res,
            })
            if os.path.isfile(frida_out):
                report["outputs"]["native_frida_script"] = frida_out
        except Exception as exc:
            report["stages"].append({
                "name": "native_signature_spoof",
                "status": "SKIP",
                "reason": str(exc),
            })

    def _run_gadget_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage: Nhúng Frida Gadget offline vào APK/Tree (không cần root)."""
        from patchx_core.behavior.gadget_pipeline import run_gadget_pipeline
        gadget_out = os.path.join(self.output_dir, "gadget")
        try:
            res = run_gadget_pipeline(
                self.artifact,
                out_dir=gadget_out,
                abi=kwargs.get("abi", "arm64-v8a"),
                interactive=False,
            )
            report["stages"].append({
                "name": "frida_gadget_injection",
                "status": "PASS" if res.get("ok") else "FAIL",
                "details": res.get("summary", {}),
                "output_apk": res.get("artifacts", {}).get("signed_apk"),
            })
            if res.get("artifacts", {}).get("signed_apk"):
                report["outputs"]["gadget_signed_apk"] = res["artifacts"]["signed_apk"]
        except Exception as exc:
            report["stages"].append({
                "name": "frida_gadget_injection",
                "status": "FAIL",
                "error": str(exc),
            })

    def _run_combo_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage 5: Active Learning Smart Combo."""
        from patchx_core.learn import generate_smart_combo, save_smart_combo
        intent = kwargs.get("intent", "bypass")
        collection = kwargs.get("collection") or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "upgraded"
        )
        combo_res = generate_smart_combo(
            self.artifact,
            collection,
            intent=intent,
            max_patches=kwargs.get("max_patches", 4),
        )
        out_combo_file = os.path.join(self.output_dir, f"smart_combo_{intent}.zip")
        if combo_res.get("success"):
            save_smart_combo(combo_res, out_combo_file)
            report["outputs"]["smart_combo_zip"] = out_combo_file

        combo_details = {k: v for k, v in combo_res.items() if k != "merged_patch"}
        if "merged_patch" in combo_res and combo_res["merged_patch"]:
            combo_details["merged_patch_name"] = getattr(combo_res["merged_patch"], "name", str(combo_res["merged_patch"]))

        report["stages"].append({
            "name": "smart_combo_learning",
            "status": "PASS" if combo_res.get("success") else "WARN",
            "details": combo_details,
        })

    def _run_semantic_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Stage: Deep Semantic & Taint Analysis (Zero-Workkey Discovery)."""
        from patchx_core.smali_sem import detect_security_gates
        tree_dir = self.artifact
        if os.path.isfile(self.artifact):
            apk_name = os.path.splitext(os.path.basename(self.artifact))[0]
            candidate_tree = os.path.join(
                os.path.dirname(self.output_dir), "apk", "apk-trees", f"{apk_name}_src"
            )
            if os.path.isdir(candidate_tree):
                tree_dir = candidate_tree
            else:
                report["stages"].append({
                    "name": "semantic_discovery",
                    "status": "SKIP",
                    "reason": f"Cần cây giải mã smali để quét taint flow. Đặt cây tại: {candidate_tree}",
                })
                return

        gates = detect_security_gates(tree_dir, max_gates=kwargs.get("max_gates", 20))
        report["stages"].append({
            "name": "semantic_discovery",
            "status": "PASS" if gates else "WARN",
            "security_gates_count": len(gates),
            "top_gates": gates[:5],
            "zero_workkey": True,
        })
        out_gates_file = os.path.join(self.output_dir, "semantic_gates.json")
        with open(out_gates_file, "w", encoding="utf-8") as fh:
            json.dump({"tree": tree_dir, "gates": gates}, fh, ensure_ascii=False, indent=2)
        report["outputs"]["semantic_gates_json"] = out_gates_file
        self.blackboard.post("security_gates", gates, origin="smali_sem")
        self.blackboard.post("smali_tree", tree_dir, origin="smali_sem")

        if kwargs.get("auto_patch", False):
            from .auto_gate_patcher import apply_security_gates
            p_res = apply_security_gates(tree_dir, gates=gates, min_confidence=kwargs.get("min_confidence", 75.0))
            report["stages"].append({
                "name": "auto_gate_patcher",
                "status": "PASS" if p_res["applied_count"] > 0 else "SKIP",
                "applied_count": p_res["applied_count"],
                "applied": p_res["applied"],
            })

    def _run_auto_hybrid_stage(self, report: Dict[str, Any], **kwargs) -> None:
        """Intelligent Auto-Hybrid Flow: Tự động tổng hợp và thực thi chuỗi tối ưu theo APK."""
        # 1. Tiếp nhận và phân tích cấu trúc (Intake)
        self._run_intake_stage(report, **kwargs)
        intake_stage = next((s for s in report["stages"] if s["name"] == "intake_triage"), None)
        has_native = False
        if intake_stage and intake_stage.get("structure"):
            abis = intake_stage["structure"].get("abis", [])
            has_native = len(abis) > 0

        # 2. Truy vết ngữ nghĩa sâu & Security Gates (Zero-Workkey) & Tự vá cổng logic
        self._run_semantic_stage(report, auto_patch=True, **kwargs)

        # 3. Can thiệp Fast-Path In-Place (DEX/AXML/ARSC)
        self._run_fast_stage(report, **kwargs)

        # 4. Nếu có thư viện Native, tự động chạy Native Signature Spoof
        if has_native and report["outputs"].get("patched_apk"):
            kwargs["target_apk"] = report["outputs"]["patched_apk"]
            kwargs["orig_apk"] = self.artifact
            self._run_native_stage(report, **kwargs)

        # 5. Phân tích hành vi & Hook Frida
        self._run_behavior_stage(report, **kwargs)

        # 6. Active Learning Smart Combo
        self._run_combo_stage(report, **kwargs)

        # 7. Tự động hợp nhất mục tiêu (Fused Target Matrix) từ Blackboard facts
        tree_dir = self.blackboard.get("smali_tree")
        if tree_dir and os.path.isdir(tree_dir):
            try:
                from patchx_core.fused_target_engine import fuse_analysis_targets, apply_fused_targets
                fused = fuse_analysis_targets(tree_dir)
                self.blackboard.post("fused_targets", fused.get("targets", []), origin="fused_target_engine")
                report["stages"].append({
                    "name": "fused_target_matrix",
                    "status": "PASS" if fused.get("summary", {}).get("total_fused", 0) > 0 else "SKIP",
                    "summary": fused.get("summary", {}),
                })
                if kwargs.get("auto_patch", True):
                    f_applied = apply_fused_targets(tree_dir, fused)
                    report["outputs"]["fused_targets_applied"] = f_applied.get("static_gates_applied", 0)
            except Exception:
                pass

        report["blackboard_summary"] = self.blackboard.summary()

    def _write_reports(self, report: Dict[str, Any]) -> None:
        """Ghi báo cáo JSON và Markdown chuẩn hóa."""
        jpath = os.path.join(self.output_dir, "pipeline_report.json")
        with open(jpath, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2, default=str)
        report["outputs"]["report_json"] = jpath

        mpath = os.path.join(self.output_dir, "pipeline_report.md")
        lines = [
            f"# Báo cáo Pipeline Thống Nhất ({report['mode'].upper()})",
            "",
            f"- **Thời điểm thực hiện**: {report['started_at']}",
            f"- **Artifact đầu vào**: `{report['artifact']['path']}` ({round(report['artifact']['size'] / (1024*1024), 2)} MB)",
            f"- **Trạng thái tổng thể**: **{report['verdict']}**",
            f"- **Thời gian xử lý**: `{report['elapsed_seconds']}s`",
            "",
            "## Chi tiết các Stage thực thi",
            "",
            "| Stage | Trạng thái | Ghi chú / Chi tiết |",
            "|---|:---:|---|",
        ]
        for stage in report.get("stages", []):
            st = stage.get("status", "UNKNOWN")
            badge = "✅ PASS" if st == "PASS" else ("⚠️ WARN" if st == "WARN" else ("⏭️ SKIP" if st == "SKIP" else "❌ FAIL"))
            info = str(stage.get("details") or stage.get("summary") or stage.get("stats") or stage.get("reason") or "OK")
            if len(info) > 80:
                info = info[:77] + "..."
            lines.append(f"| `{stage['name']}` | {badge} | {info} |")

        lines.append("")
        lines.append("## Đầu ra tạo thành (Artifacts)")
        lines.append("")
        for k, v in report.get("outputs", {}).items():
            if v:
                lines.append(f"- **{k}**: `{v}`")

        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        report["outputs"]["report_markdown"] = mpath


def run_pipeline(artifact_path: str, mode: str = "auto", output_dir: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Hàm giao tiếp chính cho CLI và các orchestrator."""
    pipeline = UnifiedPipeline(artifact_path, output_dir=output_dir)
    return pipeline.run(mode=mode, **kwargs)
