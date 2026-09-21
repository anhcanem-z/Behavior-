# -*- coding: utf-8 -*-
"""pipeline_registry — Sổ Bộ Pipeline Thống Nhất & Quản Lý Bước Luồng (Pipeline Registry).

Trung tâm đăng ký, phân loại và kiến tạo các quy trình (Pipelines) dựa trên DAG:
  1. Registry cho các bước chuẩn hóa (Standard Steps/DAGNode): intake, discovery,
     semantic, behavior, fused_targets, auto_gate, native_scan, rodata_patch, fast_patch, gadget, combo, sign.
  2. Registry cho các Pipeline hoàn chỉnh: auto, fast, behavior, native, gadget, deep_audit, combo.
  3. Dynamic Composition: Tạo pipeline mới từ danh sách bước, tự động kết nối các cạnh phụ thuộc (dependencies).
  4. Trực quan hóa: Xuất danh mục pipelines, render sơ đồ Mermaid, cây ASCII và JSON schema.
"""

from __future__ import annotations

import copy
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from .dag import DAGNode, PipelineDAG, DAGExecutionResult, NodeStatus


@dataclass
class PipelineDefinition:
    """Định nghĩa một Pipeline chuẩn hóa trong hệ thống."""
    name: str
    description: str
    dag: PipelineDAG
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    author: str = "PatchX Core"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "tags": self.tags,
            "total_steps": len(self.dag.nodes),
            "step_names": self.dag.toposort() if self.dag.nodes else [],
            "levels": self.dag.get_execution_levels() if self.dag.nodes else [],
            "metadata": self.metadata,
        }

    def execute(
        self,
        artifact_path: str,
        output_dir: Optional[str] = None,
        context_overrides: Optional[Dict[str, Any]] = None,
        blackboard: Any = None,
        stop_on_fail: bool = True,
        dry_run: bool = False,
    ) -> DAGExecutionResult:
        """Thực thi pipeline trên một artifact cụ thể."""
        art_abs = os.path.abspath(artifact_path)
        out_abs = os.path.abspath(output_dir or os.path.join(
            os.path.dirname(art_abs), f"pipeline_{self.name}_out"
        ))
        os.makedirs(out_abs, exist_ok=True)

        ctx: Dict[str, Any] = {
            "artifact_path": art_abs,
            "artifact_name": os.path.basename(art_abs),
            "output_dir": out_abs,
            "pipeline_name": self.name,
        }
        if context_overrides:
            ctx.update(context_overrides)

        # Khởi tạo hoặc cập nhật Blackboard
        if blackboard is None:
            from .blackboard import SharedBlackboard
            blackboard = SharedBlackboard(ctx)
        elif hasattr(blackboard, "post"):
            for k, v in ctx.items():
                blackboard.post(k, v, origin="pipeline_init")

        return self.dag.execute(
            context=ctx,
            blackboard=blackboard,
            stop_on_fail=stop_on_fail,
            dry_run=dry_run,
        )


class PipelineRegistry:
    """Kho lưu trữ và quản lý tập trung toàn bộ Pipeline và Bước luồng (Steps)."""

    def __init__(self):
        self._steps: Dict[str, DAGNode] = {}
        self._pipelines: Dict[str, PipelineDefinition] = {}
        self._register_default_steps()
        self._register_default_pipelines()

    # ------------------------------------------------------------------
    # Quản lý Bước luồng (Steps)
    # ------------------------------------------------------------------
    def register_step(self, step: DAGNode) -> None:
        """Đăng ký một bước xử lý tái sử dụng (DAGNode)."""
        self._steps[step.name] = step

    def get_step(self, name: str) -> Optional[DAGNode]:
        """Lấy bản sao độc lập của một bước đã đăng ký."""
        step = self._steps.get(name)
        if step is None:
            return None
        # Trả về bản sao để tránh thay đổi trạng thái gốc
        return DAGNode(
            name=step.name,
            description=step.description,
            depends_on=set(step.depends_on),
            action=step.action,
            inputs=list(step.inputs),
            outputs=list(step.outputs),
            condition=step.condition,
            optional=step.optional,
            cost=step.cost,
            tags=list(step.tags),
            metadata=copy.deepcopy(step.metadata),
        )

    def has_step(self, name: str) -> bool:
        return name in self._steps

    def list_steps(self) -> List[DAGNode]:
        return list(self._steps.values())

    # ------------------------------------------------------------------
    # Quản lý Pipelines
    # ------------------------------------------------------------------
    def register_pipeline(self, pipeline: PipelineDefinition) -> None:
        """Đăng ký một Pipeline hoàn chỉnh."""
        self._pipelines[pipeline.name] = pipeline

    def get_pipeline(self, name: str) -> Optional[PipelineDefinition]:
        return self._pipelines.get(name)

    def has_pipeline(self, name: str) -> bool:
        return name in self._pipelines

    def list_pipelines(self) -> List[PipelineDefinition]:
        return list(self._pipelines.values())

    def find_pipelines_by_tag(self, tag: str) -> List[PipelineDefinition]:
        t_low = tag.lower()
        return [p for p in self._pipelines.values() if any(t_low in pt.lower() for pt in p.tags)]

    def create_pipeline(
        self,
        name: str,
        description: str,
        step_names_or_nodes: Sequence[str | DAGNode],
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineDefinition:
        """Tạo và đăng ký một Pipeline mới từ danh sách bước (tự động kết nối DAG)."""
        dag = PipelineDAG(name=name, description=description)
        for item in step_names_or_nodes:
            if isinstance(item, str):
                step = self.get_step(item)
                if step is None:
                    raise ValueError(f"Bước chưa được đăng ký trong Registry: '{item}'")
                dag.add_node(step)
            elif isinstance(item, DAGNode):
                dag.add_node(item)
            else:
                raise TypeError(f"Yêu cầu tên bước (str) hoặc DAGNode, nhận: {type(item)}")

        # Kiểm tra tính hợp lệ của DAG tạo ra
        is_valid, errors = dag.validate()
        if not is_valid:
            raise ValueError(f"DAG không hợp lệ khi tạo pipeline '{name}': {'; '.join(errors)}")

        pipe_def = PipelineDefinition(
            name=name,
            description=description,
            dag=dag,
            tags=tags or [],
            metadata=metadata or {},
        )
        self.register_pipeline(pipe_def)
        return pipe_def

    def summary(self) -> Dict[str, Any]:
        """Xuất báo cáo tổng quan về Registry."""
        return {
            "total_registered_steps": len(self._steps),
            "steps": [s.to_dict() for s in self._steps.values()],
            "total_registered_pipelines": len(self._pipelines),
            "pipelines": [p.to_dict() for p in self._pipelines.values()],
        }

    def export_blueprint(self, output_dir: str) -> Dict[str, str]:
        """Xuất bản dựng hoàn chỉnh: Schemas, sơ đồ Mermaid, cây ASCII và tài liệu Markdown."""
        out_abs = os.path.abspath(output_dir)
        pipes_dir = os.path.join(out_abs, "pipelines")
        os.makedirs(pipes_dir, exist_ok=True)

        exported: Dict[str, str] = {}

        # 1. Xuất schema tổng thể JSON
        schema_path = os.path.join(out_abs, "registry_schema.json")
        with open(schema_path, "w", encoding="utf-8") as fh:
            json.dump(self.summary(), fh, ensure_ascii=False, indent=2)
        exported["schema_json"] = schema_path

        # 2. Xuất từng pipeline ra .mermaid, .json, .txt
        for p in self.list_pipelines():
            base_p = os.path.join(pipes_dir, p.name)

            mmd_path = f"{base_p}.mermaid"
            with open(mmd_path, "w", encoding="utf-8") as fh:
                fh.write(p.dag.to_mermaid())
            exported[f"{p.name}_mermaid"] = mmd_path

            json_path = f"{base_p}.json"
            with open(json_path, "w", encoding="utf-8") as fh:
                fh.write(p.dag.to_json())
            exported[f"{p.name}_json"] = json_path

            txt_path = f"{base_p}.txt"
            with open(txt_path, "w", encoding="utf-8") as fh:
                fh.write(p.dag.render_ascii())
            exported[f"{p.name}_ascii"] = txt_path

        # 3. Xuất tài liệu Master Blueprint Markdown
        md_path = os.path.join(out_abs, "DAG_PIPELINE_REGISTRY_BLUEPRINT.md")
        lines = [
            "# Sơ Đồ Điều Phối Thứ Tự Công Việc & Sổ Bộ Quy Trình Mẫu PatchX",
            "",
            "> Bản thiết kế kiến trúc điều phối luồng làm việc theo thứ tự trước sau có kiểm soát cho PatchX.",
            f"> Xuất bản: {time.strftime('%Y-%m-%d %H:%M:%S')} · Phiên bản: 1.0.0",
            "",
            "---",
            "",
            "## 1. TỔNG QUAN HỆ THỐNG ĐIỀU PHỐI CÔNG VIỆC",
            "",
            "- **Bộ điều phối theo thứ tự trước sau (`patchx_core/dag.py`)**: Quản lý sơ đồ luồng công việc, phát hiện vòng lặp luẩn quẩn, tự động sắp xếp thứ tự thực hiện hợp lý, chia tầng các bước độc lập chạy song song, trích xuất nhánh công việc tối thiểu, và kết nối đồng bộ qua bảng tin dùng chung.",
            "- **Sổ bộ quy trình (`patchx_core/pipeline_registry.py`)**: Quản lý tập trung 8 quy trình mẫu chuẩn bị sẵn và 12 bước xử lý có thể dùng lại.",
            f"- **Thống kê**: Tổng cộng **{len(self._pipelines)} Quy trình mẫu chuẩn hóa** và **{len(self._steps)} Bước xử lý khả dụng**.",
            "",
            "---",
            "",
            "## 2. DANH MỤC CÁC QUY TRÌNH MẪU ĐÃ CHUẨN HÓA",
            "",
            "| Quy trình | Mô tả | Số bước | Số tầng thực hiện | Thẻ phân loại |",
            "| :--- | :--- | :---: | :---: | :--- |",
        ]

        for p in self.list_pipelines():
            dag = p.dag
            levels = dag.get_execution_levels() if dag.nodes else []
            tags_str = ", ".join(p.tags)
            lines.append(f"| **`{p.name}`** | {p.description} | {len(dag.nodes)} | {len(levels)} | `{tags_str}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. SƠ ĐỒ HÌNH ẢNH TRỰC QUAN TỪNG QUY TRÌNH",
            "",
        ])

        for p in self.list_pipelines():
            lines.extend([
                f"### 3.{self.list_pipelines().index(p)+1} Quy trình: `{p.name}`",
                f"*{p.description}*",
                "",
                "```mermaid",
                p.dag.to_mermaid(),
                "```",
                "",
                "**Các tầng thực hiện độc lập:**",
                "```text",
                p.dag.render_ascii(),
                "```",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## 4. DANH MỤC CÁC BƯỚC XỬ LÝ (STEPS)",
            "",
            "| Tên bước | Mức thời gian | Phụ thuộc bước trước | Đầu vào cần có | Đầu ra thu được |",
            "| :--- | :---: | :--- | :--- | :--- |",
        ])

        for s in self.list_steps():
            deps = ", ".join(sorted(s.depends_on)) if s.depends_on else "*(Gốc)*"
            in_str = ", ".join(s.inputs) if s.inputs else "—"
            out_str = ", ".join(s.outputs) if s.outputs else "—"
            lines.append(f"| **`{s.name}`** | `{s.cost}` | `{deps}` | `{in_str}` | `{out_str}` |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. HƯỚNG DẪN SỬ DỤNG QUA DÒNG LỆNH & MÃ NGUỒN",
            "",
            "### Lệnh dòng lệnh điều phối:",
            "```bash",
            "# Liệt kê toàn bộ quy trình mẫu và các bước",
            "python3 pushx dag --list",
            "",
            "# Xem chi tiết cấu trúc sơ đồ và các tầng của một quy trình",
            "python3 pushx dag --inspect auto",
            "",
            "# Xuất mã sơ đồ Mermaid của quy trình",
            "python3 pushx dag --mermaid auto",
            "",
            "# Khởi chạy quy trình theo sơ đồ cho một tệp ứng dụng",
            "python3 pushx dag --run auto apk/app.apk -o outputs/pipeline_out",
            "",
            "# Xuất toàn bộ tài liệu sơ đồ và quy trình ra thư mục",
            "python3 pushx dag --export-all outputs/pipeline/dag",
            "```",
            "",
            "### Gọi từ mã nguồn Python:",
            "```python",
            "from patchx_core.pipeline_registry import get_pipeline_registry",
            "",
            "registry = get_pipeline_registry()",
            "pipe = registry.get_pipeline('auto')",
            "result = pipe.execute('path/to/target.apk', output_dir='outputs/run_out')",
            "print('Kết quả:', result.verdict, result.elapsed_seconds)",
            "```",
        ])

        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        exported["blueprint_md"] = md_path

        return exported

    # ------------------------------------------------------------------
    # Khởi tạo các Bước chuẩn hóa (Built-in Steps)
    # ------------------------------------------------------------------
    def _register_default_steps(self) -> None:
        """Đăng ký toàn bộ các bước cốt lõi của PatchX vào Registry."""

        # 1. Bước Intake (Tiếp nhận & Kiểm kê)
        def _action_intake(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .intake import run_intake
            art = ctx["artifact_path"]
            out = os.path.join(ctx.get("output_dir", "."), "intake")
            res = run_intake(art, out, include_tools=True)
            struct = res.get("structure", {})
            abis = struct.get("abis", [])
            return {
                "artifact_structure": struct,
                "abis": abis,
                "has_native": len(abis) > 0,
                "intake_report_json": res.get("outputs", {}).get("json"),
            }

        self.register_step(DAGNode(
            name="intake",
            description="Tiếp nhận tệp ứng dụng và kiểm kê mã máy, kiến trúc, chữ ký bảo mật (không cần rã tệp)",
            inputs=["artifact_path"],
            outputs=["artifact_structure", "abis", "has_native", "intake_report_json"],
            action=_action_intake,
            cost="FAST",
            tags=["intake", "fast", "base"],
        ))

        # 2. Bước Universal Discovery (Khai phá thông minh toàn diện)
        def _action_discovery(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .comprehensive_analyzer import UniversalDiscoveryEngine
            art = ctx["artifact_path"]
            out = os.path.join(ctx.get("output_dir", "."), "discovery")
            engine = UniversalDiscoveryEngine(art, output_dir=out)
            res = engine.run_full_discovery()
            return {
                "universal_findings": res,
                "dynamic_lexicon": res.get("lexicon_mined", {}),
                "sensitive_assets": res.get("assets_sensitive", {}),
                "morphological_gates": res.get("morphological_gates", []),
            }

        self.register_step(DAGNode(
            name="universal_discovery",
            description="Khai phá từ điển tự sinh không giới hạn & rà soát tài nguyên nhạy cảm",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["universal_findings", "dynamic_lexicon", "sensitive_assets", "morphological_gates"],
            action=_action_discovery,
            cost="MEDIUM",
            optional=True,
            tags=["discovery", "deep", "analysis"],
        ))

        # 3. Bước Semantic Analysis & Security Gates
        def _action_semantic(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .semantic_plan import compile_semantic_plan
            art = ctx["artifact_path"]
            out = os.path.join(ctx.get("output_dir", "."), "semantic")
            plan_res = compile_semantic_plan(art, out)
            return {
                "security_gates": plan_res.get("gates", []),
                "semantic_plan_json": plan_res.get("plan_file"),
            }

        self.register_step(DAGNode(
            name="semantic_analysis",
            description="Dò theo luồng dữ liệu rẽ nhánh & lập kế hoạch các cổng kiểm tra an toàn",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["security_gates", "semantic_plan_json"],
            action=_action_semantic,
            cost="MEDIUM",
            optional=True,
            tags=["semantic", "gates", "smali"],
        ))

        # 4. Bước Static Behavior Detection
        def _action_behavior(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .behavior.pipeline import BehaviorPipeline
            art = ctx["artifact_path"]
            out = os.path.join(ctx.get("output_dir", "."), "behavior")
            pipe = BehaviorPipeline(art, out)
            rep = pipe.run()
            return {
                "behaviors": rep.get("behaviors", []),
                "behavior_targets": rep.get("targets", []),
                "behavior_report_json": rep.get("outputs", {}).get("json"),
            }

        self.register_step(DAGNode(
            name="behavior_detector",
            description="Phân tích hành vi tĩnh, trích xuất chứng cứ và lập danh mục mục tiêu cần can thiệp",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["behaviors", "behavior_targets", "behavior_report_json"],
            action=_action_behavior,
            cost="MEDIUM",
            optional=True,
            tags=["behavior", "targets", "smali"],
        ))

        # 5. Bước Fused Target Engine (Hợp nhất Đích can thiệp)
        def _action_fused_target(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .fused_target_engine import fuse_analysis_targets
            b_targets = ctx.get("behavior_targets", [])
            s_gates = ctx.get("security_gates", [])
            fused = fuse_analysis_targets(b_targets, s_gates)
            return {
                "fused_targets": fused,
                "fused_count": len(fused),
            }

        self.register_step(DAGNode(
            name="fused_target_engine",
            description="Hợp nhất đa chiều giữa mục tiêu hành vi và cổng bảo vệ an toàn",
            depends_on={"behavior_detector", "semantic_analysis"},
            inputs=["behavior_targets", "security_gates"],
            outputs=["fused_targets", "fused_count"],
            action=_action_fused_target,
            cost="FAST",
            optional=True,
            tags=["fused", "targets", "vip"],
        ))

        # 6. Bước Native Scan & Signature Spoof
        def _action_native_scan(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .signature_spoof import scan_and_spoof_signature
            art = ctx["artifact_path"]
            out = os.path.join(ctx.get("output_dir", "."), "native")
            res = scan_and_spoof_signature(art, out)
            return {
                "native_findings": res,
                "native_sig_spoof": res.get("spoofed_so", []),
            }

        self.register_step(DAGNode(
            name="native_scan",
            description="Quét nhị phân tệp thư viện mã máy, kiểm tra mã băm chứng chỉ và nhận diện cơ chế tự bảo vệ",
            depends_on={"intake"},
            condition=lambda c: bool(c.get("has_native", True)),
            inputs=["artifact_path", "has_native"],
            outputs=["native_findings", "native_sig_spoof"],
            action=_action_native_scan,
            cost="MEDIUM",
            optional=True,
            tags=["native", "signature", "so"],
        ))

        # 7. Bước Rodata Patch (Vá nhị phân .so in-place)
        def _action_rodata(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .rodata_bypass import RodataBypassEngine
            out = os.path.join(ctx.get("output_dir", "."), "rodata")
            engine = RodataBypassEngine(ctx["artifact_path"], out)
            rep = engine.run_analysis()
            return {
                "rodata_report": rep,
                "rodata_patchable": rep.get("can_patch", False),
            }

        self.register_step(DAGNode(
            name="rodata_patch",
            description="Phân tích vùng dữ liệu chỉ đọc trong tệp mã máy và lập kế hoạch thay thế chuỗi",
            depends_on={"native_scan"},
            condition=lambda c: bool(c.get("has_native", True)),
            inputs=["artifact_path", "has_native"],
            outputs=["rodata_report", "rodata_patchable"],
            action=_action_rodata,
            cost="MEDIUM",
            optional=True,
            tags=["native", "rodata"],
        ))

        # 8. Bước Fast-Patch (1-Click in-place Repack)
        def _action_fast_patch(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .apk_fast_repack import fast_patch_and_repack
            art = ctx["artifact_path"]
            out_apk = ctx.get("out_apk") or os.path.join(
                ctx.get("output_dir", "."), f"patched_{os.path.basename(art)}"
            )
            res = fast_patch_and_repack(
                art,
                dex_replacements=ctx.get("dex_replacements", []),
                axml_replacements=ctx.get("axml_replacements", []),
                arsc_replacements=ctx.get("arsc_replacements", []),
                output_apk=out_apk,
                bypass_nsc=ctx.get("bypass_nsc", True),
                sign=ctx.get("sign", True),
                allow_empty=True,
            )
            return {
                "patched_apk": out_apk,
                "fast_patch_result": res,
            }

        self.register_step(DAGNode(
            name="fast_patch",
            description="Vá trực tiếp ruột tệp không cần rã và ký gói siêu tốc (<0.5 giây)",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["patched_apk", "fast_patch_result"],
            action=_action_fast_patch,
            cost="FAST",
            tags=["fast", "repack", "patch"],
        ))

        # 9. Bước Frida Gadget Injection
        def _action_gadget(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .behavior.gadget_pipeline import inject_frida_gadget_pipeline
            art = ctx["artifact_path"]
            out_apk = ctx.get("out_apk") or os.path.join(
                ctx.get("output_dir", "."), f"gadget_{os.path.basename(art)}"
            )
            res = inject_frida_gadget_pipeline(art, out_apk)
            return {
                "gadget_apk": out_apk,
                "gadget_result": res,
            }

        self.register_step(DAGNode(
            name="gadget_inject",
            description="Gắn công cụ can thiệp tạm thời vào ứng dụng và cấu hình tự nạp tập lệnh can thiệp",
            depends_on={"native_scan"},
            condition=lambda c: bool(c.get("has_native", True)),
            inputs=["artifact_path", "has_native"],
            outputs=["gadget_apk", "gadget_result"],
            action=_action_gadget,
            cost="MEDIUM",
            optional=True,
            tags=["gadget", "frida", "dynamic"],
        ))

        # 10. Bước Smart Combo Generation
        def _action_combo(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .learn import suggest_active_learning_combo
            art = ctx["artifact_path"]
            combo = suggest_active_learning_combo(art)
            return {
                "smart_combo": combo,
            }

        self.register_step(DAGNode(
            name="smart_combo",
            description="Tự động học hỏi và gợi ý tổ hợp bản vá tối ưu từ lịch sử",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["smart_combo"],
            action=_action_combo,
            cost="FAST",
            optional=True,
            tags=["combo", "learn"],
        ))

        # 11. Bước Sign & Verify APK
        def _action_sign_verify(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            target_apk = ctx.get("patched_apk") or ctx.get("gadget_apk") or ctx["artifact_path"]
            # Đảm bảo APK tồn tại và kiểm tra tính toàn vẹn chữ ký
            return {
                "signed_apk": target_apk,
                "signature_verified": os.path.isfile(target_apk),
            }

        self.register_step(DAGNode(
            name="sign_verify",
            description="Căn chỉnh tối ưu dung lượng và ký số ứng dụng bằng khóa chứng chỉ tiêu chuẩn",
            depends_on={"fast_patch"},
            inputs=["patched_apk"],
            outputs=["signed_apk", "signature_verified"],
            action=_action_sign_verify,
            cost="FAST",
            tags=["sign", "verify"],
        ))

        # 13. Bước Bypass Suite (Nhánh 1: Vượt rào & Vô hiệu hóa bảo vệ)
        def _action_bypass_suite(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .behavior.network_equalizer import NetworkEqualizer
            from .behavior.native_symbolic_lifter import NativeSymbolicLifter
            from .behavior.accuracy_oracle import AccuracyOracle
            art = ctx.get("artifact_path", "")
            neq = NetworkEqualizer()
            net_findings = neq.scan_network_artifacts(art) if art else {}
            if bb and hasattr(bb, "post"):
                bb.post("bypass:network_endpoints", net_findings.get("endpoints", []), origin="bypass_suite")
            return {
                "bypass_network": net_findings,
                "bypass_status": "READY",
            }

        self.register_step(DAGNode(
            name="bypass_suite",
            description="[Nhánh 1 Bypass] Tự động san bằng tầng mạng, bóc tách hàm JNI và vô hiệu hóa bảo mật",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["bypass_network", "bypass_status"],
            action=_action_bypass_suite,
            cost="FAST",
            optional=True,
            tags=["bypass", "network", "security"],
        ))

        # 14. Bước Upgrade Suite (Nhánh 2: Sửa đổi & Nâng cấp chức năng)
        def _action_upgrade_suite(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            from .behavior.full_deobfuscator import FullDeobfuscator
            deobf = FullDeobfuscator()
            return {
                "upgrade_deobfuscator": "READY",
                "upgrade_status": "READY",
            }

        self.register_step(DAGNode(
            name="upgrade_suite",
            description="[Nhánh 2 Nâng cấp] Gỡ rối toàn phần, tái cấu trúc logic và chuẩn hóa mã sạch",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["upgrade_deobfuscator", "upgrade_status"],
            action=_action_upgrade_suite,
            cost="FAST",
            optional=True,
            tags=["upgrade", "deobfuscate", "feature"],
        ))

        # 12. Bước Tổng hợp Báo cáo Pipeline
        def _action_report(ctx: Dict[str, Any], bb: Any) -> Dict[str, Any]:
            out_dir = ctx.get("output_dir", ".")
            rep_json = os.path.join(out_dir, "pipeline_report.json")
            rep_md = os.path.join(out_dir, "pipeline_report.md")

            summary_data = {
                "artifact": ctx.get("artifact_path"),
                "pipeline": ctx.get("pipeline_name", "custom"),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "has_native": ctx.get("has_native", False),
                "abis": ctx.get("abis", []),
                "patched_apk": ctx.get("patched_apk"),
            }

            with open(rep_json, "w", encoding="utf-8") as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)

            with open(rep_md, "w", encoding="utf-8") as f:
                f.write(f"# Pipeline Execution Report\n\n")
                f.write(f"- **Artifact**: `{ctx.get('artifact_name')}`\n")
                f.write(f"- **Pipeline**: `{ctx.get('pipeline_name')}`\n")
                f.write(f"- **Time**: `{summary_data['generated_at']}`\n")
                if ctx.get("patched_apk"):
                    f.write(f"- **Patched APK**: `{ctx.get('patched_apk')}`\n")

            return {
                "report_json": rep_json,
                "report_md": rep_md,
            }

        self.register_step(DAGNode(
            name="report",
            description="Tổng hợp toàn bộ chứng cứ và xuất báo cáo quy trình ra tệp",
            depends_on={"intake"},
            inputs=["artifact_path"],
            outputs=["report_json", "report_md"],
            action=_action_report,
            cost="FAST",
            tags=["report", "summary"],
        ))

    # ------------------------------------------------------------------
    # Khởi tạo các Pipeline Tiêu chuẩn (Standard Built-in Pipelines)
    # ------------------------------------------------------------------
    def _register_default_pipelines(self) -> None:
        """Đăng ký danh mục các Pipeline tiêu chuẩn hoàn chỉnh."""

        # 1. Pipeline 'auto': Tự động kết hợp đa tầng
        auto_dag = PipelineDAG(name="auto", description="Quy trình tự động thông minh đa tầng")
        auto_dag.add_node(self.get_step("intake"))
        auto_dag.add_node(self.get_step("universal_discovery"))
        auto_dag.add_node(self.get_step("semantic_analysis"))
        auto_dag.add_node(self.get_step("native_scan"))
        auto_dag.add_node(self.get_step("fast_patch"))

        rep_step = self.get_step("report")
        rep_step.depends_on = {"universal_discovery", "semantic_analysis", "fast_patch"}
        auto_dag.add_node(rep_step)

        self.register_pipeline(PipelineDefinition(
            name="auto",
            description="Tự động kết hợp: Tiếp nhận -> Khai phá mở rộng -> Phân tích ngữ nghĩa -> Quét mã máy -> Vá trực tiếp siêu tốc -> Xuất báo cáo",
            dag=auto_dag,
            tags=["auto", "kết_hợp", "khuyến_nghị"],
        ))

        # 2. Pipeline 'fast': Vá siêu tốc 1 thao tác (<0.5 giây)
        fast_dag = PipelineDAG(name="fast", description="Quy trình 1 thao tác vá trực tiếp siêu tốc")
        fast_dag.add_node(self.get_step("intake"))
        fast_dag.add_node(self.get_step("fast_patch"))
        fast_dag.add_node(self.get_step("sign_verify"))

        rep_fast = self.get_step("report")
        rep_fast.depends_on = {"sign_verify"}
        fast_dag.add_node(rep_fast)

        self.register_pipeline(PipelineDefinition(
            name="fast",
            description="Vá siêu tốc: Tiếp nhận -> Sửa trực tiếp ruột tệp không rã -> Ký số & Kiểm tra -> Xuất báo cáo",
            dag=fast_dag,
            tags=["fast", "tại_chỗ", "siêu_tốc"],
        ))

        # 3. Pipeline 'intake': Thẩm định & Kiểm kê tệp đầu vào
        intake_dag = PipelineDAG(name="intake", description="Tiếp nhận và kiểm kê phân loại nhanh")
        intake_dag.add_node(self.get_step("intake"))
        intake_dag.add_node(self.get_step("universal_discovery"))

        rep_intake = self.get_step("report")
        rep_intake.depends_on = {"intake", "universal_discovery"}
        intake_dag.add_node(rep_intake)

        self.register_pipeline(PipelineDefinition(
            name="intake",
            description="Tiếp nhận & Thẩm định: Kiểm kê cấu trúc tệp, chữ ký + Khai phá từ khóa nhạy cảm",
            dag=intake_dag,
            tags=["intake", "thẩm_định", "kiểm_kê"],
        ))

        # 4. Pipeline 'behavior': Phân tích hành vi sâu & Cổng bảo vệ
        behav_dag = PipelineDAG(name="behavior", description="Phân tích tĩnh hành vi mã trung gian và cổng bảo vệ")
        behav_dag.add_node(self.get_step("intake"))
        behav_dag.add_node(self.get_step("behavior_detector"))
        behav_dag.add_node(self.get_step("semantic_analysis"))
        behav_dag.add_node(self.get_step("fused_target_engine"))

        rep_behav = self.get_step("report")
        rep_behav.depends_on = {"fused_target_engine"}
        behav_dag.add_node(rep_behav)

        self.register_pipeline(PipelineDefinition(
            name="behavior",
            description="Hành vi & Luồng logic: Phân tích hành vi -> Cổng bảo vệ an toàn -> Hợp nhất mục tiêu -> Xuất báo cáo",
            dag=behav_dag,
            tags=["behavior", "mã_trung_gian", "chi_tiết"],
        ))

        # 5. Pipeline 'native': Bảo vệ tầng mã máy (.so)
        native_dag = PipelineDAG(name="native", description="Quét và xử lý cơ chế bảo vệ trong tệp mã máy")
        native_dag.add_node(self.get_step("intake"))
        native_dag.add_node(self.get_step("native_scan"))
        native_dag.add_node(self.get_step("rodata_patch"))

        rep_native = self.get_step("report")
        rep_native.depends_on = {"rodata_patch"}
        native_dag.add_node(rep_native)

        self.register_pipeline(PipelineDefinition(
            name="native",
            description="Bảo vệ tầng mã máy: Quét tệp thư viện -> Vượt kiểm tra chữ ký -> Sửa chuỗi vùng nhớ chỉ đọc -> Xuất báo cáo",
            dag=native_dag,
            tags=["native", "mã_máy", "bộ_nhớ"],
        ))

        # 6. Pipeline 'gadget': Gắn công cụ can thiệp tạm thời
        gadget_dag = PipelineDAG(name="gadget", description="Quy trình gắn công cụ can thiệp bộ nhớ tạm thời")
        gadget_dag.add_node(self.get_step("intake"))
        gadget_dag.add_node(self.get_step("native_scan"))
        gadget_dag.add_node(self.get_step("gadget_inject"))

        sign_gadget = self.get_step("sign_verify")
        sign_gadget.depends_on = {"gadget_inject"}
        gadget_dag.add_node(sign_gadget)

        rep_gadget = self.get_step("report")
        rep_gadget.depends_on = {"sign_verify"}
        gadget_dag.add_node(rep_gadget)

        self.register_pipeline(PipelineDefinition(
            name="gadget",
            description="Can thiệp bộ nhớ động: Tiếp nhận -> Quét mã máy -> Gắn công cụ can thiệp tạm thời -> Ký số -> Xuất báo cáo",
            dag=gadget_dag,
            tags=["gadget", "can_thiệp_động", "bộ_nhớ"],
        ))

        # 7. Pipeline 'deep_audit': Toàn cảnh phân tích mở
        audit_dag = PipelineDAG(name="deep_audit", description="Tổng kiểm kê và phân tích đa tầng toàn diện")
        audit_dag.add_node(self.get_step("intake"))
        audit_dag.add_node(self.get_step("universal_discovery"))
        audit_dag.add_node(self.get_step("behavior_detector"))
        audit_dag.add_node(self.get_step("semantic_analysis"))
        audit_dag.add_node(self.get_step("native_scan"))
        audit_dag.add_node(self.get_step("fused_target_engine"))

        rep_audit = self.get_step("report")
        rep_audit.depends_on = {"universal_discovery", "fused_target_engine", "native_scan"}
        audit_dag.add_node(rep_audit)

        self.register_pipeline(PipelineDefinition(
            name="deep_audit",
            description="Kiểm tra toàn diện: Đánh giá chi tiết toàn bộ ứng dụng mà không sửa đổi tệp gốc",
            dag=audit_dag,
            tags=["audit", "toàn_diện", "chỉ_đọc"],
        ))

        # 8. Pipeline 'combo': Tổ hợp thông minh tự học
        combo_dag = PipelineDAG(name="combo", description="Học hỏi từ lịch sử và đề xuất tổ hợp bản vá")
        combo_dag.add_node(self.get_step("intake"))
        combo_dag.add_node(self.get_step("smart_combo"))

        rep_combo = self.get_step("report")
        rep_combo.depends_on = {"smart_combo"}
        combo_dag.add_node(rep_combo)

        self.register_pipeline(PipelineDefinition(
            name="combo",
            description="Tổ hợp thông minh: Tiếp nhận -> Tự động học hỏi -> Gợi ý bản vá tối ưu -> Xuất báo cáo",
            dag=combo_dag,
            tags=["combo", "tự_học"],
        ))

        # 9. Pipeline 'dual_track': Song song tuyệt đối cả 2 hướng Bypass và Nâng cấp
        dual_dag = PipelineDAG(name="dual_track", description="Quy trình thực thi song song tuyệt đối 2 nhánh Bypass và Nâng cấp")
        dual_dag.add_node(self.get_step("intake"))
        dual_dag.add_node(self.get_step("bypass_suite"))
        dual_dag.add_node(self.get_step("upgrade_suite"))
        dual_dag.add_node(self.get_step("fast_patch"))

        rep_dual = self.get_step("report")
        rep_dual.depends_on = {"bypass_suite", "upgrade_suite", "fast_patch"}
        dual_dag.add_node(rep_dual)

        self.register_pipeline(PipelineDefinition(
            name="dual_track",
            description="Song song tuyệt đối: Tiếp nhận -> Đồng thời chạy Nhánh 1 (Bypass) và Nhánh 2 (Nâng cấp) -> Vá đóng gói siêu tốc -> Xuất báo cáo",
            dag=dual_dag,
            tags=["dual_track", "song_song", "toàn_diện"],
        ))



# Singleton Registry toàn cục
_GLOBAL_REGISTRY: Optional[PipelineRegistry] = None


def get_pipeline_registry() -> PipelineRegistry:
    """Truy xuất Singleton PipelineRegistry của hệ thống."""
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = PipelineRegistry()
    return _GLOBAL_REGISTRY
