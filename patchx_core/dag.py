# -*- coding: utf-8 -*-
"""dag — Directed Acyclic Graph (DAG) Dependency Engine cho PatchX.

Cung cấp động cơ điều phối luồng có kiểm soát phụ thuộc đa tầng:
  1. DAGNode: Định nghĩa một node bước trong quy trình (đầu vào, đầu ra, phụ thuộc, điều kiện, chi phí).
  2. PipelineDAG: Quản lý đồ thị có hướng không chu trình, phát hiện cycle (Kahn's / DFS),
     sắp xếp topo (Topological Sort), phân tầng thực thi (Execution Levels),
     trích xuất đồ thị con (Subgraph), xuất Mermaid/ASCII/JSON.
  3. DAGExecutor: Thực thi các node theo thứ tự topo, hỗ trợ bỏ qua có điều kiện (conditional skip),
     xử lý lỗi mềm (optional/fallback), tích hợp sâu với SharedBlackboard và đo thời gian từng chặng.
"""

from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple


class NodeStatus(str, Enum):
    """Trạng thái thực thi của một DAGNode."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    WARN = "WARN"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class DAGNode:
    """Đại diện cho một node (bước thực thi) trong đồ thị DAG."""
    name: str
    description: str = ""
    depends_on: Set[str] = field(default_factory=set)
    action: Optional[Callable[[Dict[str, Any], Any], Any]] = None
    inputs: List[str] = field(default_factory=list)      # Các khóa cần từ context/blackboard
    outputs: List[str] = field(default_factory=list)     # Các khóa sẽ sinh ra context/blackboard
    condition: Optional[Callable[[Dict[str, Any]], bool]] = None  # Điều kiện để chạy
    optional: bool = False                               # Nếu lỗi, không làm sập toàn bộ pipeline
    cost: str = "FAST"                                   # FAST (<0.3s), MEDIUM (0.3-2s), DEEP (>2s)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.depends_on, (list, tuple)):
            self.depends_on = set(self.depends_on)
        elif self.depends_on is None:
            self.depends_on = set()

    def can_execute(self, context: Dict[str, Any]) -> bool:
        """Kiểm tra điều kiện thực thi của node dựa trên context hiện tại."""
        if self.condition is not None:
            try:
                return bool(self.condition(context))
            except Exception:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "depends_on": sorted(list(self.depends_on)),
            "inputs": self.inputs,
            "outputs": self.outputs,
            "optional": self.optional,
            "cost": self.cost,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class NodeExecutionRecord:
    """Bản ghi kết quả thực thi của một node trong DAG."""
    name: str
    status: NodeStatus
    started_at: float = 0.0
    finished_at: float = 0.0
    elapsed_seconds: float = 0.0
    output_data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    skip_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "error": self.error_message,
            "skip_reason": self.skip_reason,
            "output_keys": list(self.output_data.keys()) if isinstance(self.output_data, dict) else [],
        }


@dataclass
class DAGExecutionResult:
    """Kết quả tổng thể của một lần chạy PipelineDAG."""
    dag_name: str
    verdict: str                        # SUCCESS, PARTIAL, FAILED, DRY_RUN
    started_at_str: str
    finished_at_str: str
    elapsed_seconds: float
    records: Dict[str, NodeExecutionRecord]
    context: Dict[str, Any]
    failed_nodes: List[str] = field(default_factory=list)
    skipped_nodes: List[str] = field(default_factory=list)
    executed_nodes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dag_name": self.dag_name,
            "verdict": self.verdict,
            "started_at": self.started_at_str,
            "finished_at": self.finished_at_str,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "executed_count": len(self.executed_nodes),
            "skipped_count": len(self.skipped_nodes),
            "failed_count": len(self.failed_nodes),
            "nodes": {k: v.to_dict() for k, v in self.records.items()},
        }


class PipelineDAG:
    """Đồ thị có hướng không chu trình điều phối quy trình PatchX."""

    def __init__(self, name: str = "patchx_dag", description: str = ""):
        self.name = name
        self.description = description
        self.nodes: Dict[str, DAGNode] = {}
        self.metadata: Dict[str, Any] = {}

    def add_node(self, node: DAGNode) -> PipelineDAG:
        """Thêm một node vào DAG. Trả về self để cho phép chaining."""
        self.nodes[node.name] = node
        return self

    def get_node(self, name: str) -> Optional[DAGNode]:
        return self.nodes.get(name)

    def has_node(self, name: str) -> bool:
        return name in self.nodes

    def remove_node(self, name: str) -> bool:
        """Xóa node khỏi DAG và xóa các quan hệ phụ thuộc trỏ tới nó."""
        if name not in self.nodes:
            return False
        del self.nodes[name]
        for node in self.nodes.values():
            node.depends_on.discard(name)
        return True

    def validate(self) -> Tuple[bool, List[str]]:
        """Kiểm tra tính hợp lệ của DAG: phát hiện phụ thuộc thiếu hoặc vòng lặp.

        Trả về (is_valid, error_messages).
        """
        errors = []
        # 1. Kiểm tra missing dependencies
        for name, node in self.nodes.items():
            for dep in node.depends_on:
                if dep not in self.nodes:
                    errors.append(f"Node '{name}' phụ thuộc vào node không tồn tại: '{dep}'")

        # 2. Kiểm tra cycles qua toposort
        if not errors:
            try:
                self.toposort()
            except ValueError as exc:
                errors.append(str(exc))

        return len(errors) == 0, errors

    def toposort(self) -> List[str]:
        """Sắp xếp các node theo thứ tự Topological (Kahn's Algorithm).

        Ném ValueError nếu phát hiện đồ thị có vòng lặp (Cycle).
        """
        in_degree: Dict[str, int] = {name: 0 for name in self.nodes}
        dependents: Dict[str, List[str]] = {name: [] for name in self.nodes}

        for name, node in self.nodes.items():
            for dep in node.depends_on:
                if dep in in_degree:
                    in_degree[name] += 1
                    dependents[dep].append(name)

        # Hàng đợi các node có bậc vào bằng 0 (không phụ thuộc node nào còn lại)
        queue = [name for name, deg in in_degree.items() if deg == 0]
        # Sắp xếp để thứ tự determinism
        queue.sort()

        order: List[str] = []
        while queue:
            curr = queue.pop(0)
            order.append(curr)
            for nxt in dependents.get(curr, []):
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)
                    queue.sort()

        if len(order) != len(self.nodes):
            remaining = [name for name, deg in in_degree.items() if deg > 0]
            raise ValueError(f"Phát hiện chu trình (Cycle) trong DAG tại các node: {remaining}")

        return order

    def get_execution_levels(self) -> List[List[str]]:
        """Chia đồ thị thành các tầng thực thi (Execution Levels).

        Các node trong cùng một tầng hoàn toàn độc lập với nhau và có thể chạy đồng thời.
        """
        self.toposort()  # Kiểm tra cycle trước
        in_degree = {name: len(node.depends_on) for name, node in self.nodes.items()}
        dependents: Dict[str, List[str]] = {name: [] for name in self.nodes}
        for name, node in self.nodes.items():
            for dep in node.depends_on:
                if dep in dependents:
                    dependents[dep].append(name)

        current_level = [name for name, deg in in_degree.items() if deg == 0]
        current_level.sort()
        levels: List[List[str]] = []

        while current_level:
            levels.append(current_level)
            next_level = []
            for curr in current_level:
                for nxt in dependents.get(curr, []):
                    in_degree[nxt] -= 1
                    if in_degree[nxt] == 0:
                        next_level.append(nxt)
            next_level.sort()
            current_level = next_level

        return levels

    def subgraph(self, targets: Sequence[str]) -> PipelineDAG:
        """Trích xuất đồ thị con tối thiểu chứa các target nodes và toàn bộ upstream dependencies."""
        needed_nodes: Set[str] = set()
        stack = [t for t in targets if t in self.nodes]

        while stack:
            curr = stack.pop()
            if curr not in needed_nodes:
                needed_nodes.add(curr)
                for dep in self.nodes[curr].depends_on:
                    if dep in self.nodes and dep not in needed_nodes:
                        stack.append(dep)

        sub_dag = PipelineDAG(
            name=f"{self.name}_subgraph",
            description=f"Subgraph for targets: {list(targets)}"
        )
        for name in needed_nodes:
            orig = self.nodes[name]
            cloned = DAGNode(
                name=orig.name,
                description=orig.description,
                depends_on=orig.depends_on.intersection(needed_nodes),
                action=orig.action,
                inputs=list(orig.inputs),
                outputs=list(orig.outputs),
                condition=orig.condition,
                optional=orig.optional,
                cost=orig.cost,
                tags=list(orig.tags),
                metadata=copy.deepcopy(orig.metadata),
            )
            sub_dag.add_node(cloned)

        return sub_dag

    def to_mermaid(self, direction: str = "TD") -> str:
        """Sinh chuỗi sơ đồ Mermaid chuẩn Markdown cho DAG."""
        lines = [f"graph {direction}"]
        cost_icons = {"FAST": "⚡", "MEDIUM": "⏱️", "DEEP": "🔬"}

        for name, node in sorted(self.nodes.items()):
            icon = cost_icons.get(node.cost, "•")
            label = f"{icon} {name}"
            if node.description:
                # Cắt ngắn mô tả nếu quá dài
                desc = (node.description[:24] + "..") if len(node.description) > 24 else node.description
                label += f"<br/><small>{desc}</small>"
            lines.append(f'    {name}["{label}"]')

        for name, node in sorted(self.nodes.items()):
            for dep in sorted(list(node.depends_on)):
                lines.append(f"    {dep} --> {name}")

        return "\n".join(lines)

    def render_ascii(self) -> str:
        """Sinh sơ đồ ASCII dạng cây trực quan cho Terminal CLI."""
        levels = self.get_execution_levels()
        out = [f"DAG: {self.name} ({len(self.nodes)} nodes, {len(levels)} levels)"]
        for i, lvl in enumerate(levels, 1):
            out.append(f"  [Tầng {i}]")
            for node_name in lvl:
                node = self.nodes[node_name]
                deps = f" <- [{', '.join(sorted(node.depends_on))}]" if node.depends_on else ""
                cost_str = f"({node.cost})"
                opt_str = " (optional)" if node.optional else ""
                out.append(f"    ├── {node_name} {cost_str}{opt_str}{deps}")
        return "\n".join(out)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "total_nodes": len(self.nodes),
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "levels": self.get_execution_levels() if self.nodes else [],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def execute(
        self,
        context: Optional[Dict[str, Any]] = None,
        blackboard: Any = None,
        stop_on_fail: bool = True,
        dry_run: bool = False,
    ) -> DAGExecutionResult:
        """Thực thi DAG theo thứ tự topo."""
        start_mono = time.monotonic()
        started_str = time.strftime("%Y-%m-%d %H:%M:%S")

        ctx: Dict[str, Any] = dict(context or {})
        records: Dict[str, NodeExecutionRecord] = {}
        failed_nodes: List[str] = []
        skipped_nodes: List[str] = []
        executed_nodes: List[str] = []

        is_valid, errors = self.validate()
        if not is_valid:
            return DAGExecutionResult(
                dag_name=self.name,
                verdict="FAILED",
                started_at_str=started_str,
                finished_at_str=time.strftime("%Y-%m-%d %H:%M:%S"),
                elapsed_seconds=round(time.monotonic() - start_mono, 4),
                records={},
                context=ctx,
                failed_nodes=["DAG_VALIDATION"],
            )

        order = self.toposort()

        for name in order:
            node = self.nodes[name]

            # 1. Kiểm tra xem các node tiên quyết có bị FAILED không
            parent_failed = any(dep in failed_nodes for dep in node.depends_on)
            if parent_failed:
                rec = NodeExecutionRecord(
                    name=name,
                    status=NodeStatus.SKIPPED,
                    skip_reason="Node phụ thuộc bị lỗi",
                )
                records[name] = rec
                skipped_nodes.append(name)
                continue

            # 2. Kiểm tra điều kiện runtime của node
            if not node.can_execute(ctx):
                rec = NodeExecutionRecord(
                    name=name,
                    status=NodeStatus.SKIPPED,
                    skip_reason="Không thỏa mãn điều kiện thực thi (condition False)",
                )
                records[name] = rec
                skipped_nodes.append(name)
                continue

            # 3. Chế độ dry-run
            if dry_run:
                rec = NodeExecutionRecord(
                    name=name,
                    status=NodeStatus.SUCCESS,
                    skip_reason="Dry run - mô phỏng thành công",
                )
                records[name] = rec
                executed_nodes.append(name)
                continue

            # 4. Thực thi hành động của node
            t_node_start = time.monotonic()
            rec = NodeExecutionRecord(name=name, status=NodeStatus.RUNNING, started_at=t_node_start)
            records[name] = rec

            try:
                output_res = None
                if node.action is not None:
                    output_res = node.action(ctx, blackboard)

                rec.finished_at = time.monotonic()
                rec.elapsed_seconds = rec.finished_at - t_node_start
                rec.status = NodeStatus.SUCCESS

                # Ghi output vào context và blackboard nếu có
                if isinstance(output_res, dict):
                    rec.output_data = output_res
                    ctx.update(output_res)
                    if blackboard is not None and hasattr(blackboard, "post"):
                        for out_k, out_v in output_res.items():
                            blackboard.post(out_k, out_v, origin=f"dag_node:{name}")

                executed_nodes.append(name)

            except Exception as exc:
                rec.finished_at = time.monotonic()
                rec.elapsed_seconds = rec.finished_at - t_node_start
                rec.error_message = str(exc)

                if node.optional:
                    rec.status = NodeStatus.WARN
                    executed_nodes.append(name)
                else:
                    rec.status = NodeStatus.FAILED
                    failed_nodes.append(name)
                    if stop_on_fail:
                        break

        total_elapsed = time.monotonic() - start_mono
        finished_str = time.strftime("%Y-%m-%d %H:%M:%S")

        if dry_run:
            verdict = "DRY_RUN"
        elif failed_nodes:
            verdict = "FAILED"
        elif any(r.status == NodeStatus.WARN for r in records.values()):
            verdict = "PARTIAL"
        else:
            verdict = "SUCCESS"

        return DAGExecutionResult(
            dag_name=self.name,
            verdict=verdict,
            started_at_str=started_str,
            finished_at_str=finished_str,
            elapsed_seconds=total_elapsed,
            records=records,
            context=ctx,
            failed_nodes=failed_nodes,
            skipped_nodes=skipped_nodes,
            executed_nodes=executed_nodes,
        )
