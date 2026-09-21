# -*- coding: utf-8 -*-
"""test_dag_pipeline — Bộ kiểm thử toàn diện cho DAG Dependency Engine và Pipeline Registry."""

import os
import shutil
import tempfile
import unittest
import zipfile

from patchx_core.dag import DAGNode, PipelineDAG, NodeStatus, DAGExecutionResult
from patchx_core.pipeline_registry import PipelineRegistry, PipelineDefinition, get_pipeline_registry
from patchx_core.blackboard import SharedBlackboard


class TestDAGDependencyEngine(unittest.TestCase):

    def test_dagnode_init_and_condition(self):
        node = DAGNode(
            name="test_step",
            description="A test step",
            depends_on={"dep1", "dep2"},
            inputs=["fact1"],
            outputs=["fact2"],
            condition=lambda ctx: ctx.get("enable_step", False),
        )
        self.assertEqual(node.name, "test_step")
        self.assertIn("dep1", node.depends_on)
        self.assertFalse(node.can_execute({}))
        self.assertTrue(node.can_execute({"enable_step": True}))
        d = node.to_dict()
        self.assertEqual(d["name"], "test_step")
        self.assertEqual(d["inputs"], ["fact1"])

    def test_toposort_and_cycle_detection(self):
        dag = PipelineDAG(name="test_cycle_dag")
        dag.add_node(DAGNode(name="A", depends_on=set()))
        dag.add_node(DAGNode(name="B", depends_on={"A"}))
        dag.add_node(DAGNode(name="C", depends_on={"B"}))

        order = dag.toposort()
        self.assertEqual(order, ["A", "B", "C"])

        # Tạo chu trình: A -> B -> C -> A
        dag.nodes["A"].depends_on.add("C")
        is_valid, errors = dag.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("Cycle" in e for e in errors))

        with self.assertRaises(ValueError):
            dag.toposort()

    def test_missing_dependency_validation(self):
        dag = PipelineDAG(name="missing_dep_dag")
        dag.add_node(DAGNode(name="X", depends_on={"NON_EXISTENT"}))
        is_valid, errors = dag.validate()
        self.assertFalse(is_valid)
        self.assertTrue(any("phụ thuộc vào node không tồn tại" in e for e in errors))

    def test_execution_levels(self):
        dag = PipelineDAG(name="levels_dag")
        dag.add_node(DAGNode(name="root1"))
        dag.add_node(DAGNode(name="root2"))
        dag.add_node(DAGNode(name="mid1", depends_on={"root1"}))
        dag.add_node(DAGNode(name="mid2", depends_on={"root1", "root2"}))
        dag.add_node(DAGNode(name="leaf", depends_on={"mid1", "mid2"}))

        levels = dag.get_execution_levels()
        self.assertEqual(len(levels), 3)
        self.assertEqual(sorted(levels[0]), ["root1", "root2"])
        self.assertEqual(sorted(levels[1]), ["mid1", "mid2"])
        self.assertEqual(levels[2], ["leaf"])

    def test_subgraph_extraction(self):
        dag = PipelineDAG(name="full_dag")
        dag.add_node(DAGNode(name="A"))
        dag.add_node(DAGNode(name="B", depends_on={"A"}))
        dag.add_node(DAGNode(name="C", depends_on={"B"}))
        dag.add_node(DAGNode(name="D", depends_on={"A"}))

        # Trích xuất subgraph chỉ đến C
        sub = dag.subgraph(["C"])
        self.assertEqual(set(sub.nodes.keys()), {"A", "B", "C"})
        self.assertNotIn("D", sub.nodes)

    def test_dag_execution_with_blackboard(self):
        bb = SharedBlackboard()
        dag = PipelineDAG(name="exec_dag")

        def act_step1(ctx, board):
            return {"num1": 10, "step1_done": True}

        def act_step2(ctx, board):
            val = ctx.get("num1", 0) * 2
            return {"num2": val, "step2_done": True}

        dag.add_node(DAGNode(name="step1", action=act_step1, outputs=["num1"]))
        dag.add_node(DAGNode(name="step2", depends_on={"step1"}, action=act_step2, outputs=["num2"]))

        res = dag.execute(context={"init_key": "ok"}, blackboard=bb)
        self.assertEqual(res.verdict, "SUCCESS")
        self.assertEqual(res.context["num1"], 10)
        self.assertEqual(res.context["num2"], 20)
        self.assertTrue(bb.has("num1"))
        self.assertTrue(bb.has("num2"))
        self.assertEqual(bb.get("num2"), 20)

    def test_conditional_skip(self):
        dag = PipelineDAG(name="cond_dag")
        dag.add_node(DAGNode(name="always_run", action=lambda ctx, bb: {"ran_always": True}))
        dag.add_node(DAGNode(
            name="skipped_step",
            depends_on={"always_run"},
            condition=lambda ctx: ctx.get("should_run", False),
            action=lambda ctx, bb: {"ran_skip": True}
        ))

        res = dag.execute(context={"should_run": False})
        self.assertEqual(res.verdict, "SUCCESS")
        self.assertIn("skipped_step", res.skipped_nodes)
        self.assertEqual(res.records["skipped_step"].status, NodeStatus.SKIPPED)

    def test_optional_node_error(self):
        dag = PipelineDAG(name="opt_dag")

        def failing_action(ctx, bb):
            raise RuntimeError("Temporary glitch")

        dag.add_node(DAGNode(name="opt_step", optional=True, action=failing_action))
        res = dag.execute()
        self.assertEqual(res.verdict, "PARTIAL")
        self.assertEqual(res.records["opt_step"].status, NodeStatus.WARN)


class TestPipelineRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = PipelineRegistry()

    def test_default_steps_and_pipelines(self):
        steps = self.registry.list_steps()
        self.assertGreaterEqual(len(steps), 10)

        pipelines = self.registry.list_pipelines()
        self.assertGreaterEqual(len(pipelines), 8)
        names = [p.name for p in pipelines]
        self.assertIn("auto", names)
        self.assertIn("fast", names)
        self.assertIn("native", names)
        self.assertIn("gadget", names)
        self.assertIn("deep_audit", names)

    def test_dynamic_pipeline_creation(self):
        custom_pipe = self.registry.create_pipeline(
            name="my_custom",
            description="A custom workflow",
            step_names_or_nodes=["intake", "fast_patch"],
            tags=["custom", "test"],
        )
        self.assertEqual(custom_pipe.name, "my_custom")
        self.assertTrue(self.registry.has_pipeline("my_custom"))
        self.assertEqual(custom_pipe.dag.toposort(), ["intake", "fast_patch"])

    def test_mermaid_and_ascii(self):
        pipe = self.registry.get_pipeline("auto")
        mermaid = pipe.dag.to_mermaid()
        self.assertIn("graph TD", mermaid)
        self.assertIn("intake --> fast_patch", mermaid)

        ascii_tree = pipe.dag.render_ascii()
        self.assertIn("[Tầng 1]", ascii_tree)
        self.assertIn("intake", ascii_tree)


if __name__ == "__main__":
    unittest.main()
