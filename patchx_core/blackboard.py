# -*- coding: utf-8 -*-
"""blackboard — Bể Tri Thức Dùng Chung & Mạng Năng Lực Toàn Cục (Global Capability Fabric).

Cho phép mọi module trong PatchX:
  1. Tự khai báo năng lực (Capabilities), dữ liệu đầu vào cần thiết và sản phẩm đầu ra.
  2. Chia sẻ sự kiện, bằng chứng (Evidence, Targets, Gates, Chữ ký, .rodata) vào một Bể Tri Thức chung (Blackboard).
  3. Tự động phản xạ và gọi nối nhau dựa trên Ý định người dùng (Intent-Driven Composition) thay vì gắn cứng thứ tự.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class CapabilityCard:
    """Thẻ mô tả năng lực của một module trong hệ thống."""
    name: str
    provider: str
    description: str
    requires: List[str]            # Danh sách khóa Fact cần có trong Blackboard
    produces: List[str]            # Danh sách khóa Fact sẽ sinh ra
    tags: List[str] = field(default_factory=list)  # Nhãn ý định: "fast", "vip", "native", "security", "deep"
    cost: str = "FAST"             # FAST (<0.3s), MEDIUM (0.3-2s), DEEP (>2s)
    executor: Optional[Callable[..., Any]] = None

    def can_run(self, available_facts: Set[str]) -> bool:
        """Kiểm tra xem các yêu cầu tiên quyết đã có đủ trong Blackboard chưa."""
        return all(req in available_facts for req in self.requires)


class SharedBlackboard:
    """Bể tri thức tập trung chia sẻ dữ liệu và phản xạ sự kiện giữa mọi module."""

    def __init__(self, initial_facts: Optional[Dict[str, Any]] = None):
        self._facts: Dict[str, Any] = {}
        self._fact_origins: Dict[str, str] = {}
        self._fact_mtimes: Dict[str, float] = {}
        self._listeners: Dict[str, List[Callable[[str, Any, SharedBlackboard], None]]] = {}
        self._capabilities: Dict[str, CapabilityCard] = {}

        if initial_facts:
            for k, v in initial_facts.items():
                self.post(k, v, origin="init")

        self._register_default_capabilities()

    def post(self, key: str, value: Any, origin: str = "") -> None:
        """Ghi một sự kiện/dữ liệu mới vào bể tri thức và kích hoạt các module lắng nghe."""
        self._facts[key] = value
        self._fact_origins[key] = origin or "unknown"
        self._fact_mtimes[key] = time.time()

        if key in self._listeners:
            for callback in self._listeners[key]:
                try:
                    callback(key, value, self)
                except Exception:
                    pass

    def get(self, key: str, default: Any = None) -> Any:
        """Lấy dữ liệu từ bể tri thức."""
        return self._facts.get(key, default)

    def has(self, key: str) -> bool:
        """Kiểm tra sự tồn tại của dữ liệu."""
        return key in self._facts

    def subscribe(self, key: str, callback: Callable[[str, Any, SharedBlackboard], None]) -> None:
        """Đăng ký lắng nghe khi có dữ liệu mới ở khóa cụ thể."""
        self._listeners.setdefault(key, []).append(callback)

    def register_capability(self, card: CapabilityCard) -> None:
        """Đăng ký một năng lực module mới vào mạng lưới toàn cục."""
        self._capabilities[card.name] = card

    def get_capability(self, name: str) -> Optional[CapabilityCard]:
        return self._capabilities.get(name)

    def list_capabilities(self) -> List[CapabilityCard]:
        return list(self._capabilities.values())

    def find_capabilities_by_tag(self, tag: str) -> List[CapabilityCard]:
        """Tìm các module có khả năng phục vụ cho ý định (tag) chỉ định."""
        t_low = tag.lower()
        return [c for c in self._capabilities.values() if any(t_low in ct.lower() for ct in c.tags)]

    def available_facts_set(self) -> Set[str]:
        return set(self._facts.keys())

    def plan_chain_for_intent(self, intent: str) -> List[CapabilityCard]:
        """Tự động tính toán chuỗi module tối ưu để thực thi theo Ý định (Intent)."""
        candidate_caps = self.find_capabilities_by_tag(intent)
        if not candidate_caps:
            candidate_caps = list(self._capabilities.values())

        available = set(self.available_facts_set())
        planned_chain: List[CapabilityCard] = []
        remaining = list(candidate_caps)

        max_iterations = len(remaining) + 2
        for _ in range(max_iterations):
            progress = False
            for cap in list(remaining):
                if cap.can_run(available):
                    planned_chain.append(cap)
                    remaining.remove(cap)
                    for prod in cap.produces:
                        available.add(prod)
                    progress = True
            if not progress or not remaining:
                break

        return planned_chain

    def summary(self) -> Dict[str, Any]:
        """Xuất tổng quan trạng thái bể tri thức."""
        return {
            "total_facts": len(self._facts),
            "fact_keys": list(self._facts.keys()),
            "registered_capabilities": len(self._capabilities),
            "capabilities": [
                {
                    "name": c.name,
                    "provider": c.provider,
                    "cost": c.cost,
                    "tags": c.tags,
                    "requires": c.requires,
                    "produces": c.produces,
                }
                for c in self._capabilities.values()
            ],
        }

    def _register_default_capabilities(self) -> None:
        """Đăng ký sẵn danh mục các năng lực cốt lõi của PatchX."""
        self.register_capability(CapabilityCard(
            name="intake",
            provider="patchx_core.intake",
            description="Tiếp nhận artifact và kiểm kê cấu trúc DEX/ABI/chữ ký (Zero-Extraction)",
            requires=["artifact_path"],
            produces=["artifact_structure", "abis", "has_native"],
            tags=["intake", "fast", "audit", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="behavior_detector",
            provider="patchx_core.behavior.detector",
            description="Phân tích hành vi tĩnh, trích xuất Evidence và dựng CFG rẽ nhánh",
            requires=["smali_tree"],
            produces=["behaviors", "evidence_list"],
            tags=["behavior", "deep", "vip", "audit", "all"],
            cost="MEDIUM",
        ))

        self.register_capability(CapabilityCard(
            name="target_analyzer",
            provider="patchx_core.behavior.target",
            description="Xác định và phân hạng các mục tiêu cần can thiệp logic",
            requires=["behaviors"],
            produces=["behavior_targets"],
            tags=["behavior", "target", "vip", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="semantic_taint",
            provider="patchx_core.smali_sem",
            description="Lần vết thanh ghi (Taint Flow) phát hiện cổng bảo mật rẽ nhánh Zero-Workkey",
            requires=["smali_tree"],
            produces=["security_gates"],
            tags=["semantic", "zero_workkey", "gate", "deep", "all"],
            cost="MEDIUM",
        ))

        self.register_capability(CapabilityCard(
            name="fused_target_engine",
            provider="patchx_core.fused_target_engine",
            description="Cộng hưởng hợp nhất giữa Behavior Targets và Security Gates (Dual Confirmed)",
            requires=["behavior_targets", "security_gates"],
            produces=["fused_targets"],
            tags=["target", "fused", "vip", "gate", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="auto_gate_patcher",
            provider="patchx_core.auto_gate_patcher",
            description="Tự động đảo ngược lệnh rẽ nhánh if-* hoặc ép return boolean tĩnh",
            requires=["security_gates", "smali_tree"],
            produces=["patched_smali_gates"],
            tags=["patch", "gate", "static", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="fast_patch",
            provider="patchx_core.apk_fast_repack",
            description="1-Click vá DEX + AXML + ARSC in-place không qua Apktool (<0.3s)",
            requires=["artifact_path"],
            produces=["fast_patched_apk"],
            tags=["fast", "inplace", "repack", "vip", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="native_signature_spoof",
            provider="patchx_core.signature_spoof",
            description="Quét nhị phân .so, thay thế SHA-256 cert hash và sinh Java Frida hook",
            requires=["artifact_path", "has_native"],
            produces=["native_sig_spoof", "frida_native_hook"],
            tags=["native", "signature", "rasp", "all"],
            cost="MEDIUM",
        ))

        self.register_capability(CapabilityCard(
            name="frida_generator",
            provider="patchx_core.frida_generator",
            description="Tự động sinh kịch bản hook Frida Java đa tầng theo danh sách Target",
            requires=["behavior_targets"],
            produces=["frida_hook_script"],
            tags=["frida", "dynamic", "hook", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="rodata_patcher",
            provider="patchx_core.rodata_bypass",
            description="Bypass .rodata chuỗi nhị phân ELF và Frida RAM patching",
            requires=["has_native"],
            produces=["rodata_patch_script"],
            tags=["native", "rodata", "deep", "all"],
            cost="MEDIUM",
        ))

        self.register_capability(CapabilityCard(
            name="smart_combo",
            provider="patchx_core.learn",
            description="Tự động sinh tổ hợp patch dựa trên Active Learning và lịch sử thành công",
            requires=["artifact_path"],
            produces=["smart_combo_zip"],
            tags=["combo", "learn", "all"],
            cost="FAST",
        ))

        self.register_capability(CapabilityCard(
            name="universal_discovery",
            provider="patchx_core.comprehensive_analyzer",
            description="Phân tích thông minh toàn diện, quét tệp nhạy cảm (assets/raw/cert/db) & khai phá từ điển động không giới hạn",
            requires=["artifact_path"],
            produces=["universal_findings", "dynamic_lexicon", "sensitive_assets", "morphological_gates"],
            tags=["discovery", "deep", "sensitive", "all"],
            cost="MEDIUM",
        ))


_GLOBAL_BLACKBOARD: Optional[SharedBlackboard] = None


def get_global_blackboard() -> SharedBlackboard:
    """Truy xuất Bể Tri Thức toàn cục (tạo mới nếu chưa có)."""
    global _GLOBAL_BLACKBOARD
    if _GLOBAL_BLACKBOARD is None:
        _GLOBAL_BLACKBOARD = SharedBlackboard()
    return _GLOBAL_BLACKBOARD
