# -*- coding: utf-8 -*-
"""behavior_learner — TỰ ĐỘNG ghi nhận hành vi MỚI phát hiện trong quá trình
quét các APK/lib khác nhau.

Cơ chế:
  - Sau mỗi lần `patchx smart-scan` / `patchx start-scan`, learner rà toàn bộ
    finding: gom behavior.id + category chưa nằm trong từ điển gốc
    (smart_ontology.SMART_BEHAVIORS) hoặc kho đã phát hiện.
  - Ghi vào `outputs/behavior/discovered/behaviors.json` (kho tổng hợp) và
    `behaviors_<nguồn>.json` (theo từng APK/lib) — KHÔNG tự sửa từ điển gốc.
  - Lần quét sau, `all_behaviors()` gộp từ điển gốc + kho đã phát hiện để
    nhận diện hành vi không còn bị coi là "mới".

Cấu trúc entry kho:
  {"id": "ten_hanh_vi", "kind": "behavior|category", "label": "...",
   "first_seen": "YYYY-MM-DD HH:MM", "sources": ["nguồn1", ...]}
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List

from .smart_ontology import SMART_BEHAVIORS

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
DISCOVERED_DIR = os.path.join(BASE_DIR, "outputs", "behavior", "discovered")
DISCOVERED_MAIN = os.path.join(DISCOVERED_DIR, "behaviors.json")


def _known_ids() -> set:
    known = set(SMART_BEHAVIORS)
    known.add("other_behavior")
    for entry in _load_main().values():
        known.add(entry["id"])
    return known


def _load_main() -> Dict[str, Any]:
    if os.path.isfile(DISCOVERED_MAIN):
        try:
            with open(DISCOVERED_MAIN, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)[:60] or "unknown"


def collect_new(report: Dict[str, Any]) -> Dict[str, Any]:
    """Gom behavior.id + category + tags lạ từ report quét."""
    known = _known_ids()
    found: Dict[str, Dict[str, Any]] = {}

    def visit(finding: Dict[str, Any]) -> None:
        # 1. Behavior object
        val = finding.get("behavior")
        if isinstance(val, dict):
            bid = val.get("id")
            if bid and bid not in known:
                entry = found.setdefault(bid, {
                    "id": bid, "kind": "behavior",
                    "label": val.get("label") or bid,
                    "first_seen": time.strftime("%Y-%m-%d %H:%M"),
                    "sources": [],
                })
                if source_name not in entry["sources"]:
                    entry["sources"].append(source_name)

        # 2. Behavior_extra tags
        for extra in finding.get("behavior_extra", []):
            if isinstance(extra, str) and extra and extra not in known:
                entry = found.setdefault(extra, {
                    "id": extra, "kind": "behavior_tag",
                    "label": extra.replace("_", " ").title(),
                    "first_seen": time.strftime("%Y-%m-%d %H:%M"),
                    "sources": [],
                })
                if source_name not in entry["sources"]:
                    entry["sources"].append(source_name)

        # 3. Category nếu chưa có trong known
        cat = finding.get("category")
        if isinstance(cat, str) and cat and cat not in known and cat not in ("log", "comment", "sample", "symbol", "library"):
            entry = found.setdefault(cat, {
                "id": cat, "kind": "category",
                "label": cat.replace("_", " ").title(),
                "first_seen": time.strftime("%Y-%m-%d %H:%M"),
                "sources": [],
            })
            if source_name not in entry["sources"]:
                entry["sources"].append(source_name)

    source_name = None
    if isinstance(report.get("repro"), dict):
        tgt = report["repro"].get("target") or report["repro"].get("file") or ""
        source_name = os.path.basename(str(tgt))
    source_name = source_name or "unknown"

    libs = report.get("libs")
    if isinstance(libs, list):
        for lib in libs:
            for f in lib.get("findings", []):
                visit(f)
    else:
        for f in report.get("findings", []):
            visit(f)
    return found


def learn_from_report(report: Dict[str, Any],
                      source: str | None = None) -> Dict[str, Any]:
    """Rà report, ghi hành vi mới vào kho (nếu có) — trả dict mới phát hiện."""
    new = collect_new(report)
    os.makedirs(DISCOVERED_DIR, exist_ok=True)
    if not os.path.isfile(DISCOVERED_MAIN):
        with open(DISCOVERED_MAIN, "w", encoding="utf-8") as fh:
            json.dump({}, fh, ensure_ascii=False, indent=2)
    if not new:
        return {}
    main = _load_main()
    for bid, entry in new.items():
        if bid in main:
            if source and source not in main[bid]["sources"]:
                main[bid]["sources"].append(source)
        else:
            main[bid] = entry
    with open(DISCOVERED_MAIN, "w", encoding="utf-8") as fh:
        json.dump(main, fh, ensure_ascii=False, indent=2)
    slug = _slug(source or "unknown")
    per = os.path.join(DISCOVERED_DIR, "behaviors_%s.json" % slug)
    with open(per, "w", encoding="utf-8") as fh:
        json.dump({"source": source, "new": new}, fh,
                  ensure_ascii=False, indent=2)
    return new


def all_behaviors() -> Dict[str, Dict[str, Any]]:
    """Từ điển gốc + hành vi đã phát hiện (dùng để nhận diện lần sau)."""
    merged = dict(SMART_BEHAVIORS)
    for bid, entry in _load_main().items():
        if bid not in merged:
            merged[bid] = {
                "label": entry.get("label", bid),
                "description": "Hành vi tự phát hiện (behavior_learner) — "
                               "chưa xác nhận trong từ điển gốc.",
                "suggestions": [],
                "categories": [entry.get("kind", "other")],
                "keywords": [entry["id"]],
                "risk_base": 30,
                "noise": False,
                "discovered": True,
            }
    return merged
