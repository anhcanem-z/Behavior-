# -*- coding: utf-8 -*-
"""T4 — thong minh (hoc + de xuat): kho combo thanh cong, goi y theo danh
mức APK, va khung patch theo y dinh mod (nguoi dung duyet trước khi ap)."""

import json
import os
import re
import time

from .optimizer import (CAP_LABELS, find_conflicts, merge_patches,
                        patch_capabilities)
from .session import load_patch_map


CATEGORY_KEYWORDS = [
    ("game", ("unity", "garena", "supercell", "riot", "vng", "game",
              "com.tencent", "miHoYo", "hoyoverse")),
    ("ngân hàng/tài chính", ("bank", "vpbank", "timo", "momo", "zalopay",
                             "vnptpay", "pay", "finance")),
    ("mạng xã hội", ("facebook", "zalo", "messenger", "tiktok", "whatsapp",
                     "telegram", "social")),
    ("mua sắm", ("shopee", "lazada", "tiki", "sendo", "amazon", "shopping")),
]

INTENT_KEYWORDS = {
    "bypass-license": ("vip", "license", "ban quyen", "khoa", "premium",
                       "pro", "unlock", "mo khoa"),
    "purchase": ("mua hang", "iap", "in-app", "billing", "gia lap mua"),
    "ads": ("quang cao", "ads", "advert", "chan quang cao"),
    "shell": ("shell", "vo", "token"),
    "integrity": ("toan ven", "integrity", "signature", "chu ky",
                  "sigcheck", "xac thuc"),
    "google": ("google", "play protect", "play protect"),
    "root-hide": ("root", "magisk", "an root", "quyen root"),
    "ssl-pinning": ("ssl", "pinning", "chung chi", "bat goi", "proxy",
                    "certificate"),
    "anti-debug": ("debug", "go lỗi", "debugger"),
    "frida-hide": ("frida", "kiem tra frida", "an frida"),
    "emulator": ("may ao", "emulator", "gia lap may"),
    "trace": ("truy vet", "trace", "theo doi", "du lieu"),
    "anonymity": ("an danh", "anonym", "giau"),
}


def success_store_path(root):
    return os.path.join(root, "outputs", "combos", "combos_success.json")


def record_success(root, entry):
    """Ghi combo/chuoi patch ap thanh cong vao kho (kem danh mức app)."""
    path = success_store_path(root)
    data = []
    if os.path.isfile(path):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            data = []
    data.append(dict(entry, ts=time.strftime("%Y-%m-%d %H:%M:%S")))
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return path


def categorize(package_name):
    pkg = (package_name or "").lower()
    for cat, pats in CATEGORY_KEYWORDS:
        if any(p.lower() in pkg for p in pats):
            return cat
    return "chung"


def intent_capabilities(intent_text):
    """Tu mo ta y dinh → tap nang luc (keyword don gian, cuc bo)."""
    low = (intent_text or "").lower()
    caps = set()
    for cap, kws in INTENT_KEYWORDS.items():
        if any(k.lower() in low for k in kws):
            caps.add(cap)
    if not caps:
        caps.add("bypass-license")  # mac dinh: y dinh mod thuong la bypass
    return caps


def suggest_by_intent(intent_text, patches, caps=None):
    """Chon patch theo y dinh — tra list dict {patch, năng_lực}."""
    caps = caps or intent_capabilities(intent_text)
    scored = []
    for name, p in patches.items():
        pcaps = patch_capabilities(p)
        hit = pcaps & caps
        if hit:
            scored.append({"patch": name, "năng_lực": sorted(hit),
                           "khớp_y_dinh": len(hit)})
    scored.sort(key=lambda x: -x["khớp_y_dinh"])
    return scored, caps


def build_skeleton(patches, selected_names, name):
    """Gop cac patch da chon thanh mot khung patch (combo) tu chua."""
    sel = [patches[n] for n in selected_names if n in patches]
    merged = merge_patches(sel, name)
    conflicts = len(find_conflicts(sel))
    return merged, conflicts


def suggest_plan(tree, collection, top=8):
    """Goi y chuoi patch cho APK that: coverage + danh mức + combo thanh cong."""
    from .advisor import coverage_patch
    from .smali_sem import entry_classes
    patches = load_patch_map(collection)
    app, launchers = entry_classes(tree)
    cat = categorize((app or launchers[0] if launchers else ""))
    scored = []
    for name, p in patches.items():
        try:
            cov = coverage_patch(p, tree)
        except Exception:
            continue
        if cov["quy_tắc_khớp"] > 0:
            scored.append({"patch": name,
                           "tỷ_lệ": cov["tỷ_lệ"],
                           "khớp": cov["quy_tắc_khớp"],
                           "năng_lực": sorted(patch_capabilities(p))})
    scored.sort(key=lambda x: (-x["tỷ_lệ"], -x["khớp"]))
    store = success_store_path(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    history = []
    if os.path.isfile(store):
        try:
            history = [e for e in json.load(open(store, encoding="utf-8"))
                       if e.get("danh_mục") == cat]
        except Exception:
            history = []
    return {"package": app or (launchers[0] if launchers else ""),
            "danh_mục": cat,
            "khớp": scored[:top],
            "combo_đã_thành_công": history[-5:],
            "gợi_ý": "Chuoi khuyen nghi: " + ", ".join(
                s["patch"] for s in scored[:3]) if scored else
            "Khong co patch khớp APK nay."}


def analyze_success_patterns(root):
    """Phân tích các mẫu kết hợp thành công từ kho combos_success.json."""
    store = success_store_path(root)
    if not os.path.isfile(store):
        return {"pairs": {}, "frequent_patches": {}, "total_records": 0}
    try:
        data = json.load(open(store, encoding="utf-8"))
    except Exception:
        return {"pairs": {}, "frequent_patches": {}, "total_records": 0}

    frequent_patches = {}
    pairs = {}
    for entry in data:
        raw_combo = entry.get("combo") or entry.get("patches") or []
        if isinstance(raw_combo, str):
            patches = [p.strip() for p in raw_combo.split(",") if p.strip()]
        elif isinstance(raw_combo, list):
            patches = [str(p).strip() for p in raw_combo if str(p).strip()]
        else:
            patches = []
        for p in patches:
            frequent_patches[p] = frequent_patches.get(p, 0) + 1
        for i in range(len(patches)):
            for j in range(i + 1, len(patches)):
                pair = tuple(sorted([patches[i], patches[j]]))
                pairs[pair] = pairs.get(pair, 0) + 1

    return {
        "pairs": pairs,
        "frequent_patches": frequent_patches,
        "total_records": len(data),
    }


def generate_smart_combo(tree, collection, intent=None, max_patches=4, name=None):
    """Máy sinh Smart-Combo tự động (Active Learning):

    Kết hợp độ khớp cây Smali (AST coverage) + trọng số học từ combos_success.json + lọc xung đột find_conflicts.
    """
    from .advisor import coverage_patch
    from .smali_sem import entry_classes
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    patterns = analyze_success_patterns(root)
    frequent = patterns["frequent_patches"]

    patches = load_patch_map(collection)
    app, launchers = entry_classes(tree) if os.path.isdir(tree) else (None, [])
    cat = categorize((app or (launchers[0] if launchers else "")))

    caps_filter = intent_capabilities(intent) if intent else None

    candidates = []
    for pname, p in patches.items():
        pcaps = patch_capabilities(p)
        if caps_filter and not (pcaps & caps_filter):
            continue

        cov_score = 0.0
        match_rules = 0
        if os.path.isdir(tree):
            try:
                cov = coverage_patch(p, tree)
                cov_score = cov.get("tỷ_lệ", 0.0)
                match_rules = cov.get("quy_tắc_khớp", 0)
            except Exception:
                cov_score = 0.0

        # Trọng số thành công lịch sử
        hist_weight = frequent.get(pname, 0) * 1.5
        total_score = (cov_score * 100.0) + (match_rules * 5.0) + hist_weight
        candidates.append({
            "name": pname,
            "patch": p,
            "cov_score": cov_score,
            "match_rules": match_rules,
            "hist_weight": hist_weight,
            "score": total_score,
            "caps": list(pcaps),
        })

    candidates.sort(key=lambda x: -x["score"])

    # Chọn lọc các patch không bị xung đột (greedy selection with conflict checking)
    selected_patches = []
    selected_names = []
    for cand in candidates:
        if len(selected_patches) >= max_patches:
            break
        trial = selected_patches + [cand["patch"]]
        conflicts = find_conflicts(trial)
        if not conflicts:
            selected_patches.append(cand["patch"])
            selected_names.append(cand["name"])

    combo_name = name or ("smart_combo_%s_%s" % (cat.replace("/", "_").replace(" ", "_"), time.strftime("%Y%m%d_%H%M%S")))
    merged, conf_count = build_skeleton(patches, selected_names, combo_name)

    return {
        "combo_name": combo_name,
        "package": app or (launchers[0] if launchers else ""),
        "category": cat,
        "selected_patches": selected_names,
        "patch_count": len(selected_names),
        "conflicts": conf_count,
        "merged_patch": merged,
        "historical_records_used": patterns["total_records"],
    }


def save_smart_combo(merged_patch, output_path, header=None):
    """Lưu patch combo ra file trên đĩa."""
    from .optimizer import render_patch_text
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    text = render_patch_text(merged_patch, header=header or "Smart-Combo (Active Learning)")
    with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return output_path


def suggest_active_learning_combo(artifact_path: str, collection=None, intent=None):
    """Tự động học hỏi từ lịch sử (combos_success.json & KINH_NGHIEM_HOC_HOI.md)
    và đề xuất tổ hợp bản vá tối ưu (Active Learning Combo) không xung đột.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if collection is None:
        collection = os.path.join(root, "upgraded")
        if not os.path.isdir(collection):
            collection = os.path.join(root, "combos")

    learned_intents = set()
    kinh_nghiem_path = os.path.join(root, "KINH_NGHIEM_HOC_HOI.md")
    if os.path.isfile(kinh_nghiem_path):
        try:
            with open(kinh_nghiem_path, "r", encoding="utf-8", errors="ignore") as fh:
                kn_text = fh.read().lower()
                for cap, kws in INTENT_KEYWORDS.items():
                    if any(kw in kn_text for kw in kws):
                        learned_intents.add(cap)
        except Exception:
            pass

    effective_intent = intent
    if not effective_intent and learned_intents:
        effective_intent = " ".join(learned_intents)

    return generate_smart_combo(
        tree=artifact_path,
        collection=collection,
        intent=effective_intent,
        max_patches=5,
    )

