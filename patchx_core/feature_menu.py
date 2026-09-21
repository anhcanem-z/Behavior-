# -*- coding: utf-8 -*-
"""feature_menu — DANH SÁCH CHỨC NĂNG ĐỂ LỰA CHỌN (menu pipeline).

Giải quyết vấn đề: toolkit có nhiều lệnh nhưng khó biết gọi đúng pipeline
nào cho mục tiêu của mình. Module này:
  - Tổ chức chức năng thành NHÓM theo bước luồng thực tế
    (chuẩn bị -> phân tích -> chọn bypass/patch -> áp -> build -> kiểm tra).
  - Sắp xếp hiển thị hợp lý: nhóm theo flow_step, mục theo priority,
    đánh số liên tục để chọn nhanh.
  - Tính điểm khớp khi tìm theo mục tiêu (--goal): đếm từ khóa trong
    tên/mô tả/đầu vào/đầu ra -> xếp hạng.
  - Chạy pipeline đúng thứ tự (--run ID hoặc chọn số tương tác), thay
    placeholder {KEY} bằng giá trị người dùng nhập / --set.

Chạy:
    python3 patchx menu                 # menu tương tác (chọn số)
    python3 patchx menu --list          # in toàn bộ danh sách
    python3 patchx menu --goal "patch chuỗi trong so"   # tìm + xếp hạng
    python3 patchx menu --run rodata-static --set SO=lib.so --set OLD="..." --set NEW="..."
    python3 -m patchx_core.feature_menu --list
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

BANNER = """\
============================================================
  PatchX — DANH SÁCH CHỨC NĂNG (chọn pipeline đúng mục tiêu)
------------------------------------------------------------
  Bước luồng: 1 Chuẩn bị -> 2 Phân tích -> 3 Bypass/Patch
              -> 4 Áp dụng -> 5 Build -> 6 Kiểm tra & đo
  Mẹo: dùng --goal \"từ khóa\" để tìm; --run ID để chạy luôn.
============================================================"""

# {PY} là python thực thi (mặc định python3; máy này dùng python3.12).
DEFAULT_PY = "python3"

# ---- phân chia nền tảng: NATIVE (.so) / SMALI (DEX/APK) / CHUNG ----
PLATFORM_BY_ID = {
    "rodata-static": "native", "rodata-dynamic": "native",
    "rodata-bypass-ui": "native", "smart-scan": "native", "start-scan": "native",
    "behavior-pipeline": "smali", "smart-patch": "smali",
    "remote-control": "smali",
    "analyze-model": "smali", "targets": "smali",
    "gadget-pipeline": "chung", "apk-prepare": "chung",
    "scan-index": "chung", "audit": "chung", "selfcheck-test": "chung",
    "upgrade-combo": "chung", "apply-patch": "chung", "apk-build": "chung",
    "apk-full": "chung", "coverage-roadmap": "chung", "simulate": "chung",
    "ci-golden": "chung",
    "unified-pipeline": "chung", "fast-patch": "smali",
    "native-sig-bypass": "native", "intake-triage": "chung",
    "targets-fused": "smali", "smart-combo": "chung", "dag-pipeline": "chung",
}
PLATFORM_ORDER = {"native": 0, "smali": 1, "chung": 2}
PLATFORM_LABEL = {"native": "NATIVE (.so/.elf)", "smali": "SMALI (DEX/APK)",
                  "chung": "CHUNG (build/test/đo)"}
PLATFORM_BADGE = {"native": "[.so]", "smali": "[smali]", "chung": "[chung]"}


def item_platform(item: Dict[str, Any]) -> str:
    """Nền tảng của chức năng: native (lib .so) / smali (DEX/APK) / chung."""
    return PLATFORM_BY_ID.get(item.get("id", ""), "chung")

FEATURE_GROUPS: List[Dict[str, Any]] = [
    {
        "name": "BYPASS CHUỖI TRONG .so (RODATA)",
        "flow_step": 3,
        "items": [
            {
                "id": "rodata-static",
                "name": "Patch TĨNH — chèn chuỗi trực tiếp vào file .so",
                "desc": "Tìm RVA chuỗi rồi ghi đè ngay trong file .so (không cần "
                        "Frida). Backup trước khi ghi. Chuỗi mới không được dài "
                        "hơn chuỗi cũ (trừ --allow-overflow).",
                "pipeline": [
                    "{PY} patchx rodata-find {SO} --string \"{OLD}\"",
                    "{PY} patchx rodata-apply {SO} --string \"{OLD}\" --new \"{NEW}\"",
                ],
                "inputs": ["{SO}=file .so/.elf", "{OLD}=chuỗi gốc",
                           "{NEW}=chuỗi mới (độ dài ≤ chuỗi cũ)"],
                "outputs": ["file .so đã patch", "backup outputs/backup/rodata_apply/"],
                "keywords": ["static", "tĩnh", "file", "so", "rodata", "hex",
                             "trực tiếp", "không frida", "patch chuỗi"],
            },
            {
                "id": "rodata-dynamic",
                "name": "Patch ĐỘNG — Frida patch .rodata trên RAM",
                "desc": "Sinh script Frida thay chuỗi trong .rodata khi app chạy "
                        "(không sửa file gốc). Chuỗi mới độ dài VÔ HẠN: inline "
                        "(kiểm tra dung lượng) hoặc pointer (đổi con trỏ).",
                "pipeline": [
                    "{PY} patchx rodata-find {SO} --string \"{OLD}\"",
                    "{PY} patchx rodata-patch {SO} --string \"{OLD}\" --new \"{NEW}\" --mode {MODE}",
                    "frida -U -f {PACKAGE} -l outputs/behavior/rodata_patch.js",
                ],
                "inputs": ["{SO}=file .so/.elf", "{OLD}=chuỗi gốc",
                           "{NEW}=chuỗi mới (độ dài tùy ý)",
                           "{MODE}=inline|pointer|both (mặc định both)",
                           "{PACKAGE}=package name của app"],
                "outputs": ["outputs/behavior/rodata_patch.js (script Frida)"],
                "keywords": ["dynamic", "động", "frida", "ram", "runtime",
                             "vô hạn", "pointer", "rodata"],
            },
            {
                "id": "rodata-bypass-ui",
                "name": "Bộ bypass RIÊNG — menu tĩnh/động (rodata_bypass)",
                "desc": "Thư mục module riêng + main hiển thị riêng: --flow "
                        "static (patch file) hoặc --flow dynamic (Frida RAM), "
                        "tách khỏi CLI cũ.",
                "pipeline": [
                    "{PY} rodata_bypass_main.py {SO} --flow {FLOW} --string \"{OLD}\" --new \"{NEW}\"",
                ],
                "inputs": ["{SO}=file .so/.elf", "{FLOW}=static|dynamic",
                           "{OLD}=chuỗi gốc", "{NEW}=chuỗi mới"],
                "outputs": ["static: file .so đã patch + backup",
                            "dynamic: script Frida (mặc định outputs/behavior/rodata_patch.js)"],
                "keywords": ["riêng", "bypass", "menu", "static", "dynamic",
                             "rodata_bypass", "rodata_bypass_main"],
            },
        ],
    },
    {
        "name": "BEHAVIOR + FRIDA (hành vi + hook)",
        "flow_step": 2,
        "items": [
            {
                "id": "behavior-pipeline",
                "name": "Phân tích hành vi + sinh hook Frida",
                "desc": "detector -> cfg -> target -> hook -> frida -> loader; "
                        "sinh generated_hook.js để nạp vào app.",
                "pipeline": [
                    "{PY} patchx behavior-pipeline {TREE} -o outputs/behavior",
                    "frida -U -f {PACKAGE} -l outputs/behavior/generated_hook.js",
                ],
                "inputs": ["{TREE}=cây APK đã giải mã (apktool)",
                           "{PACKAGE}=package name"],
                "outputs": ["outputs/behavior/review_plan.json",
                            "outputs/behavior/generated_hook.js"],
                "keywords": ["behavior", "hành vi", "hook", "frida", "target",
                             "sinh hook", "pipeline"],
            },
            {
                "id": "smart-patch",
                "name": "Bản patch thông minh smali — tự hiểu ngữ nghĩa, chống R8/D8",
                "desc": "Tái dùng detector behavior có sẵn (kể cả nhánh "
                        "obfuscated-*): detector -> target -> rank -> kế hoạch "
                        "JSON+MD -> --apply backup + patch. Không phụ thuộc tên "
                        "phương thức cố định nên hợp logic hiện đại và mã hóa "
                        "r8/d8.",
                "pipeline": [
                    "{PY} patchx smart-patch {TREE} -o outputs/behavior/smart_patch",
                    "{PY} patchx smart-patch {TREE} -o outputs/behavior/smart_patch --apply",
                ],
                "inputs": ["{TREE}=cây APK đã giải mã (apktool)"],
                "outputs": ["outputs/behavior/smart_patch/smart_patch_plan.json/.md",
                            "outputs/behavior/smart_patch/smart_patch_report.json/.md",
                            "outputs/behavior/smart_patch/backup/ (khi --apply)"],
                "keywords": ["smart", "thông minh", "patch", "r8", "d8",
                             "obfuscation", "ngữ nghĩa", "smali", "tự hiểu",
                             "chống r8", "chống d8"],
            },
            {
                "id": "gadget-pipeline",
                "name": "Nhúng Frida Gadget vào APK (không root)",
                "desc": "Nhúng libgadget.so + script/config vào APK rồi build + "
                        "ký — không cần frida-server.",
                "pipeline": [
                    "{PY} patchx gadget-pipeline {APK} -o outputs/behavior/gadget",
                ],
                "inputs": ["{APK}=APK hoặc cây APK"],
                "outputs": ["outputs/behavior/gadget/app_signed.apk",
                            "outputs/behavior/gadget/libgadget.so"],
                "keywords": ["gadget", "không root", "nhúng", "frida", "apk",
                             "libgadget"],
            },
            {
                "id": "remote-control",
                "name": "Điều khiển hành vi từ xa (flag ép + quan sát)",
                "desc": "remote-map lập bản đồ flag -> remote-patch ép giá trị "
                        "-> remote-observe quan sát + gửi lệnh qua Frida RPC.",
                "pipeline": [
                    "{PY} patchx remote-map {TREE} -o outputs/behavior/remote_flags.json",
                    "{PY} patchx remote-patch outputs/behavior/remote_flags.json --set \"{FLAG}=true\" -o outputs/behavior/force.zip",
                    "{PY} patchx remote-observe {PACKAGE} --hook outputs/behavior/generated_hook.js",
                ],
                "inputs": ["{TREE}=cây APK", "{FLAG}=flag cần ép (vd Lcls;->fld:Z)",
                           "{PACKAGE}=package name"],
                "outputs": ["outputs/behavior/remote_flags.json",
                            "outputs/behavior/force.zip"],
                "keywords": ["remote", "từ xa", "flag", "ép", "observe", "quan sát",
                             "rpc", "điều khiển"],
            },
        ],
    },
    {
        "name": "PHÂN TÍCH APK",
        "flow_step": 2,
        "items": [
            {
                "id": "apk-prepare",
                "name": "Giải mã APK thành cây (chuẩn bị đầu vào)",
                "desc": "Dùng apktool giải mã APK -> cây smali/resources để các "
                        "bước sau (coverage/apply/behavior) dùng chung.",
                "pipeline": [
                    "{PY} patchx apk-prepare {APK} -o {TREE}",
                ],
                "inputs": ["{APK}=file APK", "{TREE}=thư mục cây đích"],
                "outputs": ["cây APK đã giải mã (mặc định outputs/apk/apk-trees/)"],
                "keywords": ["giải mã", "apktool", "prepare", "cây", "decode",
                             "decompile"],
            },
            {
                "id": "analyze-model",
                "name": "Phân tích ngữ nghĩa + dựng model APK",
                "desc": "analyze phát hiện packer/mã hóa/entry; model --v2 dựng "
                        "mô hình trung gian chỉ-đọc để đối chiếu plan.",
                "pipeline": [
                    "{PY} patchx analyze {TREE}",
                    "{PY} patchx model {TREE} --v2 -o outputs/scan/app_model.json",
                ],
                "inputs": ["{TREE}=cây APK"],
                "outputs": ["outputs/scan/app_model.json"],
                "keywords": ["analyze", "model", "ngữ nghĩa", "packer", "phân tích",
                             "app-model"],
            },
            {
                "id": "targets",
                "name": "Xác định điểm cần sửa (targets)",
                "desc": "Quét cây, liệt kê class/method/dòng có hành vi đáng "
                        "xem xét kèm lý do + bằng chứng.",
                "pipeline": [
                    "{PY} patchx targets {TREE}",
                ],
                "inputs": ["{TREE}=cây APK"],
                "outputs": ["danh sách target in ra màn hình"],
                "keywords": ["target", "điểm", "sửa", "class", "method", "bằng chứng"],
            },
            {
                "id": "smart-scan",
                "name": "Quét thông minh .so — lọc nhiễu + data-flow + Confidence",
                "desc": "Quét mọi chuỗi trong .rodata/.data của file .so: phân "
                        "loại ngữ nghĩa (API key/token/endpoint vs log/comment/"
                        "sample), truy vết tham chiếu tĩnh từ mã tới chuỗi "
                        "(ADRP+ADD/LDR literal/LEA rip), xác thực chéo caller/"
                        "callee qua đồ thị gọi từ JNI, chấm Confidence 0-100 "
                        "kèm bằng chứng + SHA-256 (tái tạo được).",
                "pipeline": [
                    "{PY} patchx smart-scan {SO} -o outputs/behavior/smart_scan/report.json",
                ],
                "inputs": ["{SO}=file .so/.elf cần quét"],
                "outputs": ["outputs/behavior/smart_scan/*.json + *.md (báo cáo)"],
                "keywords": ["smart", "scan", "quét", "rodata", "nhiễu", "noise",
                             "dataflow", "data-flow", "confidence", "endpoint",
                             "api key", "token", "jni", "xác thực chéo", "so"],
            },
            {
                "id": "start-scan",
                "name": "start-scan — quét TOÀN BỘ lib .so trong APK/thư mục",
                "desc": "Đầu vào APK (trích lib/*.so), thư mục hoặc file .so; "
                        "quét từng lib bằng smart-scan rồi TỔNG HỢP: top findings "
                        "theo Confidence, bảng chi tiết từng lib (sha256, refs, "
                        "JNI, nhiễu). Tách biệt: start-scan = native .so, "
                        "behavior = smali.",
                "pipeline": [
                    "{PY} patchx start-scan {APK} --abi {ABI} -o outputs/behavior/smart_scan/start_scan.json",
                ],
                "inputs": ["{APK}=APK hoặc thư mục chứa .so",
                           "{ABI}=arm64-v8a|armeabi-v7a|x86_64 (tuỳ chọn)"],
                "outputs": ["outputs/behavior/smart_scan/start_scan.json + .md"],
                "keywords": ["start", "start_scan", "start-scan", "lib", "so",
                             "thư viện", "apk", "native", "tổng hợp", "abi"],
            },
        ],
    },
    {
        "name": "QUÉT & KIỂM TRA KHO PATCH",
        "flow_step": 6,
        "items": [
            {
                "id": "scan-index",
                "name": "Quét + lập chỉ mục kho patch",
                "desc": "scan_dir/index tạo patchx_index.json + patchx_report.md "
                        "cho thư mục patch (upgraded/).",
                "pipeline": [
                    "{PY} patchx index {REPO} -o outputs/scan",
                ],
                "inputs": ["{REPO}=thư mục kho patch (vd upgraded)"],
                "outputs": ["outputs/scan/patchx_index.json", "outputs/scan/patchx_report.md"],
                "keywords": ["scan", "index", "quét", "chỉ mục", "kho", "patch"],
            },
            {
                "id": "audit",
                "name": "Kiểm tra kiến trúc toàn kho patch",
                "desc": "Phát hiện lỗi cấu trúc patch (thẻ đóng, metadata, regex "
                        "lỗi...) trước khi nâng cấp/áp dụng.",
                "pipeline": [
                    "{PY} patchx audit {REPO} -o outputs/audit",
                ],
                "inputs": ["{REPO}=thư mục kho patch"],
                "outputs": ["outputs/audit/audit.json", "outputs/audit/audit_report.md"],
                "keywords": ["audit", "kiểm tra", "kiến trúc", "lỗi", "cảnh báo"],
            },
            {
                "id": "selfcheck-test",
                "name": "Kiểm tra sức khỏe toolkit + chạy bộ test",
                "desc": "selfcheck: module + đọc toàn bộ patch; test: chạy bộ tự "
                        "kiểm tra.",
                "pipeline": [
                    "{PY} patchx selfcheck",
                    "{PY} patchx test",
                ],
                "inputs": [],
                "outputs": ["kết quả in ra màn hình"],
                "keywords": ["selfcheck", "test", "sức khỏe", "kiểm tra", "module"],
            },
        ],
    },
    {
        "name": "PIPELINE THỐNG NHẤT & FAST-PATH (HIỆN ĐẠI)",
        "flow_step": 3,
        "items": [
            {
                "id": "unified-pipeline",
                "name": "Unified Pipeline — 1-Click Tự Động (Auto-Hybrid)",
                "desc": "Tích hợp toàn diện: Intake -> Phân tích -> Fast-Path Zero-Copy "
                        "-> Native Bypass -> Sign Debug -> Báo cáo JSON/Markdown.",
                "pipeline": [
                    "{PY} patchx pipeline {APK} --mode auto",
                ],
                "inputs": ["{APK}=file APK/APKS/XAPK/AAB"],
                "outputs": ["outputs/pipeline/pipeline_report.json",
                            "outputs/pipeline/pipeline_report.md"],
                "keywords": ["pipeline", "unified", "thống nhất", "auto", "hybrid",
                             "tự động", "1-click", "tinh gọn"],
            },
            {
                "id": "fast-patch",
                "name": "Fast-Path 1-Click (< 0.5s) — Zero-Copy In-Place Repack",
                "desc": "Vá nhị phân DEX string/bytecode, AXML security bypass, "
                        "ARSC string pool, gỡ chữ ký cũ, zipalign và ký debug siêu tốc.",
                "pipeline": [
                    "{PY} patchx fast-patch {APK} -o {OUT} --axml \"{OLD}={NEW}\"",
                ],
                "inputs": ["{APK}=file APK gốc", "{OUT}=file APK đã patch",
                           "{OLD}=chuỗi gốc", "{NEW}=chuỗi mới"],
                "outputs": ["file APK đã patch và ký"],
                "keywords": ["fast", "fast-patch", "repack", "zero-copy", "in-place",
                             "dex", "axml", "arsc", "nhanh"],
            },
            {
                "id": "intake-triage",
                "name": "Intake Triage — Tiếp nhận & Thẩm định Artifact (Không giải nén)",
                "desc": "Kiểm kê DEX, ABI, native lib, manifest, split, cert SHA-256 và tool capabilities.",
                "pipeline": [
                    "{PY} patchx intake {APK} -o outputs/intake",
                ],
                "inputs": ["{APK}=file APK/APKS/XAPK/AAB"],
                "outputs": ["outputs/intake/intake_*.json", "outputs/intake/intake_*.md"],
                "keywords": ["intake", "triage", "tiếp nhận", "kiểm tra", "split", "aab"],
            },
        ],
    },
    {
        "name": "NÂNG CẤP & ÁP DỤNG PATCH",
        "flow_step": 4,
        "items": [
            {
                "id": "upgrade-combo",
                "name": "Chuẩn hóa + gộp patch (upgrade/optimize/combo)",
                "desc": "upgrade chuẩn hóa zip; optimize gộp patch cùng mục tiêu; "
                        "combo gộp theo họ chức năng + class-link.",
                "pipeline": [
                    "{PY} patchx upgrade {REPO} -o upgraded",
                    "{PY} patchx optimize upgraded -o optimized",
                    "{PY} patchx combo optimized -o combos",
                ],
                "inputs": ["{REPO}=kho patch gốc"],
                "outputs": ["upgraded/", "optimized/", "combos/"],
                "keywords": ["upgrade", "optimize", "combo", "chuẩn hóa", "gộp",
                             "nâng cấp"],
            },
            {
                "id": "apply-patch",
                "name": "Áp patch lên cây APK đã giải mã",
                "desc": "Áp 1 hoặc nhiều patch (zip) lên cây; backup + idempotent; "
                        "dùng --dry-run để xem trước.",
                "pipeline": [
                    "{PY} patchx apply {PATCH} {TREE} --dry-run",
                    "{PY} patchx apply {PATCH} {TREE}",
                ],
                "inputs": ["{PATCH}=file zip patch", "{TREE}=cây APK"],
                "outputs": ["cây APK đã được áp patch"],
                "keywords": ["apply", "áp", "patch", "smali", "cây", "zip"],
            },
        ],
    },
    {
        "name": "BUILD & ĐÓNG GÓI APK",
        "flow_step": 5,
        "items": [
            {
                "id": "apk-build",
                "name": "Build nhanh APK (không cần patch)",
                "desc": "Build cây APK -> sign -> verify; đầu ra apk-build.",
                "pipeline": [
                    "{PY} patchx apk-build {TREE} -o outputs/apk/apk-build",
                ],
                "inputs": ["{TREE}=cây APK"],
                "outputs": ["outputs/apk/apk-build/*_signed.apk"],
                "keywords": ["build", "đóng gói", "sign", "ký", "apk"],
            },
            {
                "id": "apk-full",
                "name": "Luồng APK đầy đủ (patch + build + báo cáo)",
                "desc": "apk-plan -> apk-test -> apk-patch -> apk-build -> verify; "
                        "báo cáo tổng hợp.",
                "pipeline": [
                    "{PY} patchx_toolkit.py apk-full {APK} --output outputs/apk/apk-full --patches-file outputs/apk/apk-full/selected_patches.json",
                ],
                "inputs": ["{APK}=file APK"],
                "outputs": ["outputs/apk/apk-full/*_report.json/md", "APK đã ký"],
                "keywords": ["full", "đầy đủ", "apk-full", "pipeline", "build",
                             "patch apk"],
            },
        ],
    },
    {
        "name": "ĐO & ĐÁNH GIÁ",
        "flow_step": 6,
        "items": [
            {
                "id": "coverage-roadmap",
                "name": "Đo độ phủ + xếp hạng patch trên APK thật",
                "desc": "coverage đo mức patch áp được lên cây; roadmap xếp hạng "
                        "theo mức áp dụng được.",
                "pipeline": [
                    "{PY} patchx coverage {PATCH} {TREE}",
                    "{PY} patchx roadmap {REPO} {TREE} -o outputs/roadmap",
                ],
                "inputs": ["{PATCH}=file patch", "{TREE}=cây APK",
                           "{REPO}=kho patch"],
                "outputs": ["outputs/roadmap/roadmap.json + roadmap.md"],
                "keywords": ["coverage", "độ phủ", "roadmap", "xếp hạng", "đo"],
            },
            {
                "id": "simulate",
                "name": "Mô phỏng toàn diện kho patch",
                "desc": "Tự sinh mẫu từ regex, áp thử từng patch, chấm hiệu quả "
                        "+ idempotency + thời gian.",
                "pipeline": [
                    "{PY} patchx simulate {REPO} -o outputs/simulate",
                ],
                "inputs": ["{REPO}=kho patch"],
                "outputs": ["outputs/simulate/simulation.json + simulation_report.md"],
                "keywords": ["simulate", "mô phỏng", "idempotency", "hiệu quả"],
            },
            {
                "id": "ci-golden",
                "name": "Dây chuyền CI + baseline + golden",
                "desc": "ci: audit -> upgrade -> optimize -> combo-auto -> simulate "
                        "và báo cáo trước/sau; golden/baseline làm mốc đo.",
                "pipeline": [
                    "{PY} patchx ci {REPO} -o outputs/ci",
                    "{PY} patchx baseline capture --dir outputs/baseline",
                    "{PY} patchx golden -o outputs/golden",
                ],
                "inputs": ["{REPO}=kho patch"],
                "outputs": ["outputs/ci/ci_report.*", "outputs/baseline/metrics.json",
                            "outputs/golden/golden_gate.json"],
                "keywords": ["ci", "golden", "baseline", "dây chuyền", "mốc đo"],
            },
        ],
    },
]


def all_items() -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Trả [(group, item)] theo thứ tự HỆ THỐNG:
    nhánh nền tảng (native -> smali -> chung) -> bước luồng -> priority -> id."""
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for group in FEATURE_GROUPS:
        for item in group["items"]:
            out.append((group, item))
    out.sort(key=lambda gi: (
        PLATFORM_ORDER.get(item_platform(gi[1]), 2),
        gi[0].get("flow_step", 99),
        gi[1].get("priority", 99),
        gi[1].get("id", ""),
    ))
    return out


def find_item(feature_id: str) -> Optional[Dict[str, Any]]:
    for _g, item in all_items():
        if item["id"] == feature_id:
            return item
    return None


def _score_item(item: Dict[str, Any], words: List[str]) -> int:
    hay = " ".join([
        item.get("id", ""),
        item.get("name", ""),
        item.get("desc", ""),
        " ".join(item.get("inputs", [])),
        " ".join(item.get("outputs", [])),
        " ".join(item.get("keywords", [])),
    ]).lower()
    return sum(hay.count(w) for w in words)


def search_features(goal: str) -> List[Tuple[int, Dict[str, Any], Dict[str, Any]]]:
    """Tính điểm khớp từ khóa -> xếp hạng giảm dần (sắp xếp hợp lý)."""
    words = [w.lower() for w in goal.split() if w.strip()]
    rows: List[Tuple[int, Dict[str, Any], Dict[str, Any]]] = []
    for group, item in all_items():
        score = _score_item(item, words)
        if score > 0:
            rows.append((score, group, item))
    rows.sort(key=lambda r: (-r[0],
                             PLATFORM_ORDER.get(item_platform(r[2]), 2),
                             r[1].get("flow_step", 99)))
    return rows


def _num(items: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Dict[int, Dict[str, Any]]:
    return {i + 1: item for i, (_g, item) in enumerate(items)}


def render_catalog(show_pipeline: bool = False) -> str:
    lines = [BANNER, ""]
    items = all_items()
    lines.append("Phân chia theo NHÁNH nền tảng, trong nhánh theo BƯỚC luồng:")
    lines.append("  1. NATIVE (.so/.elf) — start-scan, smart-scan, rodata-*")
    lines.append("  2. SMALI (DEX/APK)   — behavior, targets, model, remote-*")
    lines.append("  3. CHUNG            — prepare, build, audit, đo lường")
    last_branch: Optional[str] = None
    last_group: Optional[str] = None
    n = 0
    for group, item in items:
        plat = item_platform(item)
        step = group.get("flow_step", 99)
        branch = PLATFORM_LABEL[plat]
        if branch != last_branch:
            lines.append("")
            lines.append("=" * 62)
            lines.append("NHÁNH %d — %s"
                        % (PLATFORM_ORDER[plat] + 1, branch))
            lines.append("=" * 62)
            last_branch = branch
            last_group = None
        gname = "%s (bước %d)" % (group["name"], step)
        if gname != last_group:
            lines.append("")
            lines.append("-- BƯỚC %d: %s --" % (step, group["name"]))
            last_group = gname
        n += 1
        lines.append("  %2d. %s %s" % (n, PLATFORM_BADGE[plat], item["name"]))
        lines.append("      %s" % item["desc"])
        if show_pipeline:
            for cmd in item["pipeline"]:
                lines.append("      $ %s" % cmd)
    lines.append("")
    lines.append("Chọn số (1-%d) để xem pipeline, 0 = thoát."
                 % n)
    return "\n".join(lines)


def render_detail(item: Dict[str, Any]) -> str:
    lines = []
    lines.append("------------------------------------------------------------")
    lines.append("  [%s] %s" % (item["id"], item["name"]))
    lines.append("  %s" % item["desc"])
    lines.append("")
    lines.append("  PIPELINE (chạy đúng thứ tự):")
    for cmd in item["pipeline"]:
        lines.append("    $ %s" % cmd)
    lines.append("")
    lines.append("  ĐẦU VÀO:")
    for inp in item.get("inputs", []) or ["(không cần)"]:
        lines.append("    - %s" % inp)
    lines.append("  ĐẦU RA:")
    for out in item.get("outputs", []) or ["(in ra màn hình)"]:
        lines.append("    - %s" % out)
    lines.append("------------------------------------------------------------")
    return "\n".join(lines)


def render_search(rows: List[Tuple[int, Dict[str, Any], Dict[str, Any]]]) -> str:
    lines = ["Kết quả tìm (xếp theo điểm khớp):", ""]
    for i, (score, group, item) in enumerate(rows, 1):
        lines.append("  %2d. %s [%s] %s  (điểm %d)" % (
            i, PLATFORM_BADGE[item_platform(item)], item["id"],
            item["name"], score))
        lines.append("      %s" % item["desc"])
    lines.append("")
    lines.append("Chạy: python3 patchx menu --run <ID> [--set KEY=VALUE ...]")
    return "\n".join(lines)


def _resolve_placeholders(cmd: str, values: Dict[str, str],
                          input_fn: Callable[[str], str],
                          interactive: bool) -> Tuple[str, Optional[str]]:
    """Thay {KEY} bằng giá trị có sẵn / người dùng nhập.

    Trả (lệnh đã thay, lỗi nếu thiếu giá trị ở chế độ không tương tác).
    """
    import re
    missing: List[str] = []

    def repl(m):
        key = m.group(1)
        if key in values:
            return values[key]
        if key == "PY":
            return DEFAULT_PY
        missing.append(key)
        if interactive:
            val = input_fn("  Nhập %s: " % key).strip()
            values[key] = val
            return val
        return "{" + key + "}"

    resolved = re.sub(r"\{([A-Za-z0-9_]+)\}", repl, cmd)
    if missing and not interactive:
        return resolved, "Thiếu giá trị: %s (dùng --set %s=...)" % (
            ", ".join(sorted(set(missing))), missing[0])
    return resolved, None


def run_pipeline(item: Dict[str, Any],
                 values: Optional[Dict[str, str]] = None,
                 input_fn: Callable[[str], str] = input,
                 confirm_fn: Optional[Callable[[str], bool]] = None,
                 interactive: bool = True) -> int:
    """Chạy lần lượt các lệnh trong pipeline; dừng khi lệnh lỗi."""
    values = dict(values or {})
    for cmd in item["pipeline"]:
        resolved, err = _resolve_placeholders(cmd, values, input_fn,
                                              interactive=interactive)
        if err:
            print("[menu] Lỗi: %s" % err)
            return 2
        print("[menu] $ %s" % resolved)
        if confirm_fn is not None and not confirm_fn(resolved):
            print("[menu] Bỏ qua lệnh (người dùng từ chối).")
            continue
        try:
            rc = subprocess.call(shlex.split(resolved))
        except OSError as exc:
            print("[menu] Không chạy được lệnh: %s (%s)" % (resolved, exc))
            return 2
        if rc != 0:
            print("[menu] Lệnh thất bại (rc=%d) — dừng pipeline %s"
                  % (rc, item["id"]))
            return rc
    print("[menu] Pipeline %s hoàn tất." % item["id"])
    return 0


def _parse_set(specs: List[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for spec in specs:
        if "=" not in spec:
            print("[menu] Bỏ qua --set thiếu '=': %r" % spec)
            continue
        key, _, val = spec.partition("=")
        values[key.strip()] = val
    return values


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="patchx menu",
        description="Danh sách chức năng để lựa chọn pipeline (menu).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ví dụ:\n"
               "  python3 patchx menu\n"
               "  python3 patchx menu --list\n"
               "  python3 patchx menu --goal \"patch chuỗi trong so\"\n"
               "  python3 patchx menu --run rodata-static --set SO=lib.so "
               "--set OLD=\"https://x\" --set NEW=\"https://y\"")
    parser.add_argument("--list", action="store_true",
                        help="In toàn bộ danh sách chức năng (có nhóm + số chọn)")
    parser.add_argument("--goal", default=None,
                        help="Tìm theo mục tiêu (tính điểm khớp từ khóa, xếp hạng)")
    parser.add_argument("--run", default=None,
                        help="Chạy pipeline theo ID (vd rodata-static)")
    parser.add_argument("--set", action="append", default=[],
                        help="Giá trị placeholder KEY=VALUE (lặp lại được)")
    parser.add_argument("--no-confirm", dest="no_confirm", action="store_true",
                        help="Chạy pipeline không hỏi xác nhận từng lệnh")
    args = parser.parse_args(argv)

    if args.list:
        print(render_catalog(show_pipeline=False))
        return 0
    if args.goal:
        rows = search_features(args.goal)
        if not rows:
            print("[menu] Không tìm thấy chức năng khớp %r — thử từ khóa khác "
                  "(vd: frida, patch, build, apk...)." % args.goal)
            return 1
        print(render_search(rows))
        return 0
    if args.run:
        item = find_item(args.run)
        if item is None:
            print("[menu] Không có ID %r. Xem danh sách: "
                  "python3 patchx menu --list" % args.run)
            return 2
        print(render_detail(item))
        print()
        values = _parse_set(args.set)
        if not args.no_confirm:
            try:
                ok = input("[menu] Chạy pipeline luôn? (y/N): ").strip().lower()
            except EOFError:
                ok = "n"
            if ok != "y":
                print("[menu] Đã hủy. Dùng --no-confirm để chạy ngay.")
                return 0
        return run_pipeline(item, values=values, interactive=False)

    # ---- menu tương tác ----
    print(render_catalog())
    items = all_items()
    index = _num(items)
    try:
        choice = input("Chọn số: ").strip()
    except EOFError:
        return 0
    if not choice.isdigit() or int(choice) not in index:
        print("[menu] Lựa chọn không hợp lệ — thoát.")
        return 2
    item = index[int(choice)]
    print()
    print(render_detail(item))
    try:
        ok = input("[menu] Chạy pipeline luôn? (y/N): ").strip().lower()
    except EOFError:
        ok = "n"
    if ok != "y":
        print("[menu] Đã hủy. Lệnh đầy đủ in ở trên — có thể copy chạy tay.")
        return 0
    return run_pipeline(item, values={})


if __name__ == "__main__":
    sys.exit(main())
