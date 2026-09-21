# -*- coding: utf-8 -*-
"""integrity_decoupler — Ma trận triệt tiêu toàn vẹn tự động (AIDM).

Hợp nhất 4 mũi nhọn bổ trợ cho các module hiện có, không viết lại trùng:
  1. Tầng Java: thay `getInstallerPackageName()` -> `"com.android.vending"` và
     ép hàm kiểm chữ ký trả về True (tái dùng `smali_ast.SmaliAstMutator`).
  2. Tầng tự đọc APK / DEX: vô hiệu lệnh thoát `System.exit`/`killProcess`
     và đảo nhánh kiểm tra (tái dùng `smali_ast` + `dex_emulator`).
  3. Tầng Native: đồng bộ SHA-256 chữ ký gốc vào toàn cây `.so`
     (tái dùng `signature_spoof.multi_layer_spoof_pipeline`).
  4. Tầng Play Integrity: sinh hook Frida giả lập phía client + stub smali.

Lưu ý trung thực: Play Integrity là xác thực phía máy chủ; lớp giả lập phía
client chỉ bỏ chặn ở ứng dụng, KHÔNG tạo được token hợp lệ từ Google.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Dấu hiệu kiểm chữ ký CẤP ỨNG DỤNG (PackageManager/signatures),
# không nhận diện tên phương thức mã hóa thư viện như verifySignature.
SECURITY_METHOD_HINTS = (
    "hassigningcertificate",
    "getinstallerpackagename",
    "getsignatures",
    "signatures[",
)

# Dấu hiệu tự đọc APK và mã băm classes.dex (tầng 2 của AIDM),
# không nhận diện mọi MessageDigest/SHA/MD5 thông thường.
DIGEST_HINTS = (
    "classes.dex",
    "getcrc",
    "getentry",
)

_MOVE_RESULT_RE = re.compile(r"^move-result-object\s+([vp]\d+)\s*$")


def detect_integrity_controls(method_text: str) -> List[str]:
    """Liệt kê các dấu hiệu kiểm soát toàn vẹn trong một khối .method.

    Dùng cho cả báo cáo và test âm: một phương thức sạch phải trả danh sách
    rỗng, chứng minh công cụ phát hiện được "không có vi phạm".
    """
    hits: List[str] = []
    low = method_text.lower()
    if "getinstallerpackagename(" in low:
        hits.append("installer-package")
    if any(hint in low for hint in SECURITY_METHOD_HINTS):
        hits.append("signing-certificate")
    if any(hint in low for hint in DIGEST_HINTS):
        hits.append("dex-digest")
    if "system;->exit(" in low or "process;->killprocess(" in low:
        hits.append("exit-call")
    return hits


def decouple_installer_package(method_text: str) -> Tuple[bool, str]:
    """Thay `getInstallerPackageName()` + `move-result-object` bằng hằng chuỗi.

    Trả về (đã_đổi, văn_bản_mới). Nếu không tìm thấy cặp invoke/move-result
    hợp lệ thì giữ nguyên (hỗ trợ test âm).
    """
    lines = method_text.split("\n")
    changed = False
    for i, line in enumerate(lines):
        if "getInstallerPackageName(" not in line:
            continue
        target_reg = None
        for j in range(i + 1, min(i + 5, len(lines))):
            nxt = lines[j].strip()
            if not nxt or nxt.startswith(("#", ":")):
                continue
            m = _MOVE_RESULT_RE.match(nxt)
            if m:
                target_reg = m.group(1)
                indent = lines[j][: len(lines[j]) - len(lines[j].lstrip())]
                lines[j] = '%sconst-string %s, "com.android.vending"' % (indent, target_reg)
            break
        if target_reg is None:
            continue
        lines[i] = None  # xóa dòng invoke gốc
        changed = True
    return changed, "\n".join(x for x in lines if x is not None)


def decouple_signing_certificate(method_text: str) -> Tuple[bool, str]:
    """Ép hàm kiểm chữ ký (trả về boolean) luôn trả True."""
    from .smali_ast import SmaliAstMutator, parse_method_ast

    low = method_text.lower()
    if not any(hint in low for hint in SECURITY_METHOD_HINTS):
        return False, method_text
    ast = parse_method_ast(method_text)
    if ast is None:
        return False, method_text
    name = (ast.name or "").lower()
    if not any(hint in name for hint in SECURITY_METHOD_HINTS):
        return False, method_text
    if ast.return_type != "Z":
        return False, method_text
    ok = SmaliAstMutator.force_return_boolean(ast, value=True)
    return ok, (ast.render() if ok else method_text)


def decouple_dex_digest_check(method_text: str) -> Tuple[bool, str]:
    """Ép hàm kiểm mã băm DEX (trả về boolean) luôn trả True."""
    from .smali_ast import SmaliAstMutator, parse_method_ast

    low = method_text.lower()
    if not any(hint in low for hint in DIGEST_HINTS):
        return False, method_text
    ast = parse_method_ast(method_text)
    if ast is None:
        return False, method_text
    if ast.return_type != "Z":
        return False, method_text
    ok = SmaliAstMutator.force_return_boolean(ast, value=True)
    return ok, (ast.render() if ok else method_text)


def verify_integrity_bypass(method_text: str) -> Dict[str, Any]:
    """Kiểm chứng toán học một phương thức đã can thiệp có trả True/1 hay không."""
    from .dex_emulator import verify_method_bypass

    return verify_method_bypass(method_text)


def inject_signature_hex(method_text: str, cert_hex: str) -> Tuple[bool, str]:
    """Ép hàm trả về String trả đúng chuỗi DER hex của chứng chỉ gốc."""
    from .smali_ast import AstNode, parse_method_ast

    ast = parse_method_ast(method_text)
    if ast is None or ast.return_type != "Ljava/lang/String;":
        return False, method_text
    ast.locals_count = max(ast.locals_count, 1)
    ast.nodes = [
        AstNode(
            kind="instruction",
            raw='    const-string v0, "%s"' % cert_hex,
            opcode="const-string",
            operands=["v0", '"%s"' % cert_hex],
        ),
        AstNode(kind="instruction", raw="    return-object v0", opcode="return-object", operands=["v0"]),
    ]
    return True, ast.render()


def neutralize_exit_calls(method_text: str) -> Tuple[bool, str]:
    """Biến lệnh thoát `System.exit`/`killProcess` thành `return-void`."""
    lines = method_text.split("\n")
    changed = False
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith((".", ":", "#")):
            continue
        if "System;->exit(" in s or "Process;->killProcess(" in s:
            indent = line[: len(line) - len(line.lstrip())]
            lines[i] = indent + "return-void"
            changed = True
    return changed, "\n".join(lines)


def invert_integrity_branch(method_text: str) -> Tuple[bool, str]:
    """Đảo nhánh rẽ điều kiện đầu tiên trong phương thức."""
    from .smali_ast import SmaliAstMutator, parse_method_ast

    ast = parse_method_ast(method_text)
    if ast is None:
        return False, method_text
    ok = SmaliAstMutator.invert_first_matching_branch(ast)
    return ok, (ast.render() if ok else method_text)


def generate_play_integrity_hook() -> str:
    """Sinh hook Frida giả lập Play Integrity phía client (best-effort)."""
    return """// == PatchX Play Integrity Client-Side Mock ==
// Chi bo chan o phia ung dung; KHONG tao duoc token hop le tu may chu Google.
Java.perform(function () {
    try {
        var IntegrityManager = Java.use(
            "com.google.android.play.core.integrity.IntegrityManager");
        IntegrityManager.requestIntegrityToken.overload(
            "com.google.android.play.core.integrity.IntegrityTokenRequest"
        ).implementation = function (req) {
            var resp = this.requestIntegrityToken(req);
            var TokenResponse = Java.use(
                "com.google.android.play.core.integrity.IntegrityTokenResponse");
            var Fake = Java.registerClass({
                name: "com.google.android.play.core.integrity.IntegrityTokenResponse",
                implements: [TokenResponse],
                methods: {
                    token: function () {
                        return "PATCHX_FAKE_INTEGRITY_TOKEN";
                    }
                }
            });
            console.log("[PatchX] Play Integrity client mock active");
            return Fake.$new();
        };
    } catch (err) {
        console.error("[PatchX] Play Integrity mock error: " + err);
    }
});
"""


def generate_play_integrity_smali_stub() -> str:
    """Trả về stub smali tối thiểu (mang tính chỗ dựng, không thể xác thực máy chủ)."""
    return """.class public Lcom/patchx/PlayIntegrityMock;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static token()Ljava/lang/String;
    .registers 1
    const-string v0, "PATCHX_FAKE_INTEGRITY_TOKEN"
    return-object v0
.end method
"""


def sync_native_signatures(
    orig_apk: str,
    new_apk: str,
    so_dir: str,
    frida_script_out: Optional[str] = None,
) -> Dict[str, Any]:
    """Đồng bộ SHA-256 chữ ký gốc vào toàn cây .so (tái dùng signature_spoof)."""
    from .signature_spoof import multi_layer_spoof_pipeline

    return multi_layer_spoof_pipeline(
        original_apk=orig_apk,
        so_dir=so_dir,
        new_cert_apk=new_apk,
        frida_script_out=frida_script_out,
    )


# Dấu hiệu native thường dùng cho chống gỡ lỗi / chống can thiệp.
NATIVE_INTEGRITY_MARKERS = (
    b"/proc/self/maps",
    b"/proc/self/status",
    b"TracerPid",
    b"ptrace",
    b"META-INF",
    b"frida",
    b"magisk",
)


def scan_native_signature_integrity(
    so_dir: str,
    orig_apk: Optional[str] = None,
) -> Dict[str, Any]:
    """Quét toàn bộ .so trong thư mục để tìm vân tay chữ ký gốc và dấu hiệu chống can thiệp.

    Đây là bước phát hiện (chỉ đọc), không sửa tệp. Nếu phát hiện .so hardcode
    vân tay chữ ký gốc (SHA-256/SHA-1/DER) thì mới cần đồng bộ lại ở bước vá.
    """
    import glob as _glob
    from .signature_spoof import signature_context

    result: Dict[str, Any] = {
        "so_dir": str(so_dir),
        "files_scanned": 0,
        "cert_sha256": None,
        "cert_sha1": None,
        "hardcoded_cert_fingerprint": [],
        "anti_tamper_markers": [],
        "warnings": [],
    }
    fingerprint_patterns: List[Tuple[str, bytes]] = []
    if orig_apk and os.path.isfile(orig_apk):
        try:
            ctx = signature_context(orig_apk)
            result["cert_sha256"] = ctx["sha256"]
            result["cert_sha1"] = ctx["sha1"]
            der_head = bytes.fromhex(ctx["cert_der_hex"][:64])
            fingerprint_patterns = [
                ("sha256_UPPER", ctx["sha256"].encode()),
                ("sha256_lower", ctx["sha256"].lower().encode()),
                ("sha1_UPPER", ctx["sha1"].encode()),
                ("sha1_lower", ctx["sha1"].lower().encode()),
                ("der_head_raw", der_head),
            ]
        except Exception as exc:  # noqa: BLE001
            result["warnings"].append("khong trich duoc chu ky goc: %s" % exc)

    for so in sorted(_glob.glob(os.path.join(str(so_dir), "**", "*.so"), recursive=True)):
        try:
            with open(so, "rb") as fh:
                data = fh.read()
        except OSError as exc:  # noqa: BLE001
            result["warnings"].append("khong doc duoc %s: %s" % (so, exc))
            continue
        result["files_scanned"] += 1
        hits: List[Dict[str, Any]] = []
        for name, pat in fingerprint_patterns:
            n = data.count(pat)
            if n:
                hits.append({"marker": name, "count": n})
        for marker in NATIVE_INTEGRITY_MARKERS:
            n = data.count(marker)
            if n:
                hits.append({"marker": marker.decode("latin-1"), "count": n})
        if not hits:
            continue
        entry = {"so": os.path.relpath(so, str(so_dir)), "hits": hits}
        if any(h["marker"].startswith(("sha", "der")) for h in hits):
            result["hardcoded_cert_fingerprint"].append(entry)
        else:
            result["anti_tamper_markers"].append(entry)

    result["summary"] = {
        "files_scanned": result["files_scanned"],
        "hardcoded_cert_fingerprint_files": len(result["hardcoded_cert_fingerprint"]),
        "anti_tamper_files": len(result["anti_tamper_markers"]),
    }
    return result


def _iter_method_blocks(text: str) -> List[Tuple[int, int, str]]:
    """Tách văn bản .smali thành các khối .method ... .end method."""
    lines = text.split("\n")
    blocks: List[Tuple[int, int, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].strip().startswith(".method"):
            start = i
            i += 1
            while i < n and lines[i].strip() != ".end method":
                i += 1
            if i < n:
                i += 1
            blocks.append((start, i, "\n".join(lines[start:i])))
        else:
            i += 1
    return blocks


def _apply_static_to_text(text: str, spearheads: Tuple[int, ...], stats: Dict[str, Any]) -> str:
    """Áp các mũi nhọn tĩnh (1, 2) lên mọi phương thức trong một tệp smali."""
    blocks = _iter_method_blocks(text)
    if not blocks:
        return text
    lines = text.split("\n")
    for start, end, block_text in blocks:
        new_block = block_text
        block_changed = False
        if 1 in spearheads:
            c, new_block = decouple_installer_package(new_block)
            if c:
                stats["installer_decoupled"] += 1
                block_changed = True
            c, new_block = decouple_signing_certificate(new_block)
            if c:
                stats["signing_forced"] += 1
                block_changed = True
        if 2 in spearheads:
            c, new_block = neutralize_exit_calls(new_block)
            if c:
                stats["exits_neutralized"] += 1
                block_changed = True
            c, new_block = decouple_dex_digest_check(new_block)
            if c:
                stats["dex_digest_forced"] += 1
                block_changed = True
        if block_changed:
            stats["methods_patched"] += 1
            stats.setdefault("patched_method_texts", []).append({
                "method": block_text.splitlines()[0].strip() if block_text else "",
                "file": stats.get("_current_file", "?"),
                "text": new_block[:4000],
            })
            lines[start:end] = new_block.split("\n")
    return "\n".join(lines)


def decouple_integrity(
    target: str,
    orig_apk: Optional[str] = None,
    new_apk: Optional[str] = None,
    so_dir: Optional[str] = None,
    out_dir: Optional[str] = None,
    spearheads: Tuple[int, ...] = (1, 2, 3, 4),
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Điều phối tổng thể AIDM: quét cây smali, đồng bộ native, sinh hook Play.

    Trả về báo cáo JSON có số liệu đo được (files/methods/branches/...).
    """
    out_dir = Path(out_dir or "outputs/integrity_decoupler")
    out_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "target": str(target),
        "spearheads": list(spearheads),
        "dry_run": dry_run,
        "files_scanned": 0,
        "files_patched": 0,
        "methods_patched": 0,
        "patched_method_texts": [],
        "installer_decoupled": 0,
        "signing_forced": 0,
        "dex_digest_forced": 0,
        "exits_neutralized": 0,
        "branches_inverted": 0,
        "native": None,
        "play_integrity": None,
        "warnings": [],
    }

    tgt = Path(target)
    smali_files: List[Path] = []
    if tgt.is_file() and tgt.suffix == ".smali":
        smali_files = [tgt]
    elif tgt.is_dir():
        smali_files = sorted(tgt.rglob("*.smali"))
    else:
        report["warnings"].append(
            "target khong phai cay/thu muc smali; bo qua buoc bien doi tinh (chi tao hook neu duoc yeu cau)"
        )

    for f in smali_files:
        report["files_scanned"] += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            report["warnings"].append("khong doc duoc %s: %s" % (f, exc))
            continue
        report["_current_file"] = str(f)
        new_text = _apply_static_to_text(text, tuple(spearheads), report)
        report.pop("_current_file", None)
        if new_text == text:
            continue
        report["files_patched"] += 1
        if not dry_run:
            backup = f.with_name(f.name + ".bak.patchx")
            if not backup.exists():
                try:
                    backup.write_bytes(f.read_bytes())
                except Exception as exc:  # noqa: BLE001
                    report["warnings"].append("khong tao duoc backup %s: %s" % (backup, exc))
            try:
                f.write_text(new_text, encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                report["warnings"].append("khong ghi duoc %s: %s" % (f, exc))

    if 3 in spearheads and so_dir and os.path.isdir(so_dir):
        report["native_scan"] = scan_native_signature_integrity(so_dir, orig_apk=orig_apk)
        if orig_apk and new_apk:
            frida_out = out_dir / "java_signature_hook.js"
            report["native"] = sync_native_signatures(
                orig_apk=orig_apk,
                new_apk=new_apk,
                so_dir=so_dir,
                frida_script_out=str(frida_out),
            )

    if 4 in spearheads:
        hook_path = out_dir / "play_integrity_hook.js"
        stub_path = out_dir / "PlayIntegrityMock.smali"
        if not dry_run:
            hook_path.write_text(generate_play_integrity_hook(), encoding="utf-8")
            stub_path.write_text(generate_play_integrity_smali_stub(), encoding="utf-8")
        report["play_integrity"] = {
            "hook": str(hook_path),
            "smali_stub": str(stub_path),
            "limit": "client-side only, khong thay the xac thuc may chu Google",
        }

    report_path = out_dir / "report.json"
    if not dry_run:
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report["report_path"] = str(report_path)
    return report
