#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patchx Toolkit — một cổng điều khiển chất lượng cao cho toàn bộ patchx.

Chức năng:
  doctor      kiểm tra môi trường và bộ patch đầu vào
  run         chạy toàn bộ quy trình thông minh cho toàn bộ patch
  package     đóng gói phân phối toolkit + bộ patch chuẩn hoá

Mọi thông báo bằng tiếng Việt; chuỗi mã nguồn / tên tệp giữ nguyên gốc.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

TOOLKIT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TOOLKIT_DIR)
PATCHX = os.path.join(TOOLKIT_DIR, "patchx")
DEFAULT_INPUT = os.path.join(TOOLKIT_DIR, "upgraded")
DEFAULT_OUT = os.path.join(TOOLKIT_DIR, "outputs", "pipeline")
DEFAULT_DEMO_APK = os.path.join(TOOLKIT_DIR, "demo-apk")
DEFAULT_APKS = os.path.join(TOOLKIT_DIR, "Apks")
APK_TREES_DIR = os.path.join(TOOLKIT_DIR, "outputs", "apk", "apk-trees")
APKS_PATCH_DIR = os.path.join(TOOLKIT_DIR, "outputs", "apk", "apk-patch")
MAX_KEPT_VERSIONS = 3

TOOL_PACKAGES = {
    "apktool": "apktool",
    "aapt2": "aapt",
    "zipalign": "prebuilt",  # không có gói trong kho Termux main — dùng prebuilt
    "apksigner": "apksigner",
    "adb": "android-tools",
    "java": "openjdk-17",
    "git": "git",
}

# Công cụ không có gói trong kho Termux: cài từ binary prebuilt (có kiểm tra sha256).
TOOL_PREBUILT = {
    "zipalign": {
        "url": ("https://raw.githubusercontent.com/rendiix/termux-zipalign/main/"
                "prebuilt-binary/arm64-v8a/zipalign"),
        "sha256": "1d8a5151e8c83f3990b149e4e6273be0f0526e5f002cf38ce41c49416a035e97",
        "note": "prebuilt zipalign arm64 (rendiix/termux-zipalign)",
    },
}


def _log(msg):
    print("[toolkit] " + msg)


def _run_patchx(args, cwd=TOOLKIT_DIR):
    """Chạy một lệnh patchx, trả (returncode, elapsed_seconds, output)."""
    _log("python3 patchx " + " ".join(args))
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, PATCHX] + args,
        cwd=cwd, text=True, capture_output=True)
    elapsed = time.monotonic() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    if output.strip():
        print(output.rstrip())
    return proc.returncode, elapsed, output


def _preflight_gate(patch_files, tree):
    """P8 — GATE 3 PREFLIGHT bắt buộc trước khi áp patch.

    Mỗi patch chạy `preflight`; verdict UNSAFE/INCOMPATIBLE → BLOCK (dừng),
    READY_WITH_WARNING → tiếp tục kèm cảnh báo.
    Trả True khi toàn bộ patch vượt cổng.
    """
    ok = True
    for pf in patch_files:
        code, _elapsed, output = _run_patchx(["preflight", pf, tree])
        verdict = "UNKNOWN"
        for line in (output or "").splitlines():
            if line.startswith("[preflight]"):
                verdict = line.split("→")[-1].strip()
        if code != 0 or verdict in ("UNSAFE", "INCOMPATIBLE"):
            _log("PREFLIGHT BLOCK: %s (%s)" % (pf, verdict))
            ok = False
        else:
            _log("PREFLIGHT OK: %s (%s)" % (pf, verdict))
    return ok


def _der_header(tag, length):
    """Header DER tối giản (chỉ dùng cho SEQUENCE) cho độ dài < 2^16."""
    if length < 0x80:
        return bytes([tag, length])
    nbytes = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | nbytes]) + length.to_bytes(nbytes, "big")


def _pkcs7_first_cert_hex(p7):
    """Trích cert X.509 đầu tiên (DER hex) từ PKCS#7 SignedData của JAR
    signature (META-INF/*.RSA). Trả chuỗi hex hoặc None."""
    def tlv(data, off):
        start = off
        tag = data[off]
        off += 1
        if (tag & 0x1F) == 0x1F:
            while data[off] & 0x80:
                off += 1
            off += 1
        first = data[off]
        off += 1
        if first & 0x80:
            n = first & 0x7F
            ln = int.from_bytes(data[off:off + n], "big")
            off += n
        else:
            ln = first
        return tag, off - start, ln

    def children(content):
        out, pos = [], 0
        while pos < len(content):
            tag, hl, ln = tlv(content, pos)
            out.append((tag, content[pos + hl:pos + hl + ln]))
            pos += hl + ln
        return out

    def find_child(content, tag):
        for t, c in children(content):
            if t == tag:
                return c
        return None

    try:
        tag, hl, ln = tlv(p7, 0)
        if tag != 0x30:
            return None
        signed = find_child(p7[hl:hl + ln], 0xA0)     # SignedData SEQUENCE
        st, sh, sl = tlv(signed, 0)
        if st != 0x30:
            return None
        certs_node = find_child(signed[sh:sh + sl], 0xA0)  # certificates [0]
        if certs_node is None:
            return None
        certs = [c for t, c in children(certs_node) if t == 0x30]
        if not certs:
            return None
        best = max(certs, key=len)
        ct, _, _ = tlv(best, 0)
        if ct != 0x30:
            return None
        return (_der_header(0x30, len(best)) + best).hex().upper()
    except Exception:
        return None


def _extract_apk_cert_hex(apk_path):
    """Cert DER hex của chữ ký v1 (JAR) từ APK gốc — giá trị cho %RSA_DATA%
    của patch hack signature. Trả chuỗi hex hoặc None."""
    import zipfile
    try:
        zf = zipfile.ZipFile(apk_path)
    except Exception:
        return None
    try:
        sig = None
        for n in zf.namelist():
            if n.startswith("META-INF/") and n.rsplit(".", 1)[-1].upper() \
                    in ("RSA", "DSA", "EC"):
                sig = n
                break
        if not sig:
            return None
        return _pkcs7_first_cert_hex(zf.read(sig))
    except Exception:
        return None
    finally:
        zf.close()


def _count_zips(path):
    if not os.path.isdir(path):
        return 0
    return sum(1 for n in os.listdir(path)
               if n.lower().endswith(".zip"))


def _list_apks(path=DEFAULT_APKS):
    """Danh sách tệp .apk trong thư mục đầu vào."""
    if not os.path.isdir(path):
        return []
    return sorted(n for n in os.listdir(path) if n.lower().endswith(".apk"))


def _list_apks_bundles(path=DEFAULT_APKS):
    """Danh sách tệp .apks (split bundle) trong thư mục đầu vào."""
    if not os.path.isdir(path):
        return []
    return sorted(n for n in os.listdir(path) if n.lower().endswith(".apks"))


def _is_termux():
    return bool(os.environ.get("PREFIX")) and os.path.isdir(
        os.environ["PREFIX"])


def _verify_sha256(path, expected):
    """Trả True nếu sha256 của tệp khớp `expected` (chuỗi hex thường)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().lower() == expected.lower()


def _install_prebuilt(tool):
    """Cài công cụ prebuilt (zipalign) vào $PREFIX/bin, có kiểm tra sha256."""
    meta = TOOL_PREBUILT.get(tool)
    if not meta:
        return False
    prefix = os.environ.get("PREFIX")
    if not prefix:
        return False
    dest = os.path.join(prefix, "bin", tool)
    tmp = dest + ".tmp"
    _log("Công cụ %s thiếu — tải prebuilt (%s)..." % (tool, meta["note"]))
    try:
        with urllib.request.urlopen(meta["url"], timeout=120) as resp:
            with open(tmp, "wb") as f:
                shutil.copyfileobj(resp, f)
        if not _verify_sha256(tmp, meta["sha256"]):
            _log("sha256 của %s không khớp — huỷ cài (cảnh giác tệp giả mạo)."
                 % tool)
            os.remove(tmp)
            return False
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except Exception as e:
        _log("Tải %s lỗi: %s" % (tool, e))
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False
    return shutil.which(tool) is not None


def _ensure_tools(tools, auto_install=True, optional=()):
    """Đảm bảo công cụ có mặt; nếu thiếu và auto_install thì tự cài.
    `optional`: công cụ không bắt buộc — cài không được chỉ cảnh báo."""
    missing = [t for t in tools if not shutil.which(t)]
    if not missing:
        return True
    _log("Thiếu công cụ: %s" % ", ".join(missing))
    if not auto_install:
        _log("Tự cài bị tắt — chạy `patchx_toolkit.py install-deps` để cài.")
        return all(t in optional for t in missing)
    if not _is_termux():
        _log("Môi trường không phải Termux, không tự cài được.")
        _log("Cài thủ công: %s" % ", ".join(missing))
        return all(t in optional for t in missing)
    for tool in missing:
        pkg = TOOL_PACKAGES.get(tool)
        if pkg == "prebuilt":
            if _install_prebuilt(tool):
                _log("Đã cài xong %s (prebuilt)" % tool)
            elif tool in optional:
                _log("Cài %s (prebuilt) không được — bỏ qua (tùy chọn)." % tool)
            else:
                _log("Cài %s (prebuilt) thất bại." % tool)
                return False
            continue
        if not pkg:
            if tool in optional:
                _log("Không có gói cài cho %s — bỏ qua (tùy chọn)." % tool)
                continue
            _log("Chưa biết gói cài cho %s" % tool)
            return False
        _log("Công cụ %s thiếu — tự cài gói %s..." % (tool, pkg))
        try:
            proc = subprocess.run(["pkg", "install", "-y", pkg],
                                  text=True, capture_output=True, timeout=600)
        except Exception as e:
            _log("Cài %s lỗi: %s" % (pkg, e))
            if tool in optional:
                continue
            return False
        if proc.returncode != 0 or not shutil.which(tool):
            _log("Cài %s thất bại (mã %d): %s"
                 % (pkg, proc.returncode,
                    (proc.stderr or "").strip()[-300:]))
            if tool in optional:
                continue
            return False
        _log("Đã cài xong %s" % tool)
    still = [t for t in missing if not shutil.which(t)]
    if still:
        _log("Còn thiếu (không cài được): %s" % ", ".join(still))
        return all(t in optional for t in still)
    return True


def _find_input_apk(args):
    """APK gốc từ args.tree (tệp .apk) hoặc mặc định Apks/; None nếu là
    cây đã giải mã sẵn hoặc không tìm thấy."""
    raw = args.tree
    if raw and os.path.isdir(raw):
        return None
    apk = None
    if raw:
        apk = os.path.abspath(raw)
        if not os.path.isfile(apk):
            _log("Không tồn tại: %s" % apk)
            return None
    else:
        apks = _list_apks()
        if not apks:
            _log("Không tìm thấy tệp .apk trong %s" % DEFAULT_APKS)
            return None
        apk = os.path.join(DEFAULT_APKS, apks[0])
        _log("Tự chọn APK đầu vào: %s" % apk)
    return apk


def _resolve_apk_tree(args):
    """Trả cây APK đã giải mã từ tree/.apk hoặc mặc định Apks/; None nếu lỗi."""
    apk = _find_input_apk(args)
    if apk is None and not (args.tree and os.path.isdir(args.tree)):
        return None
    if apk is None:
        return os.path.abspath(args.tree)
    base = os.path.splitext(os.path.basename(apk))[0]
    tree = os.path.join(APK_TREES_DIR, base)
    if os.path.isdir(tree):
        # Cache decode: chỉ dùng lại cây khi hash APK khớp (decode.json).
        import hashlib as _hl
        dj = os.path.join(tree, ".patchx", "cache", "decode.json")
        cached = None
        try:
            with open(dj, encoding="utf-8") as fh:
                cached = json.load(fh)
        except Exception:
            cached = None
        if cached and cached.get("apk_sha256"):
            sha = _hl.sha256()
            try:
                with open(apk, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        sha.update(chunk)
            except OSError:
                sha = None
            if sha and sha.hexdigest() == cached.get("apk_sha256"):
                _log("Cache decode HIT — cây %s khớp APK %s" % (tree, apk))
                return tree
            if sha:
                _log("APK đổi (hash lệch) — giải mã lại %s" % apk)
        else:
            _log("Cây có sẵn nhưng thiếu cache decode.json — dùng luôn: %s"
                 % tree)
            return tree
    os.makedirs(APK_TREES_DIR, exist_ok=True)
    auto = not getattr(args, "no_auto_install", False)
    if not _ensure_tools(["apktool", "java", "aapt2"], auto):
        return None
    code, _, _ = _run_patchx(["apk-prepare", apk, "-o", tree])
    if code != 0:
        _log("Giải mã thất bại: %s" % apk)
        return None
    return tree


def cmd_doctor(args):
    """Kiểm tra môi trường và bộ patch đầu vào."""
    ok = True
    _log("Kiểm tra Python: %s" % sys.version.split()[0])
    if not os.path.isfile(PATCHX):
        _log("THIẾU patchx tại %s" % PATCHX)
        ok = False
    else:
        _log("patchx: OK (%s)" % PATCHX)
    inp = os.path.abspath(args.input)
    if not os.path.isdir(inp):
        _log("KHÔNG TÌM THẤY thư mục patch đầu vào: %s" % inp)
        ok = False
    else:
        n = _count_zips(inp)
        _log("Thư mục patch đầu vào: %s (%d zip)" % (inp, n))
        if n == 0:
            ok = False
    if os.path.isdir(DEFAULT_DEMO_APK):
        _log("Demo APK: OK (%s)" % DEFAULT_DEMO_APK)
    else:
        _log("Không có demo-apk (bỏ qua roadmap/coverage nếu cần APK).")
    apks = _list_apks()
    if apks:
        _log("Thư mục APK đầu vào: %s (%d apk)" % (DEFAULT_APKS, len(apks)))
        for a in apks[:5]:
            _log("  - %s" % a)
        if len(apks) > 5:
            _log("  ... và %d tệp nữa" % (len(apks) - 5))
    else:
        _log("Không tìm thấy tệp .apk trong %s" % DEFAULT_APKS)
    bundles = _list_apks_bundles()
    if bundles:
        _log("APK split bundle (.apks): %d tệp" % len(bundles))
        for b in bundles[:5]:
            _log("  - %s" % b)
        if len(bundles) > 5:
            _log("  ... và %d tệp nữa" % (len(bundles) - 5))
    os.makedirs(APKS_PATCH_DIR, exist_ok=True)
    patched = _list_apks(APKS_PATCH_DIR)
    if patched:
        _log("APK đã patch (%s): %d apk" % (APKS_PATCH_DIR, len(patched)))
        for a in patched[:5]:
            _log("  - %s" % a)
        if len(patched) > 5:
            _log("  ... và %d tệp nữa" % (len(patched) - 5))
    else:
        _log("APK đã patch (%s): trống — lệnh `apk-patch` sẽ lưu kết quả tại đây"
             % APKS_PATCH_DIR)
    missing = [t for t in TOOL_PACKAGES if not shutil.which(t)]
    if missing:
        hints = []
        for t in missing:
            pkg = TOOL_PACKAGES.get(t)
            if pkg == "prebuilt":
                hints.append("%s (prebuilt — chạy install-deps)" % t)
            elif pkg is None:
                hints.append("%s (không có gói trong kho)" % t)
            else:
                hints.append(t)
        _log("Công cụ thiếu: %s — chạy `install-deps` để tự cài"
             % ", ".join(hints))
    else:
        _log("Công cụ ngoài: đủ (%s)" % ", ".join(sorted(TOOL_PACKAGES)))
    # Không dùng `tool version` chung cho mọi binary: Java/JADX/apksigner có
    # cú pháp khác nhau. Capability probe chuẩn hóa lệnh và chỉ đọc môi trường.
    try:
        from patchx_core.intake import collect_tool_capabilities
        capabilities = collect_tool_capabilities()
        _log("Phiên bản công cụ (capability probe):")
        for row in capabilities["tools"]:
            state = row.get("version") if row.get("available") else "THIẾU"
            _log("  - %s: %s" % (row["name"], state))
    except Exception as exc:
        _log("Không lấy được capability probe: %s" % exc)
    try:
        tu_sinh_dir = os.path.join(TOOLKIT_DIR, "outputs", "tu-sinh")
        os.makedirs(tu_sinh_dir, exist_ok=True)
        _log("Thư mục tệp tự sinh (tu-sinh): OK (%s)" % tu_sinh_dir)
    except Exception as exc:
        _log("Cảnh báo thư mục tệp tự sinh: %s" % exc)
    try:
        from patchx_core.rules import verify_rule_integrity
        r_status = verify_rule_integrity(TOOLKIT_DIR)
        if r_status["ok"]:
            _log("Quy tắc cốt lõi Toolkit: ĐỦ (%d/%d mục, lấy Toolkit làm gốc)" % (r_status["present"], r_status["total"]))
        else:
            _log("CẢNH BÁO: Thiếu quy tắc cốt lõi: %s" % ", ".join(r_status["missing"]))
            ok = False
    except Exception as exc:
        _log("Không kiểm tra được quy tắc cốt lõi: %s" % exc)
    return 0 if ok else 1


def cmd_install_deps(args):
    """Cài các công cụ còn thiếu (Termux: pkg install)."""
    missing = [t for t in TOOL_PACKAGES if not shutil.which(t)]
    if not missing:
        _log("Tất cả công cụ đã có sẵn.")
        return 0
    _log("Công cụ thiếu: %s" % ", ".join(missing))
    ok = _ensure_tools(missing, auto_install=True, optional=("zipalign",))
    return 0 if ok else 1


def _pipeline_steps(inp, out, include_tests=False, include_sim=False):
    """Trả danh sách (tên, args) cho quy trình toàn bộ patch tinh gọn chuẩn hóa."""
    steps = [
        ("selfcheck đầu vào", ["selfcheck", inp]),
        ("quét tóm tắt", ["scan", inp, "-o",
                          os.path.join(out, "scan.json")]),
        ("phát hiện trùng lặp", ["dupes", inp, "-o",
                                 os.path.join(out, "dupes")]),
        ("tạo manifest", ["manifest", inp, "-o",
                          os.path.join(out, "MANIFEST.json")]),
        ("kiểm tra kiến trúc", ["audit", inp, "-o",
                                os.path.join(out, "audit")]),
        ("nâng cấp chuẩn hoá", ["upgrade", inp, "-o",
                                os.path.join(out, "upgraded")]),
        ("tự kiểm tra bản nâng cấp", ["selfcheck",
                                      os.path.join(out, "upgraded")]),
        ("gộp tối ưu", ["optimize", os.path.join(out, "upgraded"),
                        "-o", os.path.join(out, "optimized")]),
        ("gộp combo tự phát hiện", ["combo", os.path.join(out, "upgraded"),
                                    "--auto", "-o",
                                    os.path.join(out, "combos")]),
        ("báo cáo HTML", ["report", os.path.join(out, "upgraded"),
                          "-o", os.path.join(out, "report.html")]),
    ]
    if include_tests:
        steps.insert(1, ("kiểm thử tự động (yêu cầu rõ ràng từ User)", ["test"]))
    if include_sim:
        steps.insert(-1, ("mô phỏng toàn diện (yêu cầu rõ ràng từ User)", ["simulate", os.path.join(out, "upgraded"), "-o", out]))
    return steps


def _write_summary(inp, out, results, started):
    total = len(results)
    ok = sum(1 for r in results if r["returncode"] == 0)
    failed = [r for r in results if r["returncode"] != 0]
    summary = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "input": os.path.abspath(inp),
        "output": os.path.abspath(out),
        "total_steps": total,
        "ok_steps": ok,
        "failed_steps": len(failed),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "steps": results,
        "failed": [r["name"] for r in failed],
    }
    jpath = os.path.join(out, "toolkit_report.json")
    with open(jpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    lines = [
        "# Patchx Toolkit Report", "",
        "- Thời gian: %s" % summary["generated"],
        "- Đầu vào: `%s`" % summary["input"],
        "- Đầu ra: `%s`" % summary["output"],
        "- Bước hoàn thành: %d/%d" % (ok, total),
        "- Tổng thời gian: %.1f s" % summary["elapsed_seconds"], "",
        "| Bước | Mã thoát | Thời gian (s) |",
        "|------|---------:|--------------:|",
    ]
    for r in results:
        lines.append("| %s | %d | %.1f |" % (
            r["name"], r["returncode"], r["elapsed"]))
    if failed:
        lines.append("")
        lines.append("## Bước lỗi")
        for r in failed:
            lines.append("- %s (mã %d)" % (r["name"], r["returncode"]))
    mpath = os.path.join(out, "toolkit_report.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    _log("Đã ghi %s" % jpath)
    _log("Đã ghi %s" % mpath)
    return 0 if ok == total else 1


def cmd_run(args):
    inp = getattr(args, "artifact", None) or args.input
    inp = os.path.abspath(inp)
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)

    # Nếu inp là file Android artifact (.apk, .apks, .aab): Chuyển sang Unified Pipeline hiện đại!
    ext = os.path.splitext(inp)[1].lower()
    if ext in (".apk", ".apks", ".aab") or (os.path.isfile(inp) and zipfile.is_zipfile(inp) and not inp.endswith(".zip")):
        _log("Phát hiện Android artifact (%s) -> Kích hoạt Unified Pipeline hiện đại." % os.path.basename(inp))
        from patchx_core.pipeline_unified import UnifiedPipeline
        pipeline = UnifiedPipeline(inp, output_dir=out)
        res = pipeline.run(mode="auto")
        _log("Hoàn thành: %s (%s s)" % (res.get("verdict"), res.get("elapsed_seconds")))
        return 0 if res.get("verdict") == "SUCCESS" else 1

    _log("Bắt đầu quy trình toàn bộ patch tinh gọn.")
    _log("Đầu vào: %s" % inp)
    _log("Đầu ra: %s" % out)
    started = time.monotonic()
    with_tests = bool(getattr(args, "with_tests", False))
    with_sim = bool(getattr(args, "simulate", False)) or (not getattr(args, "quick", False) and getattr(args, "simulate_all", False))
    steps = _pipeline_steps(inp, out, include_tests=with_tests, include_sim=with_sim)
    results = []
    for idx, (name, argv) in enumerate(steps, 1):
        print("\n=== [%d/%d] %s ===" % (idx, len(steps), name))
        code, elapsed, _ = _run_patchx(argv)
        results.append({"name": name, "returncode": code,
                        "elapsed": round(elapsed, 3)})
        if code != 0 and not args.keep_going:
            _log("Dừng do bước lỗi: %s" % name)
            return _write_summary(inp, out, results, started)
    return _write_summary(inp, out, results, started)


def _zip_tree(zf, root, base, prefix=""):
    """Nén cây thư mục/tệp vào zip; bỏ qua thư mục nội bộ nặng."""
    skip_dirs = {"__pycache__", "backup", "toolkit_out", "outputs",
                 "dist", "combos", "combos_auto", "optimized"}
    if os.path.isfile(root):
        arc = prefix + os.path.basename(root)
        zf.write(root, arc)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in skip_dirs and not d.startswith(".")]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, base)
            zf.write(full, os.path.join(prefix, rel))


def cmd_package(args):
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    build = _next_build_number(out_dir)
    name = "patchx-toolkit-%d-%s.zip" % (build, stamp)
    path = os.path.join(out_dir, name)
    included = [
        "patchx",
        "pushx",
        "patchx_toolkit.py",
        "rodata_bypass_main.py",
        "patchx_core",
        "toolkit.md",
        "apk.md",
        "quy_tac_khoi",
        "QUY_TAC_NGUOI_DUNG.md",
        "GEMINI.md",
        "CLAUDE.md",
        "AGENTS.md",
        "KINH_NGHIEM_HOC_HOI.md",
        "tests",
        "README.md",
        "AGENTS_TRANG_THAI.md",
        "tools",
        "OPERATIONS",
        "HUONG_DAN_LENH.txt",
        "HUONG_DAN_BEHAVIOR_FRIDA.txt",
        "HUONG_DAN_GADGET.txt",
        "NGU_CANH.md",
        "UPGRADE_PLAN_V3.md",
        "EVALUATION.md",
        "upgraded",
        "hook_remote_data_control",
        "webui",
    ]
    if os.path.isdir(DEFAULT_DEMO_APK):
        included.append("demo-apk")
    try:
        from patchx_core.rules import verify_rule_integrity
        r_status = verify_rule_integrity(TOOLKIT_DIR)
        if not r_status["ok"]:
            _log("CẢNH BÁO ĐÓNG GÓI: Thiếu quy tắc cốt lõi: %s" % ", ".join(r_status["missing"]))
        else:
            _log("Bảo toàn quy tắc: ĐỦ (%d/%d quy tắc cốt lõi xuất kèm Toolkit)" % (r_status["present"], r_status["total"]))
    except Exception:
        pass
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in included:
            full = os.path.join(TOOLKIT_DIR, item)
            if os.path.exists(full):
                _zip_tree(zf, full, TOOLKIT_DIR)
            else:
                _log("Bỏ qua (không tồn tại): %s" % item)
    size = os.path.getsize(path)
    _log("Đã tạo %s (%.2f MB)" % (path, size / 1048576.0))
    _prune_old_packages(out_dir, args.keep)
    return 0


def _next_build_number(out_dir):
    """Số thứ tự bản đóng gói = bản lớn nhất hiện có + 1."""
    nums = []
    for z in glob.glob(os.path.join(out_dir, "patchx-toolkit-*.zip")):
        m = re.match(r"patchx-toolkit-(\d+)-\d{8}-\d{6}\.zip$",
                     os.path.basename(z))
        if m:
            nums.append(int(m.group(1)))
    return (max(nums) + 1) if nums else 1


def _prune_old_packages(out_dir, keep):
    """Xóa bản đóng gói cũ, chỉ giữ `keep` bản mới nhất."""
    zips = sorted(glob.glob(os.path.join(out_dir, "patchx-toolkit-*.zip")),
                  key=os.path.getmtime, reverse=True)
    for old in zips[keep:]:
        try:
            os.remove(old)
            _log("Xóa bản cũ: %s" % os.path.basename(old))
        except OSError as e:
            _log("Không xóa được %s: %s" % (os.path.basename(old), e))


def _cap_label(cap):
    from patchx_core.optimizer import CAP_LABELS
    return CAP_LABELS.get(cap, cap.replace("-", " ").title())


def _print_catalog(patches):
    from patchx_core import session
    groups = session.capability_groups(patches)
    index = []
    print("\nDanh sách patch theo khả năng:")
    for cap, names in groups:
        print("  [%s]" % _cap_label(cap))
        for name in names:
            print("    %3d. %s" % (len(index) + 1, name))
            index.append(name)
    return index


def cmd_list(args):
    from patchx_core import session
    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch nào trong %s" % args.input)
        return 1
    groups = session.capability_groups(patches)
    combos = session.complementary_combos(patches, max_combos=args.limit)
    if args.json:
        data = {
            "total": len(patches),
            "groups": [{"capability": cap, "patches": names}
                       for cap, names in groups],
            "combos": combos,
        }
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        _log("Đã ghi danh sách JSON: %s" % args.json)
    _log("Tổng số patch: %d" % len(patches))
    _print_catalog(patches)
    print("\nCombo bổ trợ (năng lực hỗ trợ nhau):")
    if not combos:
        print("  Không tìm thấy combo bổ trợ.")
    for c in combos:
        print("  %s + %s" % (c["patches"][0], c["patches"][1]))
        print("    năng lực: %s" % ", ".join(c["capabilities"]))
        print("    hỗ trợ: %s" % ", ".join("%s<->%s" % pair
                                           for pair in c["support"]))
    return 0


def cmd_session(args):
    from patchx_core import session
    from patchx_core.engine import Engine
    from patchx_core.optimizer import find_conflicts, patch_capabilities

    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch nào trong %s" % args.input)
        return 1

    if args.select_file:
        with open(args.select_file, encoding="utf-8") as fh:
            raw = fh.read()
    elif args.interactive:
        index = _print_catalog(patches)
        raw = input("\nNhập số thứ tự hoặc tên patch (cách nhau dấu phẩy): ")
        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        resolved = []
        for t in tokens:
            if t.isdigit() and 1 <= int(t) <= len(index):
                resolved.append(index[int(t) - 1])
            else:
                resolved.append(t)
        raw = ",".join(resolved)
    elif args.select:
        raw = args.select
    else:
        _log("Cần --select, --select-file hoặc --interactive.")
        return 2

    selected, missing = session.resolve_patch_names(patches, raw)
    if missing:
        _log("Không tìm thấy patch: %s" % ", ".join(missing))
        return 1
    if not selected:
        _log("Chưa chọn patch nào.")
        return 1

    names = [p.name for p in selected]
    _log("Đã chọn %d patch: %s" % (len(names), ", ".join(names)))
    conflicts = find_conflicts(selected)
    if conflicts:
        _log("Cảnh báo xung đột tiềm năng:")
        for c in conflicts:
            print("  - target=%s, patches=%s" % (
                c.get("target"), ", ".join(c.get("patches", []))))

    if args.output:
        os.makedirs(args.output, exist_ok=True)
        manifest = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "input": os.path.abspath(args.input),
            "tree": os.path.abspath(args.tree) if args.tree else None,
            "patches": names,
            "conflicts": conflicts,
            "capabilities": {n: sorted(patch_capabilities(p))
                             for n, p in zip(names, selected)},
        }
        mpath = os.path.join(args.output, "session_manifest.json")
        with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
        _log("Đã ghi kế hoạch phiên: %s" % mpath)

    if args.tree:
        eng = Engine(args.tree, dry_run=args.dry_run,
                     backup=not args.no_backup, force=args.force,
                     quiet=args.quiet)
        eng.apply_many(selected)
        _log("Kết quả áp: %d thay đổi, %d cảnh báo, %d lỗi" % (
            len(eng.changes), len(eng.warnings), len(eng.errors)))
        if eng.errors:
            for e in eng.errors:
                print("  LỖI: " + e)
        if eng.warnings:
            for w in eng.warnings:
                print("  CẢNH BÁO: " + w)
    return 0


def _apk_error_exercises(apply_output, build_output, apply_code, build_code):
    """Biến lỗi phát sinh thành bài tập cải thiện."""
    combined = (apply_output or "") + "\n" + (build_output or "")
    exercises = []

    def add(title, cause, fix):
        exercises.append({"title": title, "root_cause": cause,
                          "suggested_fix": fix})

    if "Syntax error: \"(\" unexpected" in combined \
            or "aapt2_" in combined:
        add("Wrapper aapt2 trên Termux bị lỗi shell",
            "apktool 3.0.3 sinh wrapper aapt2 không tương thích shell hiện tại.",
            "Dùng `apktool b --aapt <aapt2-thật>`, hoặc trỏ APKTOOL_AAPT2 tới "
            "aapt2 thật, hoặc sửa wrapper để không dùng cú pháp shell POSIX "
            "bị lỗi.")
    if "Unrecognized option: --use-aapt1" in combined:
        add("apktool 3.x không còn cờ --use-aapt1",
            "Phiên bản apktool hiện tại chỉ hỗ trợ `--aapt <file>`, không có "
            "cờ chuyển aapt1 như các bản cũ.",
            "Dùng `apktool b --aapt /path/to/aapt2` hoặc cài apktool 2.x nếu "
            "thật sự cần aapt1; đồng thời bỏ tuỳ chọn `--use-aapt1` khỏi "
            "toolkit khi chạy apktool 3.x.")
    if "Unresolvable resource" in combined or "No resource found" in combined:
        add("Xung đột tài nguyên khi rebuild",
            "Patch sửa AndroidManifest/res nhưng tham chiếu resource chưa được "
            "cấp hoặc đã xoá không nhất quán.",
            "Đối chiếu public.xml; nếu xoá resource phải xoá cả khai báo và "
            "mọi tham chiếu; chạy audit trước khi build.")
    if "has invalid entry name" in combined:
        add("Tên resource chứa ký tự `$` làm aapt2 từ chối",
            "Cây APK giải mã cũ có tên resource bắt đầu bằng `$` "
            "($avd_..., $feedback_...); aapt2 không chấp nhận tên này.",
            "Chuẩn hoá tên file trong res/ bằng cách loại bỏ ký tự `$`, cập "
            "nhật tham chiếu trong public.xml/values nếu cần; nếu vẫn lỗi thì "
            "dùng apktool 2.x/aapt1 cho cây APK cũ.")
    if "is incompatible with attribute" in combined:
        add("Giá trị thuộc tính manifest mới hơn framework aapt2",
            "Attribute/flag khai báo theo SDK mới (vd foregroundServiceType "
            "0x800 = shortService API 35) không nằm trong framework "
            "1.apk của aapt2 Termux → aapt2 link từ chối.",
            "Toolkit tự bỏ attribute đó khỏi AndroidManifest.xml (có sao "
            "lưu); nếu cần giữ đúng flag, cập nhật framework apktool hoặc "
            "ghi giá trị dưới dạng flag đã biết.")
    if "Could not smali" in combined or "smali file" in combined:
        add("Smali do patch sinh ra không hợp lệ",
            "Chèn thiếu register, invoke sai kiểu, hoặc method không tồn tại.",
            "Dùng smali_lib.alloc_temps và find_method_block trước khi chèn; "
            "bổ sung kiểm tra type và test rebuild tự động.")
    if "verification error" in combined.lower() \
            or "register" in combined.lower():
        add("Nghi vấn sai số thanh ghi smali",
            "Patch tăng/giảm .registers/.locals chưa khớp tham số method.",
            "Chuẩn hoá bump register qua smali_lib.smali_alloc_temps; thêm "
            "golden test cho method instance/static.")
    if apply_code == 0 and "đã áp 0 thay đổi" in apply_output \
            and build_code == 0:
        add("Patch không thay đổi gì trên APK thật",
            "MATCH/TARGET không khớp class/method của APK đích.",
            "Chạy `coverage`/`roadmap` trước, lấy class-link thật từ "
            "manifest/smali rồi cập nhật TARGET/MATCH.")
    if build_code == 0:
        add("Rebuild thành công — cần kiểm tra động tiếp",
            "APK đã build lại nhưng chưa chứng minh hành vi mod đúng.",
            "Ký APK, cài lên emulator/device, chạy logcat/mạng để đạt M2/M3.")
    elif build_code not in (0, 127) and not exercises:
        add("Rebuild thất bại nhưng chưa có mẫu nhận diện",
            "Lỗi build chưa nằm trong bộ quy tắc hiện tại.",
            "Ghi lại nguyên văn stdout/stderr, thêm quy tắc mới vào "
            "`_apk_error_exercises` và bổ sung test tương ứng.")
    return exercises


PATCHED_AAPT2_CANDIDATES = (
    os.path.join(os.path.expanduser("~"), ".local", "share", "patchx",
                 "tools", "aapt2_patched", "aapt2.sh"),
    os.path.join(os.path.expanduser("~"), ".tmp_aapt2", "aapt2_qemu.sh"),
)


def _find_patched_aapt2():
    """Tìm aapt2 đã vá attr-private (build framework-res / package 0x01).

    aapt2 chính thức (kho Termux, 2.20) crash `PrivateAttributeMover` khi
    build framework-res; bản patched lấy từ apktool 2.9.x chạy qua qemu."""
    for cand in PATCHED_AAPT2_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


MANIFEST_ATTR_RE = re.compile(
    r"error: attribute (android:[A-Za-z0-9_.]+) not found")
MANIFEST_FLAG_RE = re.compile(
    r"error: '0x[0-9A-Fa-f]+' is incompatible with attribute "
    r"([A-Za-z0-9_.]+) \(attr\) flags")
RES_ATTR_RE = re.compile(
    r"([A-Za-z0-9_./\\-]+\.xml):\d+: error: '[^']*' is incompatible with "
    r"attribute ([A-Za-z0-9_.]+) \(attr\) (?:enum|flags)")


def _remove_xml_attrs(path, attrs, backup_name):
    """Bỏ các attribute khỏi một tệp XML (có sao lưu). Trả danh sách đã bỏ."""
    if not os.path.isfile(path):
        return []
    text = open(path, encoding="utf-8").read()
    fixed = []
    for a in sorted(set(attrs)):
        new = re.sub(r"\s+(?:[A-Za-z][A-Za-z0-9_.\-]*:)?%s"
                     r"(?:=\"[^\"]*\"|=\'[^\']*\'|=[^\s/>]+)"
                     % re.escape(a), "", text)
        if new != text:
            text = new
            fixed.append(a)
    if fixed:
        bdir = os.path.join(os.path.dirname(path), ".patchx", "backup") \
            if ".patchx" in path else os.path.join(
                os.path.dirname(os.path.dirname(path)), ".patchx", "backup")
        os.makedirs(bdir, exist_ok=True)
        with open(os.path.join(bdir, backup_name), "w",
                  encoding="utf-8") as fh:
            fh.write(open(path, encoding="utf-8").read())
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return fixed


def _fix_manifest_unknown_attrs(tree, attrs):
    """Bỏ attribute/flag không tồn tại trong framework khỏi AndroidManifest.xml
    (có sao lưu). Trả danh sách attribute đã bỏ.

    Lý do: aapt2/framework cũ (vd Termux) không biết attribute mới của
    SDK 33+ (vd android:enableOnBackInvokedCallback) hay flag/giá trị enum
    mới (vd foregroundServiceType 0x800, hyphenationFrequency 4) → link fail;
    bỏ attribute là cách an toàn vì giá trị mặc định thường tương đương."""
    return _remove_xml_attrs(os.path.join(tree, "AndroidManifest.xml"),
                             attrs, "AndroidManifest.xml.bak_attrfix")


def _fix_res_xml_unknown_attrs(tree, fixes):
    """Bỏ attribute không tương thích trong các tệp res/*.xml (có sao lưu).
    `fixes` = {đường_dẫn_từ_output: set(attribute)}. Trả danh sách đã bỏ."""
    out = []
    for rel, attrs in sorted(fixes.items()):
        full = rel if os.path.isfile(rel) else os.path.join(os.getcwd(), rel)
        if not os.path.isfile(full):
            continue
        name = os.path.basename(full).replace(".", "_") + ".bak_attrfix"
        fixed = _remove_xml_attrs(full, attrs, name)
        for a in fixed:
            out.append("%s:%s" % (os.path.relpath(full, tree), a))
    return out


def _build_apktool(tree, unsigned, aapt=None, extra=None):
    """Chạy `apktool b`; tự sửa attribute/flag mới hơn framework (manifest +
    res/*.xml, có sao lưu) rồi build lại tối đa 4 lượt; nếu aapt2 crash
    PrivateAttributeMover thì thử aapt2 patched. Trả (proc, lệnh cuối)."""
    # Xóa build cache apktool trước mỗi lần build/retry: nếu lượt trước chết
    # giữa chừng (aapt2 manifest/res fail, smali writer lỗi 64K...), apktool
    # có thể để lại classes*.dex chưa hoàn chỉnh (header bị zero/thiếu) và
    # các lần sau sẽ tái dùng "smali has not changed" thay vì assemble lại.
    def _clear_apktool_build_cache():
        build_dir = os.path.join(tree, "build")
        if os.path.isdir(build_dir):
            shutil.rmtree(build_dir, ignore_errors=True)

    cmd = ["apktool", "b", tree, "-o", unsigned]
    if aapt:
        cmd += ["--aapt", aapt]
    if extra:
        cmd += extra
    last_cmd = cmd
    _log("Build: %s" % " ".join(cmd))
    _clear_apktool_build_cache()
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.returncode != 0 and "PrivateAttributeMover" in (
            (proc.stderr or "") + (proc.stdout or "")):
        patched = _find_patched_aapt2()
        if patched:
            _log("aapt2 hệ thống lỗi PrivateAttributeMover — thử lại bằng "
                 "aapt2 patched: %s" % patched)
            cmd2 = ["apktool", "b", tree, "-o", unsigned, "--aapt", patched]
            if extra:
                cmd2 += extra
            _log("Build: %s" % " ".join(cmd2))
            last_cmd = cmd2
            _clear_apktool_build_cache()
            proc2 = subprocess.run(cmd2, text=True, capture_output=True)
            if proc2.returncode == 0:
                return proc2, cmd2
            proc = proc2
    all_fixed = []
    for _round in range(4):
        if proc.returncode == 0:
            break
        output = (proc.stdout or "") + (proc.stderr or "")
        m_attrs = MANIFEST_ATTR_RE.findall(output)
        m_flags = ["android:" + n if not n.startswith("android:") else n
                   for n in MANIFEST_FLAG_RE.findall(output)]
        res_fixes = {}
        for rel, attr in RES_ATTR_RE.findall(output):
            res_fixes.setdefault(rel, set()).add(attr)
        if not (m_attrs or m_flags or res_fixes):
            break
        fixed = _fix_manifest_unknown_attrs(tree, m_attrs + m_flags)
        fixed += _fix_res_xml_unknown_attrs(tree, res_fixes)
        if not fixed:
            break
        all_fixed += fixed
        _log("Framework cũ thiếu attribute/flag (%d chỗ) — đã sao lưu + bỏ, "
             "build lại (lượt %d)." % (len(fixed), _round + 1))
        _clear_apktool_build_cache()
        proc = subprocess.run(last_cmd, text=True, capture_output=True)
        if proc.returncode == 0:
            proc.manifest_fix = all_fixed
            return proc, last_cmd
    if all_fixed:
        proc.manifest_fix = all_fixed
    return proc, last_cmd


def cmd_apk_test(args):
    """Áp patch lên APK thật, rebuild và ghi bài tập cải thiện từ lỗi."""
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    apply_code = 0
    build_code = 0
    apply_output = ""
    build_output = ""

    apply_args = ["apply"]
    if args.dry_run:
        apply_args.append("--dry-run")
    apply_args.extend(args.patch)
    apply_args.append(tree)
    apply_code, _, apply_output = _run_patchx(apply_args)

    if args.build:
        if args.fix_res:
            changes = _normalize_resource_names(tree, dry_run=False)
            _log("Đã chuẩn hoá %d tên resource trước khi build" % len(changes))
        if not _ensure_tools(["apktool", "java", "aapt2"],
                             auto_install=not args.no_auto_install):
            build_code = 127
            build_output = "missing tools"
        else:
            apk_path = os.path.join(out, args.apk_name)
            extra = ["--use-aapt1"] if args.use_aapt1 else None
            started = time.monotonic()
            proc, cmd = _build_apktool(tree, apk_path, aapt=args.aapt,
                                       extra=extra)
            _log(" ".join(cmd))
            build_code = proc.returncode
            build_output = (proc.stdout or "") + (proc.stderr or "")
            print(build_output.rstrip())

    exercises = _apk_error_exercises(apply_output, build_output,
                                     apply_code, build_code)
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree,
        "patches": args.patch,
        "apply_returncode": apply_code,
        "build_returncode": build_code,
        "exercises": exercises,
    }
    jpath = os.path.join(out, "improvements.json")
    with open(jpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    lines = ["# Bài tập cải thiện từ APK thật", "",
             "- Thời gian: %s" % data["generated"],
             "- Cây APK: `%s`" % tree,
             "- Áp patch: %d lỗi; build: %d lỗi" % (
                 apply_code, build_code), ""]
    if not exercises:
        lines.append("Không phát hiện vấn đề cần cải thiện.")
    for e in exercises:
        lines += ["## " + e["title"], "",
                  "- Nguyên nhân: %s" % e["root_cause"],
                  "- Hướng sửa: %s" % e["suggested_fix"], ""]
    mpath = os.path.join(out, "improvements_report.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    _log("Đã ghi %s" % jpath)
    _log("Đã ghi %s" % mpath)
    return 0


def _cap_priority(caps):
    weights = {
        "bypass-license": 1.00,
        "integrity": 0.95,
        "google": 0.90,
        "token": 0.85,
        "api": 0.80,
        "trace": 0.75,
        "shell": 0.70,
        "anonymity": 0.60,
        "id-spoof": 0.55,
        "ads": 0.50,
        "network": 0.45,
        "permission": 0.35,
        "installer": 0.30,
        "save": 0.25,
        "ui": 0.20,
        "font": 0.10,
    }
    if not caps:
        return 0.05
    return max(weights.get(c, 0.05) for c in caps)


def _write_json(out, fname, data):
    """Ghi JSON vào thư mục output, trả đường dẫn."""
    path = os.path.join(out, fname)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    _log("Đã ghi %s" % path)
    return path


def _patch_path_map(root):
    """Trả dict tên patch -> đường dẫn zip (cùng quy tắc đặt tên
    `session.load_patch_map`) để lệnh `apply` gọi lại đúng tệp."""
    from patchx_core.audit import parse_nested_zip
    from patchx_core.parser import parse_patch_file
    mapping = {}
    if not os.path.isdir(root):
        return mapping
    for name in sorted(os.listdir(root)):
        if not name.lower().endswith(".zip"):
            continue
        path = os.path.join(root, name)
        try:
            p = parse_patch_file(path)
            mapping[p.name or os.path.splitext(name)[0]] = path
        except ValueError:
            nested = parse_nested_zip(path)
            for idx, p in enumerate(nested):
                key = p.name or os.path.splitext(name)[0]
                if len(nested) > 1:
                    key = "%s#%d" % (os.path.splitext(name)[0], idx + 1)
                mapping[key] = path
        except Exception:
            continue
    return mapping


def _plan_patches(tree, patches, limit_combos=150):
    """Tầng Plan: xếp hạng patch đơn + combo bổ trợ theo bằng chứng trên cây.

    Trả (scored, combo_scored, cache, eng) — scored/combo_scored đã sắp xếp.
    Dùng chung cho `apk-plan` và `apk-full`.
    """
    from patchx_core import session
    from patchx_core.advisor import (ScanCache, collect_literal_patterns,
                                     collect_regex_hints, coverage_patch_cached)
    from patchx_core.bypass_advisor import _modern_ratio
    from patchx_core.engine import Engine
    from patchx_core.optimizer import patch_capabilities

    _log("Đang quét nhanh (rg + cache theo hash APK) và tính toán: %s" % tree)
    cache = ScanCache(tree)
    cache.ensure(sorted(collect_literal_patterns(list(patches.values()))))
    cache.prepare_hints(collect_regex_hints(list(patches.values())))
    eng = Engine(tree, quiet=True, no_dex=True)
    eng._file_index = list(cache.inventory)
    scored = []
    for name, p in patches.items():
        cov = coverage_patch_cached(p, tree, eng=eng, cache=cache)
        matches = sum(d["khớp"] for d in cov["chi_tiết"])
        caps = patch_capabilities(p)
        score = 0.5 * cov["tỷ_lệ"] + 0.2 * min(1.0, matches / 20.0) \
            + 0.3 * _cap_priority(caps)
        rules_ratio = (cov["quy_tắc_khớp"] / cov["quy_tắc"]
                       if cov["quy_tắc"] else 0.0)
        modern = _modern_ratio(p)
        confidence = round(100 * (0.5 * cov["tỷ_lệ"]
                                  + 0.2 * min(1.0, matches / 20.0)
                                  + 0.2 * rules_ratio + 0.1 * modern), 1)
        files_matched = set()
        for d in cov["chi_tiết"]:
            files_matched.update(d.get("tệp_trúng") or [])
        top_files = sorted(
            ((f, sum(d.get("khớp", 0) for d in cov["chi_tiết"]
                     if f in (d.get("tệp_trúng") or [])))
             for f in files_matched),
            key=lambda kv: -kv[1])[:5]
        evidence = {
            "files_matched": len(files_matched),
            "top_files": [{"file": f, "matches": m}
                          for f, m in top_files],
        }
        scored.append({
            "patch": name,
            "score": round(score, 4),
            "coverage": round(cov["tỷ_lệ"], 4),
            "matches": matches,
            "rules": cov["quy_tắc"],
            "rules_matched": cov["quy_tắc_khớp"],
            "capabilities": sorted(caps),
            "chi_tiết": cov["chi_tiết"],
            "modern_ratio": round(modern, 3),
            "confidence": confidence,
            "evidence": evidence,
        })
    scored.sort(key=lambda x: (-x["score"], -x["matches"], x["patch"]))
    score_map = {x["patch"]: x["score"] for x in scored}
    combos = session.complementary_combos(patches, max_combos=limit_combos)
    combo_scored = []
    for c in combos:
        a, b = c["patches"]
        if a not in score_map or b not in score_map:
            continue
        base = (score_map[a] + score_map[b]) / 2.0
        synergy = min(len(c["support"]), 6)
        combo_scored.append({
            "patches": c["patches"],
            "score": round(base + 0.025 * synergy, 4),
            "confidence": round(
                (score_map[a] + score_map[b]) / 2.0 * 100, 1),
            "capabilities": c["capabilities"],
            "support": c["support"],
        })
    combo_scored.sort(key=lambda x: (-x["score"], x["patches"][0]))
    return scored, combo_scored, cache, eng


def _write_plan_reports(out, tree, inp, scored, combo_scored, limit, cache):
    """Ghi bypass_plan.json/md + bypass_report.json/md (tầng Plan)."""
    from patchx_core.bypass_advisor import (build_bypass_report,
                                            detect_protections_fast,
                                            render_markdown)
    os.makedirs(out, exist_ok=True)
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree,
        "input": inp,
        "top_patches": scored[:limit],
        "top_combos": combo_scored[:limit],
    }
    _write_json(out, "bypass_plan.json", data)
    # Evidence graph (P16): patch ↔ tệp trúng với số khớp làm trọng số
    nodes = []
    edges = []
    seen_files = set()
    for x in scored[:limit]:
        pid = "patch:" + x["patch"]
        nodes.append({"id": pid, "kind": "patch", "label": x["patch"],
                      "score": x["score"]})
        for tf in x.get("evidence", {}).get("top_files", []):
            fid = "file:" + tf["file"]
            if fid not in seen_files:
                seen_files.add(fid)
                nodes.append({"id": fid, "kind": "file",
                              "label": tf["file"]})
            edges.append({"from": pid, "to": fid,
                          "matches": tf["matches"]})
    _write_json(out, "evidence_graph.json",
                {"nodes": nodes, "edges": edges,
                 "generated": data["generated"]})
    lines = ["# Phương án bypass khả thi theo tỷ lệ", "",
             "- Thời gian: %s" % data["generated"],
             "- Cây APK: `%s`" % tree,
             "- Đầu vào patch: `%s`" % inp, "",
             "## Patch đơn xếp theo điểm", "",
             "| Hạng | Patch | Điểm | Tin cậy | Bao phủ | Khớp | Năng lực |",
             "|------|-------|-----:|--------:|--------:|-----:|----------|"]
    for i, x in enumerate(scored[:limit], 1):
        lines.append("| %d | %s | %.3f | %.0f%% | %.0f%% | %d | %s |" % (
            i, x["patch"], x["score"], x.get("confidence", 0),
            x["coverage"] * 100, x["matches"],
            ", ".join(x["capabilities"])))
    lines += ["", "## Combo bổ trợ xếp theo điểm", "",
              "| Hạng | Patch 1 | Patch 2 | Điểm | Tin cậy | Năng lực |",
              "|------|---------|---------|-----:|--------:|----------|"]
    for i, c in enumerate(combo_scored[:limit], 1):
        lines.append("| %d | %s | %s | %.3f | %.0f%% | %s |" % (
            i, c["patches"][0], c["patches"][1], c["score"],
            c.get("confidence", 0), ", ".join(c["capabilities"])))
    mpath = os.path.join(out, "bypass_plan.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    report = build_bypass_report(
        tree, scored, combo_scored, None, limit=limit,
        protections=detect_protections_fast(tree, cache))
    _write_json(out, "bypass_report.json", report)
    rmd = os.path.join(out, "bypass_report.md")
    with open(rmd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_markdown(report))
    _log("Đã ghi %s" % mpath)
    _log("Đã ghi %s" % rmd)
    return report


def cmd_apk_plan(args):
    from patchx_core import session

    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    apk_input = _find_input_apk(args)
    if apk_input and "PATCHX_RSA_DATA" not in os.environ:
        cert_hex = _extract_apk_cert_hex(apk_input)
        if cert_hex:
            os.environ["PATCHX_RSA_DATA"] = cert_hex
            _log(
    f"Đã nạp cert gốc APK ({len(cert_hex) // 2} byte) để thay %RSA_DATA% "
    "(hack signature)."
)
        else:
            _log("Không trích được cert v1 từ APK gốc — %RSA_DATA% sẽ giữ "
                 "nguyên (spoof chữ ký không hoạt động).")
    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch trong %s" % args.input)
        return 1
    scored, combo_scored, cache, _eng = _plan_patches(tree, patches,
                                                      args.limit_combos)
    out = os.path.abspath(args.output)
    report = _write_plan_reports(out, tree, os.path.abspath(args.input),
                                 scored, combo_scored, args.limit, cache)
    _log("Top patch (điểm | thành công dự đoán | khớp):")
    for x in scored[:10]:
        item = next((i for i in report["top_patches"]
                     if i["patch"] == x["patch"]), None)
        rate = item["tỷ_lệ_thành_công"] if item else 0.0
        print("  %.3f  %5.0f%%  %s  (%d khớp)"
              % (x["score"], rate, x["patch"], x["matches"]))
    return 0


def cmd_bench_scan(args):
    """Đo tốc độ quét candidate trên cây APK (nghiệm thu APK lớn < 60s)."""
    from patchx_core import session
    from patchx_core.advisor import (ScanCache, collect_literal_patterns,
                                     collect_regex_hints, coverage_patch_cached)
    from patchx_core.engine import Engine

    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch trong %s" % args.input)
        return 1
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    _log("Bench quét candidate trên: %s (%d patch)" % (tree, len(patches)))

    t0 = time.monotonic()
    cache = ScanCache(tree)
    cache.ensure(sorted(collect_literal_patterns(list(patches.values()))))
    cache.prepare_hints(collect_regex_hints(list(patches.values())))
    t_inventory = round(time.monotonic() - t0, 3)

    eng = Engine(tree, quiet=True, no_dex=True)
    eng._file_index = list(cache.inventory)
    t0 = time.monotonic()
    stats = {"quy_tắc": 0, "quy_tắc_khớp": 0, "rule_ước_lượng": 0,
             "rule_lọc_được": 0}
    for _name, p in patches.items():
        cov = coverage_patch_cached(p, tree, eng=eng, cache=cache)
        stats["quy_tắc"] += cov["quy_tắc"]
        stats["quy_tắc_khớp"] += cov["quy_tắc_khớp"]
        for d in cov["chi_tiết"]:
            if d.get("ước_lượng"):
                stats["rule_ước_lượng"] += 1
            elif d.get("lọc_hint"):
                stats["rule_lọc_được"] += 1
    t_coverage = round(time.monotonic() - t0, 3)
    total = round(t_inventory + t_coverage, 3)
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree,
        "input": os.path.abspath(args.input),
        "patches": len(patches),
        "inventory_seconds": t_inventory,
        "coverage_seconds": t_coverage,
        "total_seconds": total,
        "nghiem_thu_60s": total < 60.0,
        "rules": stats["quy_tắc"],
        "rules_matched": stats["quy_tắc_khớp"],
        "rules_sampled": stats["rule_ước_lượng"],
        "rules_filtered": stats["rule_lọc_được"],
        "hints_prepared": cache.hints_prepared,
    }
    jpath = os.path.join(out, "bench_report.json")
    with open(jpath, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    lines = ["# Bench quét candidate (Đợt A)", "",
             "- Thời gian: %s" % data["generated"],
             "- Cây APK: `%s`" % tree,
             "- Đầu vào patch: `%s` (%d patch)" % (data["input"],
                                                   data["patches"]),
             "",
             "| Giai đoạn | Thời gian (s) |",
             "|-----------|--------------:|",
             "| Inventory + rg batch | %.3f |" % t_inventory,
             "| Coverage %d patch | %.3f |" % (data["patches"], t_coverage),
             "| **Tổng** | **%.3f** |" % total, "",
             "## Nghiệm thu",
             "",
             "- Quy tắc quét: %d; quy tắc khớp: %d"
             % (stats["quy_tắc"], stats["quy_tắc_khớp"]),
             "- Rule regex lọc bằng hint: %d; rule ước lượng (mẫu): %d"
             % (stats["rule_lọc_được"], stats["rule_ước_lượng"]),
             "- Tổng thời gian < 60s: **%s**"
             % ("ĐẠT" if data["nghiem_thu_60s"] else "CHƯA ĐẠT"), ""]
    mpath = os.path.join(out, "bench_report.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    _log("Inventory+rg: %.3fs; coverage %d patch: %.3fs; tổng: %.3fs"
         % (t_inventory, data["patches"], t_coverage, total))
    _log("Đã ghi %s" % jpath)
    _log("Đã ghi %s" % mpath)
    return 0


def _normalize_resource_names(tree, dry_run=False):
    """Đổi tên resource có ký tự `$` và cập nhật tham chiếu đầy đủ:
    tệp thật + public.xml + mọi tệp tham chiếu (xml/smali/...)."""
    if not os.path.isdir(tree):
        return []
    res_root = os.path.join(tree, "res")
    if not os.path.isdir(res_root):
        return []
    changes = []
    for root, _dirs, files in os.walk(res_root):
        for fname in files:
            if not fname.startswith("$"):
                continue
            old = fname
            new = fname.lstrip("$")
            old_path = os.path.join(root, old)
            new_path = os.path.join(root, new)
            if os.path.exists(new_path):
                # Tránh ghi đè: thêm hậu tố patchx
                stem, ext = os.path.splitext(new)
                new = stem + "_patchx_renamed" + ext
                new_path = os.path.join(root, new)
            if not dry_run:
                os.rename(old_path, new_path)
            changes.append({"old": old, "new": new,
                            "path": os.path.relpath(old_path, tree)})

    # Cập nhật tên resource (bỏ phần mở rộng) trong toàn bộ cây trừ
    # bản sao gốc: public.xml và tham chiếu dùng tên không đuôi nên phải
    # đối chiếu theo thân tên, không theo tên tệp.
    text_exts = (".xml", ".smali", ".txt", ".json", ".properties")
    if changes and not dry_run:
        pairs = []
        for c in changes:
            old_stem = os.path.splitext(c["old"])[0]
            new_stem = os.path.splitext(c["new"])[0]
            if old_stem != new_stem:
                pairs.append((old_stem, new_stem))
        # Thay tên dài trước ($$x) để không nuốt nhầm phần của tên ngắn ($x)
        pairs.sort(key=lambda p: len(p[0]), reverse=True)
        for root, _dirs, files in os.walk(tree):
            rel_parts = os.path.relpath(root, tree).split(os.sep)
            if rel_parts and rel_parts[0] in ("original", ".patchx"):
                continue
            for fname in files:
                if not fname.lower().endswith(text_exts):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8",
                              errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                updated = text
                for old_stem, new_stem in pairs:
                    updated = updated.replace(old_stem, new_stem)
                if updated != text:
                    with open(path, "w", encoding="utf-8",
                              newline="\n") as fh:
                        fh.write(updated)
    return changes


def cmd_apk_fix_res(args):
    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    changes = _normalize_resource_names(tree, dry_run=args.dry_run)
    _log("%s %d tài nguyên có tên chứa `$`" % (
        "(dry-run) sẽ sửa" if args.dry_run else "Đã sửa", len(changes)))
    for c in changes[:20]:
        print("  %s -> %s" % (c["old"], c["new"]))
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        path = os.path.join(args.output, "resource_fix.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"tree": tree, "changes": changes}, fh,
                      ensure_ascii=False, indent=2)
        _log("Đã ghi %s" % path)
    return 0


def _patched_apk_name(base, dir=APKS_PATCH_DIR):
    """Tên APK đã patch dễ phân biệt: <cây>_patched_<YYYYMMDD-HHMMSS>.apk."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = "%s_patched_%s.apk" % (base, stamp)
    n = 1
    while os.path.exists(os.path.join(dir, name)):
        name = "%s_patched_%s-%d.apk" % (base, stamp, n)
        n += 1
    return name


def _find_keystore():
    """Keystore đã ký APK thật trước đó (nếu còn)."""
    cand = os.path.join(APKS_PATCH_DIR, "patchx-debug.keystore")
    return cand if os.path.isfile(cand) else None


def _ensure_debug_keystore():
    """Sinh keystore debug trong outputs/apk/apk-patch/ nếu chưa có (dùng khi ký)."""
    ks = os.path.join(APKS_PATCH_DIR, "patchx-debug.keystore")
    if os.path.isfile(ks):
        return ks
    if not shutil.which("keytool"):
        return None
    proc = subprocess.run(
        ["keytool", "-genkeypair", "-keystore", ks,
         "-storepass", "patchx123", "-keypass", "patchx123",
         "-alias", "patchx", "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "10000", "-dname", "CN=PatchX Debug"],
        text=True, capture_output=True)
    if proc.returncode != 0:
        _log("Sinh keystore debug lỗi: %s"
             % (proc.stderr or "").strip()[-300:])
        return None
    return ks


def cmd_apk_patch(args):
    """Áp patch lên APK, build, ký và lưu APK đã patch vào outputs/apk/apk-patch/."""
    auto = not getattr(args, "no_auto_install", False)
    if not _ensure_tools(["apktool", "java", "aapt2", "zipalign",
                          "apksigner"], auto):
        return 1
    if not args.patch and not getattr(args, "fast", False):
        _log("Cần ít nhất một patch.")
        return 1

    # Chế độ Fast-Path (sửa DEX/AXML in-place siêu tốc không qua apktool d/b)
    if getattr(args, "fast", False):
        from patchx_core.apk_fast_repack import fast_patch_and_repack
        apk_target = None
        if getattr(args, "tree", None) and os.path.isfile(args.tree):
            apk_target = args.tree
        elif getattr(args, "patch", None):
            for p in args.patch:
                if p.endswith(".apk") and os.path.isfile(p):
                    apk_target = p
                    break
        if not apk_target and os.path.isdir(DEFAULT_APKS):
            cands = [os.path.join(DEFAULT_APKS, f) for f in os.listdir(DEFAULT_APKS) if f.endswith(".apk")]
            if cands:
                apk_target = sorted(cands, key=os.path.getsize)[0]
        if not apk_target:
            _log("Fast-Path yêu cầu một tệp .apk đầu vào (chỉ định trong tham số tree hoặc đặt trong Apks/).")
            return 1

        os.makedirs(APKS_PATCH_DIR, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(apk_target))[0]
        out_name = "%s_fastpatched_%s.apk" % (base_name, time.strftime("%Y%m%d-%H%M%S"))
        final_apk = os.path.join(APKS_PATCH_DIR, out_name)

        dex_reps = []
        for item in getattr(args, "dex_str", []) or []:
            if "=" in item:
                o, n = item.split("=", 1)
                dex_reps.append((o, n, False))
        for item in getattr(args, "dex_hex", []) or []:
            if "=" in item:
                o, n = item.split("=", 1)
                dex_reps.append((o, n, True))
        axml_reps = []
        for item in getattr(args, "axml", []) or []:
            if "=" in item:
                o, n = item.split("=", 1)
                axml_reps.append((o, n))
        arsc_reps = []
        for item in getattr(args, "arsc", []) or []:
            if "=" in item:
                o, n = item.split("=", 1)
                arsc_reps.append((o, n))

        _log("Khởi chạy Fast-Path: %s -> %s" % (apk_target, final_apk))
        t0 = time.monotonic()
        res = fast_patch_and_repack(
            apk_target,
            dex_replacements=dex_reps if dex_reps else None,
            axml_replacements=axml_reps if axml_reps else None,
            arsc_replacements=arsc_reps if arsc_reps else None,
            output_apk=final_apk,
            strip_signatures=True,
        )
        dt = time.monotonic() - t0
        if not res.get("success"):
            _log("Fast-Path thất bại: %s" % res.get("message"))
            return 1

        _log("Fast-Path thành công trong %.2fs (DEX: %d hits, AXML: %d hits, ARSC: %d hits, Stripped: %d)"
             % (dt, res["dex_hits"], res["axml_hits"], res.get("arsc_hits", 0), res["stripped_signatures"]))

        # Ký số APK
        signed = False
        if not args.no_sign:
            ks = args.keystore or _find_keystore() or _ensure_debug_keystore()
            if ks and shutil.which("apksigner"):
                signed_apk = final_apk[:-4] + "_signed.apk"
                sp = subprocess.run(
                    ["apksigner", "sign", "--ks", ks, "--ks-pass", "pass:" + args.ks_pass,
                     "--key-pass", "pass:" + args.ks_pass, "--out", signed_apk, final_apk],
                    text=True, capture_output=True
                )
                if sp.returncode == 0:
                    shutil.move(signed_apk, final_apk)
                    signed = True
                    _log("Đã ký số debug APK: %s" % final_apk)

        size = os.path.getsize(final_apk)
        report = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": "fast-path",
            "apk_input": apk_target,
            "output": out_name,
            "size_bytes": size,
            "signed": signed,
            "seconds": round(dt, 2),
            "dex_hits": res["dex_hits"],
            "axml_hits": res["axml_hits"],
        }
        _write_report(report)
        return 0

    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    os.makedirs(APKS_PATCH_DIR, exist_ok=True)
    name = _patched_apk_name(os.path.basename(tree.rstrip(os.sep)))
    tmp_dir = os.path.join(APKS_PATCH_DIR, "_tmp_%s"
                           % time.strftime("%H%M%S"))
    os.makedirs(tmp_dir, exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
              "tree": tree, "patches": args.patch, "output": name}
    try:
        if not _preflight_gate(args.patch, tree):
            _log("PREFLIGHT BLOCK — dừng pipeline apk-patch.")
            _write_report(report)
            return 1
        code, _, _ = _run_patchx(["apply"] + args.patch + [tree])
        report["apply_returncode"] = code
        if code != 0:
            _log("Áp patch thất bại (mã %d) — dừng." % code)
            _write_report(report)
            return 1
        changes = _normalize_resource_names(tree, dry_run=False)
        report["resource_fixes"] = len(changes)
        _log("Đã chuẩn hoá %d tên resource chứa `$`" % len(changes))
        _log("Bước 4.5: Cổng kiểm tra NGỮ NGHĨA smali (chặn VerifyError trước khi build)...")
        if not _cong_ngu_nghia(tree, tmp_dir, report, args):
            _write_report(report)
            return 1
        unsigned = os.path.join(tmp_dir, name + ".unsigned.apk")
        started = time.monotonic()
        proc, cmd = _build_apktool(tree, unsigned,
                                   aapt=args.aapt or shutil.which("aapt2"))
        report["build_seconds"] = round(time.monotonic() - started, 1)
        report["build_returncode"] = proc.returncode
        if proc.returncode != 0:
            _log("Build thất bại (mã %d): %s"
                 % (proc.returncode,
                    ((proc.stderr or "") + (proc.stdout or "")).strip()[-400:]))
            _write_report(report)
            return 1
        aligned = os.path.join(tmp_dir, name + ".aligned.apk")
        ap = subprocess.run(["zipalign", "-f", "4", unsigned, aligned],
                            text=True, capture_output=True)
        report["zipalign_returncode"] = ap.returncode
        if ap.returncode != 0:
            _log("zipalign lỗi: %s" % (ap.stderr or "").strip()[-300:])
            aligned = unsigned
        final = aligned
        report["signed"] = False
        if not args.no_sign:
            ks = args.keystore or _find_keystore() or _ensure_debug_keystore()
            if not ks:
                _log("Không có keystore để ký — lưu APK đã align (chưa ký).")
            else:
                final = os.path.join(APKS_PATCH_DIR, name)
                sp = subprocess.run(
                    ["apksigner", "sign", "--ks", ks,
                     "--ks-pass", "pass:" + args.ks_pass,
                     "--key-pass", "pass:" + args.ks_pass,
                     "--out", final, aligned],
                    text=True, capture_output=True)
                report["signed"] = sp.returncode == 0
                if sp.returncode != 0:
                    _log("Ký APK lỗi: %s"
                         % (sp.stderr or "").strip()[-300:])
                    final = aligned
        if final == aligned:
            shutil.copyfile(aligned, os.path.join(APKS_PATCH_DIR, name))
            final = os.path.join(APKS_PATCH_DIR, name)
        size = os.path.getsize(final)
        report["size_bytes"] = size
        _log("Đã lưu APK đã patch (%s, %.2f MB): %s"
             % ("đã ký" if report["signed"] else "chưa ký",
                size / 1048576.0, final))
        _write_report(report)
        return 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _write_report(report):
    """Ghi báo cáo JSON của lệnh apk-patch vào outputs/apk/apk-patch/."""
    os.makedirs(APKS_PATCH_DIR, exist_ok=True)
    path = os.path.join(APKS_PATCH_DIR,
                        "report_%s.json" % report["output"].rsplit(".", 1)[0])
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    _log("Đã ghi %s" % path)



def _patch_set_fingerprint(inp, path_map):
    """Vân tay cache: bộ patch đầu vào + mã nguồn lõi (engine/smali_lib/...).

    Sửa engine.py/smali_lib.py hoặc patch → vân tay đổi → apply/build cache
    tự bị INVALIDATE (không dùng kết quả cũ). Chỉ decode/plan được giữ khi
    đầu vào không đổi.
    """
    import hashlib as _hl
    h = _hl.sha256()
    h.update(os.path.abspath(inp).encode("utf-8"))
    for name in sorted(path_map):
        p = path_map[name]
        h.update(name.encode("utf-8"))
        try:
            with open(p, "rb") as fh:
                h.update(_hl.sha256(fh.read()).digest())
        except OSError:
            h.update(b"?")
    for mod in ("engine.py", "smali_lib.py", "smali_validate.py",
                "parser.py", "model.py"):
        mp = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "patchx_core", mod)
        h.update(mod.encode("utf-8"))
        try:
            with open(mp, "rb") as fh:
                h.update(_hl.sha256(fh.read()).digest())
        except OSError:
            h.update(b"?")
    tp = os.path.abspath(__file__)
    h.update(b"toolkit")
    try:
        with open(tp, "rb") as fh:
            h.update(_hl.sha256(fh.read()).digest())
    except OSError:
        pass
    return h.hexdigest()


def _load_stages(out):
    p = os.path.join(out, "stages.json")
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_stages(out, stages):
    try:
        _write_json(out, "stages.json", stages)
    except Exception:
        pass


def _validate_tree(tree, changed_only=False):
    """Xác thực cấu trúc smali — trả dict kết quả (kèm giây)."""
    from patchx_core.smali_validate import validate_tree as _vt
    t0 = time.monotonic()
    r = _vt(tree, changed_only=changed_only)
    r["seconds"] = round(time.monotonic() - t0, 1)
    return r


def _log_validation(r):
    _log("Xác thực smali: %d/%d tệp đạt, %d method, %d tệp kiểm tra (%.1fs)%s"
         % (r["ok"], r["files"], r["methods"], r["changed"], r["seconds"],
            " — chỉ tệp đổi mới" if r.get("changed_only") else ""))
    for e in (r["errors"] or [])[:25]:
        _log("FAIL " + e)


def _cong_ngu_nghia(tree, out, report, args):
    """Bước 1.5 — cổng kiểm tra NGỮ NGHĨA smali: chặn VerifyError trước khi build.

    `patchx_core/smali_validate.py` chỉ kiểm HÌNH DẠNG (cân đối .method/.end method,
    cú pháp từng lệnh) nên ngày 2026-09-20 nó báo "12.196/12.196 tệp đạt, 0 lỗi"
    mà app vẫn crash vì máy ảo ART từ chối lớp MainActivity. Cổng này kiểm thêm
    nhóm lỗi NGỮ NGHĨA:
      N1 — đọc thanh ghi CHƯA GÁN trên một đường đi nào đó (LỖI: chặn build)
      N2 — vùng vá ghi đè thanh ghi mà đoạn ngoài vùng vá còn đọc (CẢNH BÁO)
    Trả True nếu được phép build tiếp.
    """
    TEN_CONG_CU = "kiem_tra_verify.py"
    if getattr(args, "bo_cong_ngu_nghia", False):
        _log("Bước 1.5: BỎ QUA cổng kiểm tra ngữ nghĩa (--bo-cong-ngu-nghia).")
        report["cong_ngu_nghia"] = {"bo_qua": True}
        return True
    cong_cu = os.path.join(TOOLKIT_DIR, "tools", TEN_CONG_CU)
    if not os.path.isfile(cong_cu):
        _log("Bước 1.5: chưa có %s — bỏ qua cổng ngữ nghĩa." % cong_cu)
        report["cong_ngu_nghia"] = {"thieu_cong_cu": cong_cu}
        return True
    cmd = [sys.executable, cong_cu, "--tree", tree, "--json"]
    if getattr(args, "cong_ngu_nghia_all", False):
        cmd.append("--all")
    t0 = time.monotonic()
    proc = subprocess.run(cmd, text=True, capture_output=True)
    giay = round(time.monotonic() - t0, 1)
    try:
        d = json.loads(proc.stdout)
    except Exception:
        _log("Bước 1.5: cổng ngữ nghĩa không trả JSON (mã %d) — coi như cảnh báo."
             % proc.returncode)
        _log(((proc.stderr or "") + (proc.stdout or "")).strip()[-400:])
        report["cong_ngu_nghia"] = {"json_loi": True, "returncode": proc.returncode,
                                    "seconds": giay}
        return True
    loi = d.get("loi") or []
    canh = d.get("canh_bao") or []
    report["cong_ngu_nghia"] = {"tep": d.get("tep"), "ham": d.get("ham"),
                                "seconds": giay, "so_loi": len(loi),
                                "so_canh_bao": len(canh),
                                "loi": loi[:100], "canh_bao": canh[:100]}
    duoc_chan, ly_do_chan = _cong_cu_duoc_chan(TEN_CONG_CU, cong_cu)
    report["cong_ngu_nghia"]["duoc_chan"] = duoc_chan
    report["cong_ngu_nghia"]["ly_do_chan"] = ly_do_chan
    _log("Bước 1.5: Cổng ngữ nghĩa — %d tệp, %d hàm (%.1fs): %d LỖI, %d cảnh báo"
         % (d.get("tep", 0), d.get("ham", 0), giay, len(loi), len(canh)))
    for v in loi[:25]:
        _log("  [LỖI ] %s :: %s() dòng %d (pc 0x%X) — đọc %s chưa gán | %s"
             % (os.path.basename(v.get("tep", "?")), v.get("ham", "?"),
                v.get("dong", 0), v.get("pc", 0), v.get("thanh_ghi", "?"),
                v.get("text", "")))
    for v in canh[:10]:
        _log("  [CẢNH] %s :: %s() vùng vá dòng %d ghi %s, dòng %d vẫn đọc lại"
             % (os.path.basename(v.get("tep", "?")), v.get("ham", "?"),
                v.get("dong_ghi", 0), v.get("thanh_ghi", "?"),
                v.get("dong_doc_lai", 0)))
    if loi:
        if duoc_chan:
            _log("Cổng ngữ nghĩa CHẶN BUILD (%d lỗi) — sửa xong mới build lại; muốn bỏ "
                 "qua có chủ ý thì thêm --bo-cong-ngu-nghia." % len(loi))
            return False
        _log("Cổng ngữ nghĩa thấy %d lỗi NHƯNG chưa được phép chặn (%s) — CHẠY BÓNG: "
             "chỉ cảnh báo, KHÔNG chặn build." % (len(loi), ly_do_chan))
    return True


def _cong_cu_duoc_chan(ten_tep, duong_dan):
    """Công cụ chỉ được quyền CHẶN build khi sổ 'tin dùng' cho phép.

    Đây là cơ chế chống đúng loại sai ngày 2026-09-20: một công cụ chưa chứng minh được
    mình thì không được phép chặn việc của người dùng.
      - Có sổ và mục đó ở trạng thái tin_dung + chế độ chan  -> cho chặn.
      - Có sổ nhưng chưa cho phép                          -> CHẠY BÓNG (chỉ cảnh báo).
      - Chưa có sổ -> phải tự chứng minh ngay: chạy --tu-kiem, đạt thì cho chặn.
    """
    so_tep = os.path.join(TOOLKIT_DIR, "outputs", "cong_cu", "trang_thai.json")
    try:
        with open(so_tep, encoding="utf-8") as f:
            so = json.load(f)
    except (OSError, ValueError):
        so = None
    if so:
        muc = (so.get("cong_cu") or {}).get(ten_tep) or {}
        if muc.get("che_do") == "chan" and muc.get("trang_thai") == "tin_dung":
            return True, "sổ tin dùng cho phép (nguồn nâng: %s)" % muc.get("nguon_nang")
        return False, "sổ tin dùng CHƯA cho phép (trạng thái=%s, chế độ=%s)" % (
            muc.get("trang_thai", "khong-co"), muc.get("che_do", "khong-co"))
    try:
        r = subprocess.run([sys.executable, duong_dan, "--tu-kiem"],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            return True, "tự kiểm đạt ngay tại chỗ (chưa có sổ tin dùng)"
    except (OSError, subprocess.SubprocessError):
        pass
    return False, "chưa có sổ tin dùng và tự kiểm không đạt"


def cmd_apk_debug(args):
    """Chế độ debug-fast: áp patch lên cây ĐÃ GIẢI MÃ rồi xác thực smali,
    DỪNG — không build/ký/cài (rút ngắn vòng lặp fix→test)."""
    auto = not getattr(args, "no_auto_install", False)
    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    from patchx_core import session
    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch trong %s" % args.input)
        return 1
    path_map = _patch_path_map(args.input)
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
              "tree": tree, "input": os.path.abspath(args.input),
              "mode": "apk-debug"}
    if args.patches:
        selected = list(args.patches)
        missing = [n for n in selected if n not in patches]
        if missing:
            _log("Patch không tồn tại: %s" % ", ".join(missing))
            _write_json(out, "apk_debug_report.json", report)
            return 1
    else:
        _log("Chưa chỉ định patch — chạy plan để tự chọn top.")
        scored, combo_scored, cache, _eng = _plan_patches(
            tree, patches, args.limit_combos)
        selected = [x["patch"] for x in scored
                    if x["matches"] > 0 or x["coverage"] > 0][:args.top]
        if not selected:
            _log("Không có patch nào khớp trên cây — dừng.")
            _write_json(out, "apk_debug_report.json", report)
            return 1
        _write_plan_reports(out, tree, report["input"], scored,
                            combo_scored, args.top, cache)
    report["patches_selected"] = selected
    _log("Áp %d patch: %s" % (len(selected), ", ".join(selected)))
    apply_paths = [path_map.get(n, n) for n in selected]
    t0 = time.monotonic()
    code, elapsed, apply_output = _run_patchx(["apply"] + apply_paths
                                              + [tree])
    report["apply_returncode"] = code
    report["apply_seconds"] = round(elapsed, 1)
    report["apply_output_tail"] = (apply_output or "").strip()[-600:]
    if code != 0:
        _log("Áp patch thất bại (mã %d) — dừng." % code)
        _write_json(out, "apk_debug_report.json", report)
        return 1
    _log("Xác thực smali (không build/ký/cài)...")
    vr = _validate_tree(tree, changed_only=args.changed_only)
    _log_validation(vr)
    report["validate"] = {k: v for k, v in vr.items() if k != "errors"}
    report["validate_errors"] = vr["errors"][:200]
    report["validate_total_errors"] = len(vr["errors"])
    _write_json(out, "apk_debug_report.json", report)
    if vr["errors"]:
        _log("Xác thực THẤT BẠI (%d lỗi) — xem apk_debug_report.json."
             % len(vr["errors"]))
        return 1
    _log("Cổng kiểm tra NGỮ NGHĨA smali (không build — bắt lỗi thanh ghi ngay tại đây)...")
    if not _cong_ngu_nghia(tree, out, report, args):
        _write_json(out, "apk_debug_report.json", report)
        return 1
    _log("Xác thực ĐẠT — dùng `apk-build` để build + ký.")
    return 0


def cmd_apk_build(args):
    """Build nhanh: xác thực smali → chuẩn hoá resource → apktool b →
    zipalign → ký → verify (không plan/apply)."""
    auto = not getattr(args, "no_auto_install", False)
    if not _ensure_tools(["apktool", "java", "aapt2", "zipalign",
                          "apksigner"], auto):
        return 1
    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    report = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
              "tree": tree, "mode": "apk-build"}
    _log("Bước 1: Xác thực smali...")
    vr = _validate_tree(tree, changed_only=args.changed_only)
    _log_validation(vr)
    report["validate"] = {k: v for k, v in vr.items() if k != "errors"}
    report["validate_errors"] = vr["errors"][:200]
    report["validate_total_errors"] = len(vr["errors"])
    if vr["errors"]:
        _log("Xác thực THẤT BẠI (%d lỗi) — dừng, không build."
             % len(vr["errors"]))
        _write_json(out, "apk_build_report.json", report)
        return 1
    _log("Bước 1.5: Cổng kiểm tra NGỮ NGHĨA smali (chặn VerifyError trước khi build)...")
    if not _cong_ngu_nghia(tree, out, report, args):
        _write_json(out, "apk_build_report.json", report)
        return 1
    _log("Bước 2: Chuẩn hoá resource `$`")
    changes = _normalize_resource_names(tree, dry_run=False)
    report["resource_fixes"] = len(changes)
    _log("Đã chuẩn hoá %d tên resource chứa `$`" % len(changes))
    unsigned = os.path.join(out, "apk_build.unsigned.apk")
    t0 = time.monotonic()
    proc, _cmd = _build_apktool(tree, unsigned,
                                aapt=args.aapt or shutil.which("aapt2"))
    report["build_seconds"] = round(time.monotonic() - t0, 1)
    report["build_returncode"] = proc.returncode
    build_output = (proc.stdout or "") + (proc.stderr or "")
    if build_output.strip():
        print(build_output.rstrip()[-1500:])
    if proc.returncode != 0:
        _log("Build thất bại (mã %d) — xem apk_build_report.json."
             % proc.returncode)
        _write_json(out, "apk_build_report.json", report)
        return 1
    _log("Bước 3: zipalign + ký + verify")
    name = _patched_apk_name(os.path.basename(tree.rstrip(os.sep)), dir=out)
    report["output_apk"] = name
    aligned = os.path.join(out, "apk_build.aligned.apk")
    ap = subprocess.run(["zipalign", "-f", "4", unsigned, aligned],
                        text=True, capture_output=True)
    report["zipalign_returncode"] = ap.returncode
    if ap.returncode != 0:
        _log("zipalign lỗi: %s" % (ap.stderr or "").strip()[-300:])
        aligned = unsigned
    ok = True
    verify_output = ""
    if args.no_sign:
        report["sign_skipped"] = True
        final = aligned
    else:
        ks = args.keystore or _find_keystore() or _ensure_debug_keystore()
        if not ks:
            _log("Không có keystore để ký — lưu APK đã align (chưa ký).")
            report["signed"] = False
            ok = False
            final = aligned
        else:
            final = os.path.join(out, name)
            sp = subprocess.run(
                ["apksigner", "sign", "--ks", ks,
                 "--ks-pass", "pass:" + args.ks_pass,
                 "--key-pass", "pass:" + args.ks_pass,
                 "--out", final, aligned],
                text=True, capture_output=True)
            report["signed"] = sp.returncode == 0
            report["sign_returncode"] = sp.returncode
            if sp.returncode != 0:
                _log("Ký APK lỗi: %s" % (sp.stderr or "").strip()[-300:])
                ok = False
            else:
                vp = subprocess.run(["apksigner", "verify", "--verbose",
                                     final],
                                    text=True, capture_output=True)
                report["verify_returncode"] = vp.returncode
                verify_output = (vp.stdout or "") + (vp.stderr or "")
                report["verify_schemes"] = [
                    line.strip() for line in verify_output.splitlines()
                    if "Verified using" in line and "true" in line.lower()]
                if vp.returncode != 0:
                    ok = False
    if not os.path.exists(os.path.join(out, name)):
        shutil.copyfile(aligned, os.path.join(out, name))
    final_path = os.path.join(out, name)
    report["size_bytes"] = os.path.getsize(final_path)

    # Tự động dọn dẹp các tệp trung gian (unsigned, aligned) để tiết kiệm bộ nhớ trên Termux
    if os.path.isfile(final_path) and not getattr(args, "keep_intermediates", False):
        for temp_f in (unsigned, aligned):
            if temp_f != final_path and os.path.isfile(temp_f):
                try:
                    os.remove(temp_f)
                except OSError:
                    pass

    _log("Đã lưu APK (%s, %.2f MB): %s"
         % ("đã ký" if report.get("signed") else "chưa ký",
            report["size_bytes"] / 1048576.0, final_path))
    _write_json(out, "apk_build_report.json", report)
    return 0 if ok else 1


def _write_full_report(out, report):
    """Ghi apk_full_report.json/md từ dữ liệu các tầng."""
    _write_json(out, "apk_full_report.json", report)
    lines = ["# Báo cáo apk-full (end-to-end)", "",
             "- Thời gian: %s" % report["generated"],
             "- Cây APK: `%s`" % report["tree"],
             "- Đầu vào patch: `%s`" % report["input"],
             "- Patch chọn: %s" % ", ".join(
                 report.get("patches_selected", []) or []), ""]
    if report.get("dry_run"):
        lines += ["Dry-run: dừng sau bước Plan — chưa áp patch."]
    else:
        lines += ["| Bước | Kết quả |", "|------|---------|"]
        lines += ["| Plan (inventory+candidate) | %.1fs — %d patch khớp |"
                  % (report.get("plan_seconds", 0.0),
                     len(report.get("patches_selected", [])))]
        lines += ["| Apply | mã %s trong %.1fs |"
                  % (report.get("apply_returncode"),
                     report.get("apply_seconds", 0.0))]
        lines += ["| Chuẩn hoá resource | %d tên `$` |"
                  % report.get("resource_fixes", 0)]
        lines += ["| Build | mã %s trong %.1fs |"
                  % (report.get("build_returncode"),
                     report.get("build_seconds", 0.0))]
        if "zipalign_returncode" in report:
            lines += ["| Zipalign | mã %s |" % report["zipalign_returncode"]]
        if report.get("sign_skipped"):
            lines += ["| Ký | bỏ qua (--no-sign) |"]
        elif "signed" in report:
            lines += ["| Ký | %s |"
                      % ("OK" if report.get("signed") else "LỖI")]
        if report.get("verify_returncode") is not None:
            schemes = ", ".join(report.get("verify_schemes", [])) or "chưa rõ"
            lines += ["| Verify | mã %s (%s) |"
                      % (report["verify_returncode"], schemes)]
        if report.get("output_apk"):
            lines += ["", "## APK đầu ra", "",
                      "- Tệp: `%s/%s`" % (os.path.abspath(out),
                                          report["output_apk"]),
                      "- Kích thước: %.2f MB"
                      % (report.get("size_bytes", 0) / 1048576.0)]
        exercises = report.get("exercises") or []
        lines += ["", "## Bài tập cải thiện"]
        if not exercises:
            lines += ["- Không phát hiện vấn đề cần cải thiện."]
        for e in exercises:
            lines += ["- %s — %s"
                      % (e["title"], e.get("suggested_fix", ""))]
    mpath = os.path.join(out, "apk_full_report.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    _log("Đã ghi %s" % mpath)



def cmd_apk_full(args):
    """Dây chuyền end-to-end tinh gọn:
    Mặc định tự động kích hoạt Unified Pipeline (Fast-Path In-Place <0.5s + Taint Security Gates)
    nếu nhận tệp APK/APKS/AAB, loại bỏ hoàn toàn nguy cơ lỗi aapt2 và sự phụ thuộc apktool chậm chạp.
    Hỗ trợ --legacy nếu muốn ép chạy quy trình giải mã và apktool b truyền thống.
    """
    # 1. Phát hiện artifact APK trực tiếp
    target_apk = None
    tree_arg = getattr(args, "tree", None)
    if tree_arg and os.path.isfile(tree_arg):
        ext = os.path.splitext(tree_arg)[1].lower()
        if ext in (".apk", ".apks", ".aab"):
            target_apk = tree_arg
    if not target_apk and getattr(args, "input", None):
        inp_ext = os.path.splitext(args.input)[1].lower()
        if inp_ext in (".apk", ".apks", ".aab") and os.path.isfile(args.input):
            target_apk = args.input

    # Nếu có tệp APK và không bật cờ --legacy: Chạy Unified Fast-Path In-Place Repack (<0.5s)
    if target_apk and not getattr(args, "legacy", False):
        _log("Áp dụng Pipeline Tinh Gọn Hiện Đại: Fast-Path Zero-Copy (<0.5s) & Taint Security Gates.")
        from patchx_core.pipeline_unified import UnifiedPipeline
        out = os.path.abspath(args.output)
        pipeline = UnifiedPipeline(target_apk, output_dir=out)
        res = pipeline.run(mode="auto")
        _log("Hoàn thành Pipeline: %s (%s s)" % (res.get("verdict"), res.get("elapsed_seconds")))
        return 0 if res.get("verdict") == "SUCCESS" else 1

    auto = not getattr(args, "no_auto_install", False)
    if not _ensure_tools(["apktool", "java", "aapt2", "zipalign",
                          "apksigner"], auto):
        return 1
    from patchx_core import session

    tree = _resolve_apk_tree(args)
    if not tree:
        return 1
    patches = session.load_patch_map(args.input)
    if not patches:
        _log("Không tìm thấy patch trong %s" % args.input)
        return 1
    path_map = _patch_path_map(args.input)
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    resume = bool(getattr(args, "resume", False))
    stages = _load_stages(out)
    fp_patches = _patch_set_fingerprint(args.input, path_map)
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tree": tree,
        "input": os.path.abspath(args.input),
        "dry_run": bool(args.dry_run),
        "resume": resume,
    }
    apply_output = ""

    # ---- Bước 1–3: Inventory + Candidate + Plan (có cache) ----
    plan_hit = False
    if resume and stages.get("plan", {}).get("fingerprint") == fp_patches \
            and os.path.isfile(os.path.join(out, "bypass_plan.json")):
        selected = list(stages["plan"]["selected"])
        scored, combo_scored, cache = [], [], None
        plan_hit = True
        report["plan_seconds"] = 0.0
        report["plan_skipped"] = True
        _log("Resume: bỏ qua Plan (cache khớp) — %d patch đã chọn"
             % len(selected))
    else:
        _log("Bước 1–3: Inventory + Candidate + Plan")
        t0 = time.monotonic()
        scored, combo_scored, cache, _eng = _plan_patches(tree, patches,
                                                          args.limit_combos)
        report["plan_seconds"] = round(time.monotonic() - t0, 1)
        if not args.patches and args.patches_file:
            pfile = os.path.abspath(args.patches_file)
            if not os.path.isfile(pfile):
                _log("Không tìm thấy --patches-file: %s" % pfile)
                return 1
            try:
                raw = open(pfile, encoding="utf-8").read().strip()
                if raw.startswith("[") or raw.startswith("{"):
                    data = json.loads(raw)
                    args.patches = data if isinstance(data, list) else \
                        data.get("patches") or []
                else:
                    args.patches = [ln.strip() for ln in raw.splitlines()
                                    if ln.strip()]
            except Exception as e:
                _log("Lỗi đọc --patches-file: %s" % e)
                return 1
            _log("Đọc %d patch chỉ định từ %s" % (len(args.patches), pfile))
        if args.patches:
            selected = list(args.patches)
            missing = [n for n in selected if n not in patches]
            if missing:
                _log("Patch không tồn tại: %s" % ", ".join(missing))
                return 1
        else:
            selected = [x["patch"] for x in scored
                        if x["matches"] > 0 or x["coverage"] > 0][:args.top]
            if not selected:
                _log("Không có patch nào khớp trên cây này — dừng (có thể "
                     "chỉ định patch cụ thể).")
                return 1
        stages["plan"] = {"fingerprint": fp_patches, "selected": selected,
                          "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        _save_stages(out, stages)
    report["patches_selected"] = selected
    _log("Chọn %d patch: %s" % (len(selected), ", ".join(selected)))

    # P8 — GATE 3 PREFLIGHT bắt buộc trước khi áp
    patch_files = [path_map.get(n, n) for n in selected]
    if not _preflight_gate(patch_files, tree):
        _log("PREFLIGHT BLOCK — dừng pipeline apk-full.")
        return 1

    if not plan_hit:
        _write_json(out, "inventory.json",
                    {"tree": tree, "files": len(cache.inventory),
                     "hints_prepared": bool(cache.hints_prepared)})
        _write_json(out, "candidates.json",
                    [{"patch": x["patch"], "score": x["score"],
                      "coverage": x["coverage"], "matches": x["matches"],
                      "rules": x["rules"], "rules_matched": x["rules_matched"],
                      "capabilities": x["capabilities"]} for x in scored])
        _write_plan_reports(out, tree, report["input"], scored, combo_scored,
                            args.top, cache)

    if args.dry_run:
        _log("Dry-run: dừng sau bước Plan — chưa apply/build.")
        _write_full_report(out, report)
        return 0

    # ---- Bước 4: Apply (có cache) ----
    fp_apply = json.dumps({"tree": tree, "selected": selected,
                           "patches": fp_patches}, sort_keys=True)
    if resume and stages.get("apply", {}).get("fingerprint") == fp_apply \
            and os.path.isfile(os.path.join(out, "apply_report.json")):
        _log("Resume: bỏ qua Apply (cache khớp)")
        report["apply_returncode"] = 0
        report["apply_seconds"] = 0.0
        report["apply_skipped"] = True
    else:
        _log("Bước 4: Apply %d patch lên cây" % len(selected))
        apply_paths = [path_map.get(n, n) for n in selected]
        t0 = time.monotonic()
        code, elapsed, apply_output = _run_patchx(["apply"] + apply_paths
                                                  + [tree])
        report["apply_returncode"] = code
        report["apply_seconds"] = round(elapsed, 1)
        if code != 0:
            _log("Áp patch thất bại (mã %d) — dừng." % code)
            _write_full_report(out, report)
            return 1
        _write_json(out, "apply_report.json",
                    {"tree": tree, "patches": selected, "returncode": code,
                     "seconds": report["apply_seconds"]})
        stages["apply"] = {"fingerprint": fp_apply,
                           "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        _save_stages(out, stages)

    if args.no_build:
        _log("Bỏ build theo --no-build — cây đã được áp patch.")
        _write_full_report(out, report)
        return 0

    # ---- Bước 5–6: resource + build + zipalign + ký (có cache) ----
    name = _patched_apk_name(os.path.basename(tree.rstrip(os.sep)), dir=out)
    report["output_apk"] = name
    final_path = os.path.join(out, name)
    build_output = ""
    build_code = 0
    if resume and stages.get("build", {}).get("fingerprint") == fp_apply \
            and os.path.isfile(final_path):
        _log("Resume: bỏ qua Build+Sign (APK đã tồn tại: %s)" % final_path)
        report["resource_fixes"] = 0
        report["build_seconds"] = 0.0
        report["build_returncode"] = 0
        report["build_skipped"] = True
        report["zipalign_returncode"] = 0
        report["signed"] = True
        report["sign_returncode"] = 0
        unsigned = final_path
        ok = True
        verify_output = ""
    else:
        _log("Bước 4.5: Cổng kiểm tra NGỮ NGHĨA smali (chặn VerifyError trước khi build)...")
        if not _cong_ngu_nghia(tree, out, report, args):
            _write_full_report(out, report)
            return 1
        _log("Bước 5: Chuẩn hoá resource `$` + apktool b")
        changes = _normalize_resource_names(tree, dry_run=False)
        report["resource_fixes"] = len(changes)
        _log("Đã chuẩn hoá %d tên resource chứa `$`" % len(changes))
        unsigned = os.path.join(out, "apk_full.unsigned.apk")
        t0 = time.monotonic()
        proc, cmd = _build_apktool(tree, unsigned,
                                   aapt=args.aapt or shutil.which("aapt2"))
        build_code = proc.returncode
        report["build_seconds"] = round(time.monotonic() - t0, 1)
        report["build_returncode"] = build_code
        build_output = (proc.stdout or "") + (proc.stderr or "")
        if build_output.strip():
            print(build_output.rstrip()[-1500:])
        _write_json(out, "build_report.json",
                    {"tree": tree, "returncode": build_code,
                     "seconds": report["build_seconds"],
                     "unsigned_apk": (os.path.basename(unsigned)
                                      if os.path.exists(unsigned) else None),
                     "manifest_fix": getattr(proc, "manifest_fix", []),
                     "output_tail": build_output.strip()[-800:]})
        if build_code != 0:
            _log("Build thất bại (mã %d) — xem build_report.json."
                 % build_code)
            report["exercises"] = _apk_error_exercises(apply_output,
                                                       build_output, 0,
                                                       build_code)
            _write_full_report(out, report)
            return 1
        _log("Bước 6: zipalign + ký + verify")
        aligned = os.path.join(out, "apk_full.aligned.apk")
        ap = subprocess.run(["zipalign", "-f", "4", unsigned, aligned],
                            text=True, capture_output=True)
        report["zipalign_returncode"] = ap.returncode
        if ap.returncode != 0:
            _log("zipalign lỗi: %s" % (ap.stderr or "").strip()[-300:])
            aligned = unsigned
        ok = True
        verify_output = ""
        if args.no_sign:
            report["sign_skipped"] = True
        else:
            ks = args.keystore or _find_keystore() or _ensure_debug_keystore()
            if not ks:
                _log("Không có keystore để ký — lưu APK đã align (chưa ký).")
                report["signed"] = False
                ok = False
            else:
                final = os.path.join(out, name)
                sp = subprocess.run(
                    ["apksigner", "sign", "--ks", ks,
                     "--ks-pass", "pass:" + args.ks_pass,
                     "--key-pass", "pass:" + args.ks_pass,
                     "--out", final, aligned],
                    text=True, capture_output=True)
                report["signed"] = sp.returncode == 0
                report["sign_returncode"] = sp.returncode
                if sp.returncode != 0:
                    _log("Ký APK lỗi: %s"
                         % (sp.stderr or "").strip()[-300:])
                    ok = False
                else:
                    vp = subprocess.run(["apksigner", "verify", "--verbose",
                                         final],
                                        text=True, capture_output=True)
                    report["verify_returncode"] = vp.returncode
                    verify_output = (vp.stdout or "") + (vp.stderr or "")
                    report["verify_schemes"] = [
                        line.strip() for line in verify_output.splitlines()
                        if "Verified using" in line and "true" in line.lower()]
                    if vp.returncode != 0:
                        ok = False
        if not os.path.exists(final_path):
            shutil.copyfile(aligned, final_path)
        report["size_bytes"] = os.path.getsize(final_path)
        _log("Đã lưu APK (%s, %.2f MB): %s"
             % ("đã ký" if report.get("signed") else "chưa ký",
                report["size_bytes"] / 1048576.0, final_path))
        stages["build"] = {"fingerprint": fp_apply,
                           "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        _save_stages(out, stages)
    if "size_bytes" not in report and os.path.isfile(final_path):
        report["size_bytes"] = os.path.getsize(final_path)

    if args.runtime and report.get("signed") and ok:
        if resume and stages.get("runtime") and os.path.isfile(
                os.path.join(out, "runtime_report.json")):
            _log("Resume: bỏ qua Runtime verify (báo cáo cũ còn hiệu lực)")
            try:
                with open(os.path.join(out, "runtime_report.json"),
                          encoding="utf-8") as fh:
                    rt = json.load(fh)
            except Exception:
                rt = {}
            report["runtime"] = {k: v for k, v in rt.items()
                                 if k != "logcat_tail"}
            if rt.get("trạng_thái") != "thiếu môi trường" \
                    and rt.get("m2") is False:
                ok = False
        else:
            _log("Bước 7: Runtime verify (M2/M3)")
            rt = _runtime_verify(final_path, wait=args.runtime_wait,
                                 logcat_lines=args.runtime_logcat_lines,
                                 expect=args.runtime_expect or (),
                                 forbid=args.runtime_forbid or ())
            report["runtime"] = {k: v for k, v in rt.items()
                                 if k != "logcat_tail"}
            _write_json(out, "runtime_report.json", rt)
            _write_runtime_report(out, rt)
            if rt.get("trạng_thái") != "thiếu môi trường" \
                    and rt.get("m2") is False:
                ok = False
            stages["runtime"] = {"time": time.strftime("%Y-%m-%d %H:%M:%S")}
            _save_stages(out, stages)
    _write_json(out, "verify_report.json",
                {"returncode": report.get("verify_returncode"),
                 "schemes": report.get("verify_schemes", []),
                 "output_tail": verify_output.strip()[-800:]})
    if ok:
        try:
            from patchx_core.learn import record_success, categorize
            rt = report.get("runtime") or {}
            record_success(TOOLKIT_DIR, {
                "combo": ", ".join(selected),
                "danh_mục": categorize(report.get("tree", "")),
                "apk": report.get("output_apk"),
                "m2": rt.get("m2"),
                "m3": rt.get("m3"),
            })
            _log("Đã ghi vào kho combo thành công (combos_success.json).")
        except Exception:
            pass
    report["exercises"] = _apk_error_exercises(apply_output, build_output,
                                               0, build_code)
    _write_full_report(out, report)
    return 0 if ok else 1




def _adb_devices():
    """Danh sách device/emulator đang kết nối (state = device)."""
    try:
        proc = subprocess.run(["adb", "devices"], text=True,
                              capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    devices = []
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


_EMULATOR_LOCAL_PORTS = (5555, 5557, 5559, 5561, 21503, 26944, 26945)


def _adb_connect(target, timeout=10):
    """Thử `adb connect host:port` (máy ảo cloud/redfinger/VMOS...)."""
    try:
        proc = subprocess.run(["adb", "connect", target], text=True,
                              capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False, "timeout/lỗi chạy adb"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0 and "connected" in out.lower(), out


def _aapt2_badging(apk):
    """Trích package/launchable-activity từ `aapt2 dump badging`."""
    aapt = shutil.which("aapt2")
    if not aapt:
        return {}
    try:
        proc = subprocess.run([aapt, "dump", "badging", apk], text=True,
                              capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    out = (proc.stdout or "") + (proc.stderr or "")
    info = {}
    m = re.search(r"package: name='([^']+)'", out)
    if m:
        info["package"] = m.group(1)
    m = re.search(r"launchable-activity: name='([^']+)'", out)
    if m:
        info["activity"] = m.group(1)
    return info


_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
               "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
               "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
               "0A": "LISTEN", "0B": "CLOSING"}


def _net_snapshot(device, timeout=20):
    """Đọc /proc/net/tcp{,6},udp{,6} qua adb — trả dict proto → dòng."""
    snap = {}
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        p = subprocess.run(["adb", "-s", device, "shell", "cat",
                            "/proc/net/%s" % proto],
                           text=True, errors="replace",
                           capture_output=True, timeout=timeout)
        snap[proto] = (p.stdout or "").splitlines()
    return snap


def _hex_ipv4(h):
    """Hex little-endian trong /proc/net/tcp → a.b.c.d."""
    if not h or h == "00000000":
        return "0.0.0.0"
    try:
        n = int(h, 16)
    except ValueError:
        return h
    return ".".join(str((n >> (8 * i)) & 0xFF) for i in range(4))


def _hex_ipv6(h):
    """Hex big-endian 32 ký tự trong /proc/net/tcp6 → IPv6 dạng số."""
    if not h:
        return ""
    try:
        words = [h[i:i + 4] for i in range(0, 32, 4)]
        return ":".join(str(int(w, 16)) for w in words)
    except ValueError:
        return h


def _fmt_addr(spec):
    """Địa chỉ dạng HEX:PORT trong /proc/net → IP:port."""
    addr, port = (spec.split(":") + [""])[:2]
    try:
        p = int(port or "0", 16)
    except ValueError:
        p = 0
    if len(addr) == 8:
        ip = _hex_ipv4(addr)
    else:
        ip = _hex_ipv6(addr)
    return "%s:%d" % (ip, p)


def _parse_proc_net(lines):
    """Chuyển dòng /proc/net/tcp thành tập (local, remote, state)."""
    out = []
    for ln in lines[1:]:
        parts = ln.split()
        if len(parts) < 4:
            continue
        out.append((parts[1], parts[2], parts[3]))
    return out


def _net_new_connections(before, after):
    """Kết nối TCP mới xuất hiện sau launch so với trước (bỏ LISTEN)."""
    def pairs(snap):
        s = set()
        for proto in ("tcp", "tcp6"):
            s.update(_parse_proc_net(snap.get(proto, [])))
        return s

    new = []
    for local, remote, state in sorted(pairs(after) - pairs(before)):
        if state in ("0A", "07", "06"):  # LISTEN/CLOSE/TIME_WAIT — bỏ qua
            continue
        new.append({"local": _fmt_addr(local),
                    "remote": _fmt_addr(remote),
                    "state": _TCP_STATES.get(state, state)})
    return new


def _find_signed_apk():
    """APK đã ký mới nhất (outputs/apk/apk-patch/*_signed.apk)."""
    cands = []
    for d in (APKS_PATCH_DIR,):
        if not os.path.isdir(d):
            continue
        for n in os.listdir(d):
            if n.lower().endswith(".apk") and "_signed" in n.lower():
                cands.append(os.path.join(d, n))
    if not cands:
        return None
    return max(cands, key=os.path.getmtime)


def _runtime_verify(apk, package=None, activity=None, wait=8,
                    logcat_lines=2000, expect=(), forbid=(), timeout=60,
                    capture_net=True, device=None, scenario=None,
                    scenario_out=None):
    """Runtime verify (Đợt C): cài, mở, logcat, đánh giá M2/M3.

    Không có device/emulator → trả trạng thái "thiếu môi trường" (hợp lệ,
    không phải lỗi) theo UPGRADE_PLAN_V3. M3 dùng kịch bản tuỳ chọn
    `expect` (regex phải xuất hiện) / `forbid` (regex không được xuất hiện).
    """
    result = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
              "apk": os.path.abspath(apk)}
    if not os.path.isfile(apk):
        result["lỗi"] = "Không tìm thấy APK: %s" % apk
        return result
    install_apks = [apk]
    install_method = "install"
    badging_apk = apk
    if apk.lower().endswith(".apks"):
        import tempfile
        split_dir = tempfile.mkdtemp(prefix="patchx_apks_")
        try:
            with zipfile.ZipFile(apk) as zf:
                zf.extractall(split_dir)
        except (OSError, zipfile.BadZipFile) as e:
            result["lỗi"] = "Không giải nén được .apks: %s" % e
            return result
        apk_files = sorted(
            os.path.join(split_dir, n) for n in os.listdir(split_dir)
            if n.lower().endswith(".apk"))
        if not apk_files:
            result["lỗi"] = "File .apks không chứa APK con."
            return result
        base = next((p for p in apk_files
                     if os.path.basename(p).lower() == "base.apk"), apk_files[0])
        badging_apk = base
        install_apks = [base] + [p for p in apk_files if p != base]
        install_method = "install-multiple"
        result["split_dir"] = split_dir
        result["split_apks"] = [os.path.basename(p) for p in install_apks]
    badging = _aapt2_badging(badging_apk)
    pkg = package or badging.get("package")
    act = activity or badging.get("activity")
    result["package"] = pkg
    result["activity"] = act
    if not pkg:
        result["lỗi"] = "Không lấy được package name (aapt2 dump badging)."
        return result
    devices = _adb_devices()
    result["devices"] = devices
    if not devices:
        result["trạng_thái"] = "thiếu môi trường"
        result["m2"] = None
        result["m3"] = None
        result["m2_status"] = "M2_SKIP"
        result["m3_status"] = "M3_SKIP"
        result["verdict"] = "SKIP"
        result["ghi_chú"] = ("Không có device/emulator kết nối (adb devices "
                             "trống) — M2/M3 chưa nghiệm thu được. Kết nối "
                             "thiết bị hoặc khởi động emulator rồi chạy lại.")
        return result
    if device and device not in devices:
        result["trạng_thái"] = "thiếu môi trường"
        result["m2"] = None
        result["m3"] = None
        result["m2_status"] = "M2_SKIP"
        result["m3_status"] = "M3_SKIP"
        result["verdict"] = "SKIP"
        result["device"] = device
        result["ghi_chú"] = ("Device chỉ định không kết nối (%s) — có: %s"
                             % (device, ", ".join(devices)))
        return result
    device = device or devices[0]
    result["device"] = device

    total_size = sum(os.path.getsize(p) for p in install_apks
                     if os.path.isfile(p))
    install_timeout = max(timeout, 60 + int(total_size / 524288))
    install_cmd = ["adb", "-s", device, install_method, "-r", "-g"] + install_apks
    sp = subprocess.run(install_cmd, text=True, errors="replace",
                        capture_output=True, timeout=install_timeout)
    result["install_returncode"] = sp.returncode
    result["install_method"] = install_method
    install_out = ((sp.stdout or "") + (sp.stderr or "")).strip()
    result["install_output"] = install_out
    m2 = sp.returncode == 0 and "Success" in install_out
    if not m2:
        result["m2"] = False
        result["m3"] = None
        result["m2_status"] = "M2_FAIL"
        result["m3_status"] = "M3_SKIP"
        result["verdict"] = "FAIL"
        result["ghi_chú"] = "Cài APK lỗi — xem install_output."
        return result

    if act:
        cmd = ["adb", "-s", device, "shell", "am", "start", "-n",
               "%s/%s" % (pkg, act)]
    else:
        cmd = ["adb", "-s", device, "shell", "monkey", "-p", pkg,
               "-c", "android.intent.category.LAUNCHER", "1"]
    # Xóa logcat trước khi launch để M2/M3 chỉ tính log của lần chạy này
    # (tránh crash cũ trong buffer và logcat bị spam tràn cửa sổ đọc).
    try:
        subprocess.run(["adb", "-s", device, "logcat", "-c"],
                       text=True, errors="replace",
                       capture_output=True, timeout=timeout)
    except Exception:
        pass
    net_before = _net_snapshot(device) if capture_net else {}
    lp = subprocess.run(cmd, text=True, errors="replace",
                        capture_output=True, timeout=timeout)
    result["launch_returncode"] = lp.returncode
    result["launch_output"] = ((lp.stdout or "") + (lp.stderr or "")).strip()
    time.sleep(wait)

    net_after = _net_snapshot(device) if capture_net else {}
    new_conns = _net_new_connections(net_before, net_after)
    result["network_new_connections"] = new_conns
    if new_conns:
        result["network_note"] = ("Phát hiện %d kết nối mạng mới sau khi mở "
                                  "app — kiểm tra nếu là hành vi 'âm thầm' "
                                  "gửi dữ liệu của patch." % len(new_conns))
    else:
        result["network_note"] = ("Không phát hiện kết nối TCP mới sau khi "
                                  "mở app (đọc /proc/net/tcp).")

    # Tóm tắt chữ ký: schemes v1/v2/v3/v4 (T3 — xác thực hiện đại)
    sigp = subprocess.run(["apksigner", "verify", "--verbose", apk],
                          text=True, errors="replace",
                          capture_output=True, timeout=timeout)
    sig_out = (sigp.stdout or "") + (sigp.stderr or "")
    schemes = []
    for v in ("v1", "v2", "v3", "v3.1", "v4"):
        if "Verified using %s scheme" % v in sig_out:
            schemes.append(v)
    result["signature_ok"] = sigp.returncode == 0
    result["signature_schemes"] = schemes
    result["signature_note"] = ("Play Integrity / hardware attestation cần "
                                "thiết bị thật — máy ảo cloud không xác "
                                "minh được (giới hạn T3).")

    pidp = subprocess.run(["adb", "-s", device, "shell", "pidof", pkg],
                          text=True, errors="replace",
                          capture_output=True, timeout=timeout)
    pid = (pidp.stdout or "").strip()
    result["pid"] = pid or None

    # Fallback M2: logcat máy ảo có thể spam làm trôi dòng `Displayed`.
    # `dumpsys activity activities` cho biết activity đang resumed chính xác.
    resumed = ""
    try:
        dmp = subprocess.run(["adb", "-s", device, "shell", "dumpsys",
                              "activity", "activities"],
                             text=True, errors="replace",
                             capture_output=True, timeout=timeout)
        resumed = (dmp.stdout or "") + (dmp.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        pass
    resumed_ok = bool(pid) and (pkg in resumed)
    result["resumed_activity"] = resumed_ok

    lc = subprocess.run(["adb", "-s", device, "logcat", "-d", "-t",
                         str(logcat_lines)], text=True, errors="replace",
                        capture_output=True, timeout=timeout)
    logcat = (lc.stdout or "") + (lc.stderr or "")
    result["logcat_tail"] = logcat.strip()[-1500:]
    def _main_proc(line):
        m = re.search(r"Process: ([^,]+), PID", line)
        return bool(m) and m.group(1).strip() == pkg

    crash_lines = [ln for ln in logcat.splitlines()
                   if ("FATAL EXCEPTION" in ln or "AndroidRuntime" in ln)
                   and _main_proc(ln)]
    sub_crashes = [ln for ln in logcat.splitlines()
                   if ("FATAL EXCEPTION" in ln or "AndroidRuntime" in ln)
                   and pkg in ln and not _main_proc(ln)
                   and "Process: " in ln]
    result["crash_lines"] = crash_lines[:10]
    result["subprocess_crashes"] = sub_crashes[:10]
    anr_lines = [ln for ln in logcat.splitlines()
                 if re.search(r"ANR in %s(?:$| )" % re.escape(pkg), ln)]
    result["anr_lines"] = anr_lines[:10]
    activity_ok = resumed_ok or (lp.returncode == 0 and bool(pid))
    m2 = m2 and bool(pid) and activity_ok and not crash_lines and not anr_lines
    result["m2"] = m2
    result["m2_status"] = "M2_PASS" if m2 else "M2_FAIL"

    reasons = []
    m3 = None
    if scenario:
        from patchx_core.runtime_scenario import run_scenario
        srep = run_scenario(device, pkg, act, scenario,
                            out_dir=scenario_out or None)
        result["scenario"] = srep
        m3 = {"M3_PASS": True, "M3_FAIL": False, "M3_SKIP": None}.get(
            srep["status"])
        result["m3_status"] = srep["status"]
        reasons = list(srep.get("reasons", []))
        if m3 is None:
            reasons.append("scenario không có assert — SKIP")
    elif expect or forbid:
        expect_ok = any(any(re.search(e, ln) for e in expect)
                        for ln in logcat.splitlines())
        if not expect_ok:
            reasons.append("logcat không chứa mẫu --expect")
        forbid_ok = not any(any(re.search(f, ln) for f in forbid)
                            for ln in logcat.splitlines())
        if not forbid_ok:
            reasons.append("logcat chứa mẫu --forbid")
        m3 = bool(expect_ok and forbid_ok)
        result["m3_status"] = "M3_PASS" if m3 else "M3_FAIL"
    else:
        result["m3_status"] = "M3_SKIP"
        reasons.append("Chưa cung cấp kịch bản xác minh hành vi "
                       "(--scenario hoặc --expect/--forbid).")
    result["m3"] = m3
    result["m3_reasons"] = reasons
    failed = (not m2) or (result.get("m3") is False)
    all_ok = m2 and (result.get("m3") is True)
    result["verdict"] = "FAIL" if failed else ("PASS" if all_ok else "SKIP")
    result["ghi_chú"] = ("M2 = cài + mở + process sống + không FATAL "
                         "EXCEPTION/ANR. M3 = kịch bản hành vi theo app.")
    if failed:
        try:
            from patchx_core.failure_db import classify_failure
        except ImportError:
            classify_failure = None
        if classify_failure:
            msg = " ".join([
                (result.get("install_output") or "")[:400],
                " ".join(result.get("crash_lines") or [])[:400],
                " ".join(result.get("anr_lines") or [])[:400],
                " ".join(reasons)[:400],
            ])
            hit = classify_failure(msg, stage="RUNTIME_M2")
            if hit:
                result["error_id"] = hit["error_id"]
                result["error_fix"] = hit["fix"]
                result["error_cause"] = hit["cause"]
    return result


def _write_runtime_report(out, result):
    """Ghi runtime_report.json/md (Đợt C)."""
    _write_json(out, "runtime_report.json", result)
    lines = ["# Báo cáo Runtime verify (Đợt C — M2/M3)", "",
             "- Thời gian: %s" % result.get("generated"),
             "- APK: `%s`" % result.get("apk")]
    if result.get("lỗi"):
        lines += ["- LỖI: %s" % result["lỗi"]]
    else:
        lines += ["- Package: `%s` | Activity: `%s`"
                  % (result.get("package"), result.get("activity") or "auto"),
                  "- Device: %s" % ", ".join(result.get("devices") or [])
                  or "- Device: (không có)", ""]
        if result.get("install_method"):
            lines += ["- Cài đặt: `%s`" % result["install_method"]]
        if result.get("split_apks"):
            lines += ["- Split APK: `%s`"
                      % "`, `".join(result["split_apks"])]
        if result.get("resumed_activity") is not None:
            lines += ["- Resumed activity: %s"
                      % ("CÓ" if result["resumed_activity"] else "KHÔNG")]
        if result.get("trạng_thái") == "thiếu môi trường":
            lines += ["## Trạng thái: THIẾU MÔI TRƯỜNG (hợp lệ)", "",
                      result.get("ghi_chú", "")]
        else:
            lines += ["| Tiêu chí | Kết quả |", "|----------|---------|",
                      "| Cài APK | %s |" % (
                          "OK" if result.get("m2") else
                          ("LỖI" if result.get("m2") is False else "—")),
                      "| Mở app | mã %s |"
                      % result.get("launch_returncode"),
                      "| Process sống | %s |"
                      % ("Có (pid %s)" % result["pid"]
                         if result.get("pid") else "KHÔNG"),
                      "| Crash (FATAL EXCEPTION) | %d dòng |"
                      % len(result.get("crash_lines") or []),
                      "| ANR | %d dòng |"
                      % len(result.get("anr_lines") or []),
                      "| **M2 (cài + mở + không crash)** | **%s** (%s) |"
                      % ("ĐẠT" if result.get("m2") else "CHƯA ĐẠT",
                         result.get("m2_status")),
                      "| Verdict | **%s** |" % result.get("verdict"),
                      "| **M3 (hành vi đúng)** | **%s** |"
                      % ("ĐẠT" if result.get("m3") else
                         ("CHƯA ĐẠT" if result.get("m3") is False else "CHƯA XÁC MINH")),
                      ""]
            if result.get("m3_reasons"):
                lines += ["## Lý do M3", ""]
                lines += ["- " + r for r in result["m3_reasons"]]
            srep = result.get("scenario")
            if srep:
                lines += ["", "## Kịch bản M3 (từng bước)", "",
                          "| Bước | Loại | Kết quả | Chi tiết |",
                          "|------|------|---------|----------|"]
                for st in srep.get("steps", []):
                    lines += ["| %d | %s | %s | %s |"
                              % (st["step"], st["type"],
                                 "PASS" if st["ok"] else "FAIL",
                                 (st.get("detail") or "").replace("|", "/")
                                 [:120])]
            lines += ["", "## Xác thực hiện đại (T3)", "",
                      "- Chữ ký: %s (%s)" % (
                          "HỢP LỆ" if result.get("signature_ok") else "LỖI",
                          ", ".join(result.get("signature_schemes") or [])),
                      "- Nếu thiếu v2/v3: patch cần bổ sung để qua kiểm tra "
                      "signature (khoá v1/v2/v3).",
                      "- " + result.get("signature_note",
                                        "Play Integrity cần thiết bị thật."),
                      "", "## Hành vi mạng (T3)", "",
                      "- " + result.get("network_note", "không chụp mạng.")]
            conns = result.get("network_new_connections") or []
            if conns:
                lines += ["- Kết nối mới:"]
                lines += ["  - %s -> %s (%s)" % (
                    c["local"], c["remote"], c["state"]) for c in conns[:10]]
            if result.get("crash_lines"):
                lines += ["", "## Crash log (trích)", ""]
                lines += ["```", "\n".join(result["crash_lines"]), "```"]
            if result.get("logcat_tail"):
                lines += ["", "## Logcat (đuôi)", ""]
                lines += ["```", result["logcat_tail"], "```"]
    mpath = os.path.join(out, "runtime_report.md")
    with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    _log("Đã ghi %s" % mpath)


def cmd_apk_runtime(args):
    """Runtime verify M2/M3 trên APK đã ký (Đợt C)."""
    auto = not getattr(args, "no_auto_install", False)
    if not _ensure_tools(["adb", "aapt2"], auto):
        return 1
    connect_attempts = []
    if args.scan_local:
        connect_attempts += ["127.0.0.1:%d" % p
                             for p in _EMULATOR_LOCAL_PORTS]
    if args.connect:
        connect_attempts.append(args.connect)
    apk = args.apk or _find_signed_apk()
    if not apk:
        _log("Cần APK đã build/ký: apk-runtime PATH.apk (hoặc để mặc định "
             "tự tìm trong outputs/apk/apk-patch/).")
        return 1
    connect_result = []
    for target in connect_attempts:
        _log("Thử kết nối máy ảo: adb connect %s" % target)
        ok, out = _adb_connect(target)
        connect_result.append({"target": target, "ok": ok, "output": out})
        if ok:
            break
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    scenario = None
    if args.scenario:
        from patchx_core.runtime_scenario import load_scenario
        scenario = load_scenario(args.scenario)
        _log("Đã nạp scenario M3: %s (%d bước)"
             % (args.scenario, len(scenario.get("steps", []))))
    result = _runtime_verify(apk, package=args.package, activity=args.activity,
                             wait=args.wait, logcat_lines=args.logcat_lines,
                             expect=args.expect or (), forbid=args.forbid or (),
                             capture_net=not args.no_capture_net,
                             device=args.device, scenario=scenario,
                             scenario_out=args.scenario_out or out)
    if connect_result:
        result["connect_attempts"] = connect_result
    _write_runtime_report(out, result)
    if result.get("trạng_thái") == "thiếu môi trường":
        _log("Thiếu môi trường (không có device/emulator) — M2/M3 chưa "
             "nghiệm thu được (trạng thái hợp lệ).")
        return 0
    _log("M2=%s M3=%s verdict=%s (device: %s)"
         % (result.get("m2_status"), result.get("m3_status"),
            result.get("verdict"),
            ", ".join(result.get("devices") or [])))
    if result.get("verdict") == "FAIL":
        return 1
    return 0


_CAP_COLORS = {
    "bypass-license": "#e8590c",
    "integrity": "#0b7285",
    "shell": "#5f3dc4",
    "trace": "#2b8a3e",
    "token": "#c2255c",
    "root": "#e03131",
    "network": "#1971c2",
    "ads": "#f08c00",
    "debug": "#495057",
}


def _render_plan_ui(data):
    """Trang HTML tương tác: liệt kê patch + năng lực để người dùng chọn,
    kèm thống kê điểm/bao phủ/tỷ lệ thành công % và phương án đề xuất."""
    import html as H
    report = data.get("report") or {}
    plan = data.get("plan") or {}
    candidates = data.get("candidates") or []
    apk = data.get("apk") or ""
    out_dir = data.get("output") or ""
    tree = report.get("tree") or plan.get("tree") or data.get("tree") or ""
    pkg = data.get("package") or ""
    generated = plan.get("generated") or report.get("generated") or ""

    by_name = {}
    for p in report.get("top_patches") or []:
        by_name[p.get("patch")] = p
    detail_by_name = {}
    for p in plan.get("top_patches") or []:
        detail_by_name[p.get("patch")] = p
    rows = []
    for c in candidates:
        name = c.get("patch", "")
        rep = by_name.get(name) or {}
        det = detail_by_name.get(name) or {}
        rows.append({
            "name": name,
            "score": round(c.get("score", 0), 3),
            "coverage": round((c.get("coverage") or 0) * 100, 1),
            "matches": c.get("matches", 0),
            "caps": c.get("capabilities") or [],
            "success": rep.get("tỷ_lệ_thành_công"),
            "phan_tich": rep.get("phân_tích"),
            "chi_tiet": det.get("chi_tiết") or rep.get("điểm_bypass") or [],
            "cach": (rep.get("cách_công_cụ") or {}).get("cách") or [],
            "cong_cu": (rep.get("cách_công_cụ") or {}).get("công_cụ") or [],
            "de_xuat": rep.get("đề_xuất") or [],
        })
    rows.sort(key=lambda r: (-r["score"], -(r["success"] or 0), r["name"]))
    payload = {
        "rows": rows,
        "protections": report.get("protections") or [],
        "phan_an": report.get("plan") or {},
        "combos": plan.get("top_combos") or [],
        "apk": apk,
        "apk_name": os.path.basename(apk) if apk else "",
        "apk_size": os.path.getsize(apk) if apk and os.path.isfile(apk) else 0,
        "output": out_dir,
        "tree": tree,
        "package": pkg,
        "generated": generated,
    }
    data_json = json.dumps(payload, ensure_ascii=False)
    return """<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kế hoạch vượt chặn — chọn bản vá</title>
<style>
  :root{--bg:#0f1420;--card:#161d2e;--card2:#1c2538;--tx:#e8edf7;--mut:#8b96ad;
        --acc:#4da3ff;--ok:#37c07c;--warn:#ffb454;--bad:#ff6b6b;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,sans-serif}
  header{padding:12px 16px;background:linear-gradient(135deg,#14213d,#0f1420);
        border-bottom:1px solid #26304a}
  h1{margin:0 0 2px;font-size:clamp(16px,4.5vw,20px);line-height:1.25}
  h3{margin:14px 0 6px}
  .mut{color:var(--mut)}
  #meta{font-size:11px;word-break:break-all}
  main{padding:12px 16px;max-width:1100px;margin:0 auto}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
  .stat{background:var(--card);border:1px solid #26304a;border-radius:10px;padding:8px 10px}
  .stat b{display:block;font-size:19px}
  .stat span{color:var(--mut);font-size:12px}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
        color:#fff;margin:2px 2px 0 0}
  .chip{padding:4px 10px;border-radius:999px;border:1px solid #39445f;cursor:pointer;
        background:var(--card2);font-size:12px;user-select:none}
  .chip.on{background:var(--acc);border-color:var(--acc);color:#04121f}
  .toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0}
  input[type=search],select{background:var(--card2);border:1px solid #39445f;color:var(--tx);
        border-radius:8px;padding:7px 10px;font-size:13px}
  table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
  th,td{padding:7px 8px;text-align:left;border-bottom:1px solid #232d45;vertical-align:top}
  th{background:var(--card2);font-size:12px;color:var(--mut);position:sticky;top:0}
  .bar{height:6px;background:#2a3450;border-radius:4px;overflow:hidden;min-width:60px}
  .bar i{display:block;height:100%;background:linear-gradient(90deg,#4da3ff,#37c07c)}
  .score{font-weight:700}
  .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
  .selbar{position:sticky;bottom:0;background:#10172a;border-top:1px solid #26304a;
        padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  button{background:var(--acc);border:0;color:#04121f;font-weight:700;padding:8px 14px;
        border-radius:8px;cursor:pointer;font-size:13px}
  button.ghost{background:var(--card2);color:var(--tx);border:1px solid #39445f}
  .mono{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:#0b1120;
        border:1px solid #26304a;border-radius:8px;padding:8px 10px;white-space:pre-wrap;
        word-break:break-all;color:#9ecbff}
  .cap{font-size:11px;color:var(--mut)}
  details summary{cursor:pointer;color:var(--acc)}
  .prot{border:1px solid #26304a;border-radius:8px;padding:6px 10px;margin:4px 0;
        background:var(--card);font-size:12px}
  @media (max-width:640px){
    header{padding:10px 12px}
    main{padding:10px 12px}
    .grid{grid-template-columns:repeat(2,1fr);gap:8px;margin:10px 0}
    th,td{padding:6px}
    table{font-size:12px}
    .hide-sm{display:none}
    .toolbar{flex-direction:column;align-items:stretch}
    input[type=search],select{width:100%}
    .selbar{padding:8px 10px}
    button{padding:7px 10px;font-size:12px}
    .prot{font-size:11px;padding:5px 8px}
    .badge{font-size:10px;padding:1px 6px}
  }
</style></head><body>
<header><h1>🎯 Kế hoạch vượt chặn — chọn bản vá</h1>
  <div class="mut" id="meta"></div></header>
<main>
  <div class="grid" id="stats"></div>
  <div id="prots"></div>
  <div class="toolbar">
    <input type="search" id="q" placeholder="🔍 Tìm bản vá..." style="flex:1">
    <select id="sort">
      <option value="score">Sắp: điểm cao</option>
      <option value="success">Sắp: thành công %</option>
      <option value="name">Sắp: tên A–Z</option>
    </select>
  </div>
  <div class="toolbar" id="caps"></div>
  <table><thead><tr>
    <th style="width:34px"></th><th>Bản vá</th><th>Điểm</th><th>Phủ</th>
    <th class="hide-sm">Số khớp</th><th>Thành công %</th><th>Khả năng</th><th></th>
  </tr></thead><tbody id="tbody"></tbody></table>
  <h3>📋 Phương án + rủi ro</h3>
  <div id="plan"></div>
  <h3>🔗 Tổ hợp bổ trợ</h3>
  <div id="combos"></div>
</main>
<div class="selbar">
  <b id="selcount">Đã chọn: 0</b>
  <button id="btn_suggest">Chọn theo đề xuất</button>
  <button id="btn_copy" class="ghost">📋 Sao chép lệnh</button>
  <button id="btn_save">💾 Lưu chọn</button>
  <span class="mono" id="cmdline" style="flex:1 1 100%"></span>
</div>
<script>
const DATA = __DATA__;
const CAPS = __CAPS__;
const VN_CAP={"bypass-license":"Bỏ giấy phép","integrity":"Toàn vẹn","shell":"Lệnh","trace":"Theo dõi","token":"Mã thẻ","root":"Root","network":"Mạng","ads":"Quảng cáo","debug":"Gỡ lỗi"};
const VN_PROT={"pinning":"Chống đổi chứng chỉ","emulator":"Máy ảo","safetynet":"Safetynet","root":"Root","anti-debug":"Chống gỡ lỗi"};
const sel = new Set(JSON.parse(localStorage.getItem("plan_sel")||"[]"));
let capFilter = new Set();
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function badge(c){const col=CAPS[c]||"#555";return `<span class="badge" style="background:${col}">${esc(VN_CAP[c]||c)}</span>`;}
function renderMeta(){
  const mb=DATA.apk_size>0?` • Dung lượng: ${(DATA.apk_size/1048576).toFixed(1)} MB`:"";
  document.getElementById("meta").textContent =
    `Tên: ${DATA.apk_name||"—"} • Gói: ${DATA.package||"—"} • Nơi: ${DATA.tree||"—"}${mb}${DATA.generated?" • Lúc: "+DATA.generated:""}`;
  const all = DATA.rows;
  const capsAll = new Set(); all.forEach(r=>r.caps.forEach(c=>capsAll.add(c)));
  document.getElementById("stats").innerHTML = [
    ["Bản vá", all.length], ["Khả năng", capsAll.size],
    ["Khớp nhiều nhất", Math.max(0,...all.map(r=>r.matches))],
    ["Lớp bảo vệ", DATA.protections.length],
  ].map(s=>`<div class="stat"><b>${s[1]}</b><span>${s[0]}</span></div>`).join("");
  document.getElementById("prots").innerHTML =
    DATA.protections.map(p=>`<div class="prot">🛡 <b>${esc(VN_PROT[p.loại||p.tên]||p.loại||p.tên)}</b> × ${p.lần||0} — ${esc((p.tệp||[]).slice(0,3).join(", "))}</div>`).join("");
  const capDiv = document.getElementById("caps");
  capDiv.innerHTML = [...capsAll].sort().map(c=>
    `<span class="chip${capFilter.has(c)?" on":""}" data-c="${esc(c)}">${esc(VN_CAP[c]||c)}</span>`).join("");
  capDiv.querySelectorAll(".chip").forEach(ch=>ch.onclick=()=>{
    const c=ch.dataset.c; capFilter.has(c)?capFilter.delete(c):capFilter.add(c);
    ch.classList.toggle("on"); renderRows();
  });
}
function renderPlan(){
  const p = DATA.phan_an||{};
  document.getElementById("plan").innerHTML =
    `<div class="prot">✅ Phương án: <b>${esc(p.phương_án||"—")}</b> — tỷ lệ dự đoán `+
    `<b class="ok">${p.tỷ_lệ_dự_đoán??"—"}%</b></div>`+
    (p.steps||[]).map((s,i)=>`<div class="prot">${i+1}. ${esc(s)}</div>`).join("")+
    (p.rủi_ro||[]).map(r=>`<div class="prot warn">⚠ ${esc(r)}</div>`).join("");
  const cb = DATA.combos||[];
  document.getElementById("combos").innerHTML = cb.length?
    `<table><tr><th>Bản vá 1</th><th>Bản vá 2</th><th>Điểm</th><th>Khả năng</th></tr>`+
    cb.map(c=>`<tr><td>${esc(c.patch1||"")}</td><td>${esc(c.patch2||"")}</td>`+
    `<td class="score">${(c.score??0).toFixed(3)}</td>`+
    `<td>${(c.capabilities||[]).map(badge).join("")}</td></tr>`).join("")+
    `</table>`:"<div class='mut'>Không có tổ hợp.</div>";
}
function renderRows(){
  const q=(document.getElementById("q").value||"").toLowerCase();
  const sort=document.getElementById("sort").value;
  let rows=DATA.rows.filter(r=>
    (!q||r.name.toLowerCase().includes(q)||r.caps.some(c=>c.includes(q)))&&
    (capFilter.size===0||r.caps.some(c=>capFilter.has(c))));
  if(sort==="success")rows.sort((a,b)=>(b.success??-1)-(a.success??-1));
  else if(sort==="name")rows.sort((a,b)=>a.name.localeCompare(b.name));
  else rows.sort((a,b)=>b.score-a.score);
  const tb=document.getElementById("tbody");
  tb.innerHTML=rows.map(r=>{
    const pt=r.phan_tich||{};
    const fines=(pt.phạt||[]).map(f=>`<div class="warn">trừ ${esc(VN_PROT[f.loại]||f.loại)} −${f.điểm}đ</div>`).join("");
    const detail=(r.chi_tiet||[]).map(b=>`<div>▪ khối ${b.khối??"—"} ${esc(b.loại||"")} → ${esc(b.target||"")}: `+
      `<b>${b.khớp??0} khớp</b> — ${esc((b.tệp_trúng||[]).slice(0,2).join(", "))}</div>`).join("");
    const cach=(r.cach||[]).map(c=>`<div class="ok">✔ ${esc(c)}</div>`).join("");
    const tools=(r.cong_cu||[]).map(t=>`<span class="badge" style="background:#364fc7">${esc(t)}</span>`).join("");
    const dx=(r.de_xuat||[]).map(x=>`<div class="mut">➤ ${esc(x)}</div>`).join("");
    return `<tr>
      <td><input type="checkbox" data-n="${esc(r.name)}" ${sel.has(r.name)?"checked":""}></td>
      <td><b>${esc(r.name)}</b><div class="cap">${(pt.yếu_tố||[]).map(y=>esc(y.tên)).join(" • ")}</div></td>
      <td class="score">${r.score.toFixed(3)}</td>
      <td><div class="bar"><i style="width:${Math.min(100,r.coverage)}%"></i></div>${r.coverage.toFixed(0)}%</td>
      <td class="hide-sm">${r.matches.toLocaleString("vi-VN")}</td>
      <td>${r.success!=null?`<b class="${r.success>=50?"ok":r.success>=25?"warn":"bad"}">${r.success}%</b>`:"—"}</td>
      <td>${r.caps.map(badge).join("")}</td>
      <td><details><summary>chi tiết</summary><div>
        ${cach}${tools}<div style="margin:4px 0"></div>${detail||"<span class='mut'>không có</span>"}${fines}${dx}
      </div></details></td>
    </tr>`;
  }).join("")||"<tr><td colspan=8 class='mut'>Không có bản vá phù hợp.</td></tr>";
  tb.querySelectorAll("input[type=checkbox]").forEach(ch=>ch.onchange=()=>{
    ch.checked?sel.add(ch.dataset.n):sel.delete(ch.dataset.n);
    localStorage.setItem("plan_sel",JSON.stringify([...sel]));
    renderSel();
  });
}
function renderSel(){
  document.getElementById("selcount").textContent=`Đã chọn: ${sel.size}`;
  document.getElementById("cmdline").textContent=sel.size?
    `python3 patchx_toolkit.py apk-full "${DATA.apk}" --output "${DATA.output}" --patches-file "${DATA.output}/selected_patches.json"`
    :"(chưa chọn patch nào)";
}
document.getElementById("q").addEventListener("input",renderRows);
document.getElementById("sort").addEventListener("change",renderRows);
document.getElementById("btn_suggest").onclick=()=>{
  sel.clear();
  if(DATA.phan_an&&DATA.phan_an.phương_án)sel.add(DATA.phan_an.phương_án);
  DATA.rows.filter(r=>!sel.has(r.name)).slice(0,1).forEach(r=>sel.add(r.name));
  localStorage.setItem("plan_sel",JSON.stringify([...sel]));
  renderRows(); renderSel();
};
document.getElementById("btn_copy").onclick=()=>{
  const cmd=`python3 patchx_toolkit.py apk-full "${DATA.apk}" --output "${DATA.output}" --patches-file "${DATA.output}/selected_patches.json"`;
  navigator.clipboard.writeText(cmd).then(()=>alert("Đã sao chép lệnh!")).catch(()=>alert(cmd));
};
document.getElementById("btn_save").onclick=()=>{
  const blob=new Blob([JSON.stringify({patches:[...sel]},null,2)],{type:"application/json"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);
  a.download="selected_patches.json";a.click();
  alert("Đã tải selected_patches.json — đặt vào thư mục đầu ra rồi chạy lệnh đã sao chép.");
};
renderMeta();renderPlan();renderRows();renderSel();
</script></body></html>""".replace("__DATA__", data_json).replace(
        "__CAPS__", json.dumps(_CAP_COLORS))


def cmd_plan_ui(args):
    """UI tương tác: liệt kê patch + năng lực, thống kê tỷ lệ thành công %,
    người dùng chọn patch → sao chép lệnh apk-full / ghi selected_patches.json."""
    if getattr(args, "output", None):
        out = os.path.abspath(args.output)
    else:
        found = []
        for root, dirs, files in os.walk(TOOLKIT_DIR):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            if "bypass_report.json" in files:
                found.append(os.path.join(root, "bypass_report.json"))
        if not found:
            _log("Chưa có báo cáo plan nào — chạy 'python3 patchx_toolkit.py "
                 "apk-full --dry-run' trước.")
            return 1
        latest = max(found, key=os.path.getmtime)
        out = os.path.dirname(latest)
        _log("Tự dùng thư mục plan mới nhất: %s (dùng --output để ghi đè)"
             % out)
    if not os.path.isdir(out):
        _log("Không tìm thấy thư mục đầu ra (đã chạy apk-full --dry-run chưa?): %s" % out)
        return 1

    def _load(name):
        p = os.path.join(out, name)
        if not os.path.isfile(p):
            _log("Thiếu %s — chạy 'python3 patchx_toolkit.py apk-full --dry-run' trước." % name)
            return None
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as e:
            _log("Lỗi đọc %s: %s" % (name, e))
            return None

    report = _load("bypass_report.json")
    plan = _load("bypass_plan.json")
    candidates = _load("candidates.json")
    if report is None or plan is None or candidates is None:
        return 1
    apk = os.path.abspath(args.apk) if args.apk else ""
    tree = report.get("tree") or plan.get("tree") or ""
    pkg = args.package or ""
    if not pkg and tree and os.path.isfile(os.path.join(tree, "AndroidManifest.xml")):
        try:
            import re as _re
            m = _re.search(r'package="([^"]+)"',
                           open(os.path.join(tree, "AndroidManifest.xml"),
                                encoding="utf-8").read())
            pkg = m.group(1) if m else ""
        except Exception:
            pass
    if not apk:
        base = os.path.basename(tree.rstrip("/")) if tree else ""
        guess = os.path.join(DEFAULT_APKS, base + ".apk")
        apk = guess if os.path.isfile(guess) else ""
        if apk:
            _log("Tự đoán APK gốc: %s (dùng --apk để ghi đè)" % apk)
    html = _render_plan_ui({
        "report": report, "plan": plan, "candidates": candidates,
        "apk": apk, "output": out, "tree": tree, "package": pkg,
    })
    dest = os.path.join(out, "bypass_plan_ui.html")
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(html)
    _log("Đã ghi UI: %s" % dest)
    _log("Mở trong trình duyệt: cd %s && python3 -m http.server 8787"
         " → http://127.0.0.1:8787/bypass_plan_ui.html" % out)
    _log("(hoặc mở thẳng tệp bypass_plan_ui.html bằng trình duyệt).")
    return 0



def cmd_webui(args):
    """Khởi động giao diện web toàn diện cho toàn bộ patchx — chạy ngay trên
    điện thoại qua Termux, mở bằng trình duyệt (hoặc máy ảo Redfinger)."""
    server = os.path.join(TOOLKIT_DIR, "webui", "server.py")
    if not os.path.isfile(server):
        _log("Thiếu máy chủ UI: %s" % server)
        return 1
    url = "http://%s:%d" % (args.host, args.port)
    _log("Khởi động Web UI: %s" % url)
    _log("Dừng: Ctrl+C. Muốn mở từ máy khác/điện thoại: dùng --host 0.0.0.0 "
         "rồi vào http://IP:8787.")
    proc = subprocess.Popen([sys.executable, server, "--host", args.host,
                             "--port", str(args.port)], cwd=TOOLKIT_DIR)
    try:
        if args.open and shutil.which("termux-open-url"):
            subprocess.run(["termux-open-url", url], timeout=8)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    return 0



def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="patchx_toolkit.py",
        description="Patchx Toolkit: phân phối và chạy toàn bộ hoạt động "
                    "thông minh cho toàn bộ patch.")
    sub = parser.add_subparsers(dest="lệnh", metavar="LỆNH")

    p = sub.add_parser("doctor", help="Kiểm tra môi trường và bộ patch đầu vào")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào (mặc định _patchx/upgraded)")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("run", help="Chạy quy trình tự động tinh gọn chuẩn hóa")
    p.add_argument("artifact", nargs="?", default=None,
                   help="Tệp APK/APKS/AAB hoặc thư mục patch (tự động nhận diện)")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--output", default=DEFAULT_OUT,
                   help="Thư mục đầu ra")
    p.add_argument("--quick", action="store_true",
                   help="Chạy nhanh bỏ qua các bước nặng")
    p.add_argument("--with-tests", action="store_true",
                   help="Kích hoạt kiểm thử tự động (mặc định tắt theo quy tắc không tự ý test)")
    p.add_argument("--simulate", action="store_true",
                   help="Kích hoạt mô phỏng toàn diện")
    p.add_argument("--keep-going", action="store_true",
                   help="Tiếp tục chạy dù có bước lỗi")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("package", help="Đóng gói phân phối toolkit + patch")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "dist"),
                   help="Thư mục chứa bản phân phối")
    p.add_argument("--keep", type=int, default=MAX_KEPT_VERSIONS,
                   help="Số bản phân phối giữ lại tối đa (mặc định 3)")
    p.set_defaults(func=cmd_package)

    p = sub.add_parser("list", help="Liệt kê patch theo khả năng và combo bổ trợ")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--limit", type=int, default=80,
                   help="Số combo bổ trợ tối đa hiển thị")
    p.add_argument("--json", default=None,
                   help="Ghi danh sách ra tệp JSON")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("session", help="Chọn và chạy chung một phiên patch")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--tree", default=None,
                   help="Thư mục APK đã giải mã để áp trực tiếp")
    p.add_argument("--select", default=None,
                   help="Tên patch, phân cách dấu phẩy")
    p.add_argument("--select-file", default=None,
                   help="Tệp danh sách patch cần chọn")
    p.add_argument("--interactive", action="store_true",
                   help="Chọn tương tác theo số thứ tự/tên")
    p.add_argument("--output", default=None,
                   help="Thư mục ghi kế hoạch phiên")
    p.add_argument("--dry-run", action="store_true",
                   help="Chỉ xem trước, không ghi cây APK")
    p.add_argument("--no-backup", action="store_true",
                   help="Không sao lưu trước khi sửa")
    p.add_argument("--force", action="store_true",
                   help="Áp lại kể cả đã áp trước đó")
    p.add_argument("--quiet", action="store_true",
                   help="In ít hơn")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("apk-test", help="Chạy thử trên APK thật, rebuild và "
                                        "ghi bài tập cải thiện từ lỗi")
    p.add_argument("patch", nargs="+", help="Các patch cần áp")
    p.add_argument("tree", nargs="?", default=None,
                   help="Thư mục APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "apk_test_out"),
                   help="Thư mục đầu ra báo cáo")
    p.add_argument("--build", action="store_true",
                   help="Chạy `apktool b` sau khi áp patch")
    p.add_argument("--apk-name", default="patched.apk",
                   help="Tên APK đầu ra khi build")
    p.add_argument("--use-aapt1", action="store_true",
                   help="Dùng aapt1 khi build bằng apktool")
    p.add_argument("--aapt", default=None,
                   help="Đường dẫn tới aapt2 thật")
    p.add_argument("--fix-res", action="store_true",
                   help="Tự chuẩn hoá tên resource chứa `$` trước khi build")
    p.add_argument("--dry-run", action="store_true",
                   help="Chỉ xem trước, không áp thật")
    p.set_defaults(func=cmd_apk_test)

    p = sub.add_parser("apk-plan", help="Quét cây APK, mô phỏng và xếp hạng "
                                        "phương án bypass khả thi")
    p.add_argument("tree", nargs="?", default=None,
                   help="Thư mục APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "apk_plan_out"),
                   help="Thư mục đầu ra")
    p.add_argument("--limit", type=int, default=30,
                   help="Số mục tối đa trong mỗi bảng")
    p.add_argument("--limit-combos", type=int, default=150,
                   help="Số combo bổ trợ tối đa để tính điểm")
    p.set_defaults(func=cmd_apk_plan)

    p = sub.add_parser("bench-scan", help="Đo tốc độ quét candidate trên cây "
                                          "APK (nghiệm thu APK lớn < 60s)")
    p.add_argument("tree", nargs="?", default=None,
                   help="Cây APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "outputs", "bench"),
                   help="Thư mục đầu ra báo cáo")
    p.set_defaults(func=cmd_bench_scan)

    p = sub.add_parser("apk-fix-res", help="Chuẩn hoá tên resource chứa ký tự "
                                           "`$` để aapt2 rebuild được")
    p.add_argument("tree", nargs="?", default=None,
                   help="Thư mục APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("--dry-run", action="store_true",
                   help="Chỉ xem trước, không đổi tên")
    p.add_argument("--output", default=None,
                   help="Thư mục ghi resource_fix.json")
    p.set_defaults(func=cmd_apk_fix_res)

    p = sub.add_parser("apk-patch", help="Áp patch lên APK, build, ký và lưu "
                                         "APK đã patch vào outputs/apk/apk-patch/")
    p.add_argument("patch", nargs="*", help="Các patch cần áp")
    p.add_argument("tree", nargs="?", default=None,
                   help="Cây APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("--fast", action="store_true",
                   help="Chế độ Fast-Path: patch trực tiếp DEX/AXML in-place không qua apktool build")
    p.add_argument("--dex-str", action="append", default=[], metavar="OLD=NEW",
                   help="Thay chuỗi UTF-8 trong classes*.dex khi chạy --fast")
    p.add_argument("--dex-hex", action="append", default=[], metavar="TARGET=REPL",
                   help="Thay opcode/bytecode hex trong classes*.dex khi chạy --fast")
    p.add_argument("--axml", action="append", default=[], metavar="OLD=NEW",
                   help="Thay chuỗi trong AndroidManifest.xml khi chạy --fast")
    p.add_argument("--arsc", action="append", default=[], metavar="OLD=NEW",
                   help="Thay chuỗi trong resources.arsc khi chạy --fast")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--no-sign", action="store_true",
                   help="Bỏ qua ký APK")
    p.add_argument("--keystore", default=None,
                   help="Keystore ký APK (mặc định: patchx.keystore, nếu "
                        "không có thì sinh keystore debug trong outputs/apk/apk-patch/)")
    p.add_argument("--ks-pass", default="patchx123",
                   help="Mật khẩu keystore (mặc định: patchx123)")
    p.add_argument("--aapt", default=None,
                   help="Đường dẫn tới aapt2 thật")
    p.add_argument("--bo-cong-ngu-nghia", action="store_true",
                   help="Bỏ qua cổng kiểm tra NGỮ NGHĨA smali (bước 4.5)")
    p.add_argument("--cong-ngu-nghia-all", action="store_true",
                   help="Cổng ngữ nghĩa quét CẢ tệp chưa vá")
    p.set_defaults(func=cmd_apk_patch)

    p = sub.add_parser("apk-debug", help="Chế độ debug-fast: áp patch lên "
                                         "cây có sẵn + xác thực smali, DỪNG "
                                         "(không decode lại/build/ký/cài)")
    p.add_argument("tree", nargs="?", default=None,
                   help="Cây APK đã giải mã (hoặc tệp .apk)")
    p.add_argument("patches", nargs="*",
                   help="Patch chỉ định (nếu rỗng: tự chọn top theo plan)")
    p.add_argument("--patches-file", default=None,
                   help="Tệp danh sách patch chỉ định (JSON hoặc mỗi dòng "
                        "một tên)")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "outputs",
                                                    "apk", "apk-debug"),
                   help="Thư mục đầu ra báo cáo")
    p.add_argument("--top", type=int, default=3,
                   help="Số patch hàng đầu tự chọn theo plan (mặc định 3)")
    p.add_argument("--limit-combos", type=int, default=150,
                   help="Số combo bổ trợ tối đa để tính điểm")
    p.add_argument("--changed-only", action="store_true",
                   help="Xác thực chỉ tệp đổi mới (nhanh hơn nữa)")
    p.add_argument("--bo-cong-ngu-nghia", action="store_true",
                   help="Bỏ qua cổng kiểm tra NGỮ NGHĨA smali")
    p.add_argument("--cong-ngu-nghia-all", action="store_true",
                   help="Cổng ngữ nghĩa quét CẢ tệp chưa vá")
    p.set_defaults(func=cmd_apk_debug)

    p = sub.add_parser("apk-build", help="Build nhanh: xác thực smali → "
                                         "resource → apktool b → ký + verify "
                                         "(không plan/apply)")
    p.add_argument("tree", nargs="?", default=None,
                   help="Cây APK đã giải mã (hoặc tệp .apk)")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "outputs",
                                                    "apk", "apk-build"),
                   help="Thư mục đầu ra (APK + báo cáo)")
    p.add_argument("--no-sign", action="store_true",
                   help="Bỏ qua ký APK")
    p.add_argument("--keystore", default=None,
                   help="Keystore ký APK (mặc định: patchx.keystore)")
    p.add_argument("--ks-pass", default="patchx123",
                   help="Mật khẩu keystore (mặc định: patchx123)")
    p.add_argument("--aapt", default=None,
                   help="Đường dẫn tới aapt2 thật")
    p.add_argument("--changed-only", action="store_true",
                   help="Xác thực chỉ tệp đổi mới (nhanh hơn nữa)")
    p.add_argument("--bo-cong-ngu-nghia", action="store_true",
                   help="Bỏ qua cổng kiểm tra NGỮ NGHĨA smali (bước 1.5) — chỉ dùng "
                        "khi đã hiểu rõ rủi ro VerifyError")
    p.add_argument("--cong-ngu-nghia-all", action="store_true",
                   help="Cổng ngữ nghĩa quét CẢ tệp chưa vá (mặc định chỉ tệp có dấu "
                        "# PATCHX để giữ vòng lặp build nhanh)")
    p.add_argument("--keep-intermediates", action="store_true",
                   help="Giữ lại tệp .unsigned.apk và .aligned.apk sau khi build")
    p.set_defaults(func=cmd_apk_build)

    p = sub.add_parser("apk-full", help="Dây chuyền end-to-end: plan → apply → "
                                        "fix-res → build → zipalign → sign → "
                                        "verify → báo cáo")
    p.add_argument("tree", nargs="?", default=None,
                   help="Cây APK đã giải mã hoặc tệp .apk "
                        "(mặc định: tự chọn trong Apks/)")
    p.add_argument("patches", nargs="*",
                   help="Patch chỉ định (bỏ qua tự chọn top); nếu rỗng thì "
                        "tự chọn theo plan")
    p.add_argument("--patches-file", default=None,
                   help="Tệp danh sách patch chỉ định (JSON {\"patches\": [...]} "
                        "hoặc mỗi dòng một tên) — sinh từ UI plan-ui")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.add_argument("--input", default=DEFAULT_INPUT,
                   help="Thư mục patch đầu vào")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR, "outputs",
                                                    "apk", "apk-full"),
                   help="Thư mục đầu ra (báo cáo + APK)")
    p.add_argument("--top", type=int, default=3,
                   help="Số patch hàng đầu tự chọn theo plan (mặc định 3)")
    p.add_argument("--limit-combos", type=int, default=150,
                   help="Số combo bổ trợ tối đa để tính điểm")
    p.add_argument("--dry-run", action="store_true",
                   help="Chỉ chạy tới bước Plan, không apply/build")
    p.add_argument("--legacy", action="store_true",
                   help="Ép buộc chạy quy trình apktool b truyền thống (dễ phát sinh lỗi aapt2)")
    p.add_argument("--no-build", action="store_true",
                   help="Bỏ qua build (chỉ plan + apply)")
    p.add_argument("--resume", action="store_true",
                   help="Bỏ qua stage đã hoàn thành (plan/apply/build/runtime) "
                        "khi đầu vào không đổi — vòng lặp fix→test nhanh")
    p.add_argument("--no-sign", action="store_true",
                   help="Bỏ qua ký APK")
    p.add_argument("--keystore", default=None,
                   help="Keystore ký APK (mặc định: patchx.keystore, nếu "
                        "không có thì sinh keystore debug)")
    p.add_argument("--ks-pass", default="patchx123",
                   help="Mật khẩu keystore (mặc định: patchx123)")
    p.add_argument("--aapt", default=None,
                   help="Đường dẫn tới aapt2 thật")
    p.add_argument("--runtime", action="store_true",
                   help="Chạy thêm runtime verify (M2/M3) sau khi ký (cần "
                        "device/emulator; không có thì báo thiếu môi trường)")
    p.add_argument("--runtime-wait", type=int, default=8,
                   help="Giây chờ sau khi mở app khi --runtime")
    p.add_argument("--runtime-logcat-lines", type=int, default=2000,
                   help="Số dòng logcat khi --runtime")
    p.add_argument("--runtime-expect", action="append", default=[],
                   help="Regex phải xuất hiện trong logcat để M3 ĐẠT")
    p.add_argument("--runtime-forbid", action="append", default=[],
                   help="Regex không được xuất hiện trong logcat để M3 ĐẠT")
    p.add_argument("--bo-cong-ngu-nghia", action="store_true",
                   help="Bỏ qua cổng kiểm tra NGỮ NGHĨA smali (bước 4.5)")
    p.add_argument("--cong-ngu-nghia-all", action="store_true",
                   help="Cổng ngữ nghĩa quét CẢ tệp chưa vá")
    p.set_defaults(func=cmd_apk_full)

    p = sub.add_parser("apk-runtime", help="Runtime verify M2/M3 (Đợt C): "
                                           "cài, mở, logcat, bắt crash")
    p.add_argument("apk", nargs="?", default=None,
                   help="APK đã build/ký (mặc định: APK ký mới nhất trong "
                        "outputs/apk/apk-patch/)")
    p.add_argument("--device", default=None,
                   help="Device adb cụ thể (vd 100.64.170.99:5555) — mặc "
                        "định dùng device đầu tiên")
    p.add_argument("--package", default=None,
                   help="Package name (mặc định: tự đọc aapt2 dump badging)")
    p.add_argument("--activity", default=None,
                   help="Activity khởi động (mặc định: launchable-activity)")
    p.add_argument("--connect", default=None,
                   help="Kết nối máy ảo trước khi verify: HOST:PORT (vd "
                        "127.0.0.1:12345 của Redfinger/VMOS)")
    p.add_argument("--scan-local", action="store_true",
                   help="Tự quét + kết nối các cổng adb phổ biến trên "
                        "127.0.0.1 (5555/5557/5559/5561/21503/26944/26945)")
    p.add_argument("--wait", type=int, default=8,
                   help="Giây chờ sau khi mở app (mặc định 8)")
    p.add_argument("--logcat-lines", type=int, default=2000,
                   help="Số dòng logcat đọc lại (mặc định 2000 — máy ảo "
                        "spam log nhiều)")
    p.add_argument("--no-capture-net", action="store_true",
                   help="Tắt chụp kết nối mạng trước/sau launch "
                        "(mặc định bật — /proc/net/tcp)")
    p.add_argument("--expect", action="append", default=[],
                   help="Regex phải xuất hiện trong logcat để M3 ĐẠT "
                        "(có thể lặp)")
    p.add_argument("--forbid", action="append", default=[],
                   help="Regex không được xuất hiện trong logcat để M3 ĐẠT "
                        "(có thể lặp)")
    p.add_argument("--scenario", default=None,
                   help="Kịch bản M3 (scenario.json): launch/wait/tap/input/"
                        "navigate/assert_*")
    p.add_argument("--scenario-out", default=None,
                   help="Thư mục lưu ảnh chụp màn hình kịch bản (mặc định "
                        "cùng thư mục --output)")
    p.add_argument("--output", default=os.path.join(TOOLKIT_DIR,
                                                    "apk_runtime_out"),
                   help="Thư mục đầu ra báo cáo")
    p.add_argument("--no-auto-install", action="store_true",
                   help="Không tự cài công cụ thiếu")
    p.set_defaults(func=cmd_apk_runtime)

    p = sub.add_parser("plan-ui", help="Trang UI tương tác: liệt kê patch + "
                                       "năng lực, tỷ lệ thành công phần "
                                       "trăm, chọn "
                                       "patch → sao chép lệnh apk-full")
    p.add_argument("--output", default=None,
                   help="Thư mục chứa báo cáo plan (mặc định: thư mục "
                        "apk-full mới nhất có bypass_report.json)")
    p.add_argument("--apk", default=None,
                   help="Đường dẫn APK gốc (dùng trong lệnh apk-full; mặc "
                        "định đoán theo tên cây)")
    p.add_argument("--package", default=None,
                   help="Package name hiển thị (mặc định: tự đọc manifest)")
    p.set_defaults(func=cmd_plan_ui)

    p = sub.add_parser("install-deps", help="Cài tự động các công cụ còn thiếu "
                                            "(apktool, zipalign, apksigner, ...)")
    p.set_defaults(func=cmd_install_deps)

    p = sub.add_parser("webui", help="Khởi động giao diện web toàn diện cho "
                                     "toàn bộ patchx (mở trên điện thoại)")
    p.add_argument("--host", default="127.0.0.1",
                   help="Địa chỉ nghe (127.0.0.1 là máy này; 0.0.0.0 mở "
                        "mạng ngoài)")
    p.add_argument("--port", type=int, default=8787,
                   help="Cổng phục vụ (mặc định 8787)")
    p.add_argument("--open", action="store_true",
                   help="Tự mở trình duyệt nếu có termux-open-url")
    p.set_defaults(func=cmd_webui)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
