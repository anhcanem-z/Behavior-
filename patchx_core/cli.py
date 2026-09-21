# -*- coding: utf-8 -*-
"""Giao diện dòng lệnh của patchx — toàn bộ thông báo bằng tiếng Việt."""
from .smali_validate import smali_files


import argparse
import glob
import json
import os
import subprocess
import sys
import time
import zipfile

from . import __version__
from .parser import parse_patch_file
from .audit import LEVEL_ERROR, LEVEL_WARN
from .behavior.flows import (available_flows, flow_alias_for_behavior,
                            get_flow_definition, normalize_flow_name)
from .behavior.ontology import BEHAVIORS

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class C:
    """Bảng mã màu ANSI trực quan cho giao diện dòng lệnh."""
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    BG_BLU = "\033[44;97m"
    BG_MAG = "\033[45;97m"
    BG_RED = "\033[41;97m"
    BG_GRN = "\033[42;30m"


def _load_patches(root, recursive=False):
    """Nạp mọi patch (zip) trong thư mục; xử lý zip lồng nhau."""
    patches = []
    from .indexer import _iter_zips
    from .audit import parse_nested_zip
    for z in _iter_zips(root, recursive=recursive):
        try:
            patches.append(parse_patch_file(z))
        except ValueError:
            patches.extend(parse_nested_zip(z))
        except Exception as e:
            print("[patchx] bỏ qua %s: %s" % (os.path.basename(z), e))
    return patches


def cmd_scan(args):
    from .indexer import scan_dir
    records = scan_dir(args.thu_muc, recursive=args.recursive)
    dupes = [r for r in records if r.get("dupe_id")]
    if dupes:
        print("[patchx] %d file trùng nội dung (%d nhóm)" % (
            len(dupes), len({r["dupe_id"] for r in dupes})))
    print("Tổng patch: %d" % len(records))
    print("%-38s %-18s %8s %6s %6s %s" % (
        "Patch", "Nhóm", "Engine", "Khối", "Tài nguyên", "Vấn đề"))
    for r in records:
        n_sec = sum(r["sections"].values()) if r["sections"] else 0
        problems = "LỖI" if r["parse_error"] else (
            str(len(r["issues"])) if r["issues"] else "—")
        print("%-38s %-18s %8s %6d %6d %s" % (
            r["name"], r["tag"], r["engine_ver"] or "—",
            n_sec, len(r["assets"]), problems))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "patches": records}, fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", args.o)


def cmd_index(args):
    from .indexer import write_index
    out = args.o or os.path.join(BASE_DIR, "outputs", "scan")
    ip, rp = write_index(args.thu_muc, out, name=args.ten,
                         recursive=args.recursive)
    print("Đã ghi:", ip)
    print("Đã ghi:", rp)


def cmd_dupes(args):
    from .indexer import scan_dir, dedupe_report
    records = scan_dir(args.thu_muc, recursive=args.recursive)
    groups = dedupe_report(records)
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "scan")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "dupes.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "root": args.thu_muc, "total": len(records),
                   "groups": groups}, fh, ensure_ascii=False, indent=2)
    lines = ["# Báo cáo trùng lặp nội dung", "",
             "- Tổng file: %d" % len(records),
             "- Nhóm trùng: %d" % len(groups), ""]
    if not groups:
        lines.append("Không phát hiện trùng lặp (theo hash patch.txt).")
    for g in groups:
        lines.append("## Nhóm %d — %d file (bản chuẩn: %s)" % (
            g["nhóm"], g["số_file"], g["bản_chuẩn"]))
        lines.append("")
        lines.append("- sha256: `%s`" % g["sha256"])
        lines.append("- Bản chuẩn (nhỏ nhất): `%s`" % g["bản_chuẩn"])
        for d in g["bản_trùng"]:
            lines.append("- Bản trùng: `%s`" % d)
        lines.append("")
    rp = os.path.join(out_dir, "dupes_report.md")
    with open(rp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("[patchx] %d nhóm trùng từ %d file" % (len(groups), len(records)))
    for g in groups:
        print("  Nhóm %d: %s (+ %d bản trùng)" % (
            g["nhóm"], g["bản_chuẩn"], len(g["bản_trùng"])))
    print("Đã ghi:", os.path.join(out_dir, "dupes_report.md"))
    return 0


def cmd_manifest(args):
    from .indexer import scan_dir, dedupe_report
    root = os.path.abspath(args.thu_muc)
    records = scan_dir(root, recursive=True)
    folders = {}
    empty = []
    for d in sorted(os.listdir(root)):
        if not os.path.isdir(os.path.join(root, d)) or d.startswith("."):
            continue
        zips = [r for r in records if r["path"].startswith(d + os.sep)]
        if zips:
            folders[d] = {"files": len(zips),
                          "size": sum(r["size"] for r in zips)}
        else:
            empty.append(d)
    manifest = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": root,
        "total_files": len(records),
        "total_size": sum(r["size"] for r in records),
        "files": {r["path"]: r["sha256"] for r in records},
        "folders": folders,
        "empty_folders": empty,
        "dupe_groups": dedupe_report(records),
    }
    out = args.o or os.path.join(BASE_DIR, "outputs", "scan", "MANIFEST.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    print("[patchx] MANIFEST: %d file, %d thu mức, %d thu mức trong, "
          "%d nhóm trung" % (len(records), len(folders), len(empty),
                             len(manifest["dupe_groups"])))
    if empty:
        print("  Thư mục trống: %s" % ", ".join(empty))
    print("Đã ghi:", out)
    return 0


def cmd_verify_manifest(args):
    """T5: xác minh kho theo MANIFEST.json — phát hiện file bị sửa/thêm/bớt."""
    from .indexer import scan_dir
    root = os.path.abspath(args.thu_muc)
    mpath = args.manifest or os.path.join(root, "_patchx", "MANIFEST.json")
    if not os.path.isfile(mpath):
        print("[patchx] Khong thay MANIFEST.json — chay `patchx manifest` "
              "trước.")
        return 1
    old = json.load(open(mpath, encoding="utf-8"))
    old_files = old.get("files", {})
    records = scan_dir(root, recursive=True, use_cache=False)
    cur = {r["path"]: r["sha256"] for r in records}
    added = sorted(set(cur) - set(old_files))
    removed = sorted(set(old_files) - set(cur))
    modified = sorted(p for p in set(old_files) & set(cur)
                      if old_files[p] != cur[p])
    ok = not (added or removed or modified)
    print("[patchx] verify-manifest: %d file, thêm %d, xóa %d, sửa %d%s"
          % (len(cur), len(added), len(removed), len(modified),
             "" if ok else " — ⚠ KHO ĐÃ BỊ THAY ĐỔI"))
    for p in added[:10]:
        print("  + %s" % p)
    for p in removed[:10]:
        print("  - %s" % p)
    for p in modified[:10]:
        print("  ~ %s" % p)
    return 0 if ok else 2


def cmd_report(args):
    from .indexer import scan_dir, dedupe_report
    import html as html_mod
    records = scan_dir(args.thu_muc, recursive=args.recursive)
    dupes = dedupe_report(records)
    cov_apk = getattr(args, "apk", None)
    rows = []
    n_khop = 0
    for idx, r in enumerate(records):
        n_sec = sum(r["sections"].values()) if r["sections"] else 0
        issues = "LỖI: " + r["parse_error"] if r["parse_error"] \
            else "; ".join(r["issues"]) if r["issues"] else ""
        dupe = "Nhóm %d" % r["dupe_id"] if r.get("dupe_id") else ""
        preview = ""
        cov_cell = "—"
        if cov_apk:
            from .parser import parse_patch_file
            from .advisor import coverage_patch
            try:
                p = parse_patch_file(os.path.join(args.thu_muc, r["path"]))
                cov = coverage_patch(p, cov_apk)
                cov_cell = "%s%% (%d)" % (cov.get("tỷ_lệ", 0),
                                          cov.get("quy_tắc_khớp", 0))
                if cov.get("quy_tắc_khớp", 0) > 0:
                    n_khop += 1
                rules = []
                for sec in p.sections:
                    m = sec.get("MATCH")
                    if not m:
                        continue
                    rules.append((m, sec.get("REPLACE") or ""))
                    if len(rules) >= 3:
                        break
                if rules:
                    lines = []
                    for m, rp in rules:
                        lines.append('<span class="del">- %s</span><br>'
                                     '<span class="add">+ %s</span>'
                                     % (html_mod.escape(str(m)[:300]),
                                        html_mod.escape(str(rp)[:300])))
                    preview = ("<h4>Preview diff (toi da 3 quy tac)</h4>"
                               "<pre>%s</pre>" % "<br>".join(lines))
            except Exception as e:
                preview = ("<p class='bad'>Lỗi đọc patch: %s</p>"
                           % html_mod.escape(str(e)))
        data = " ".join([r["name"], r["tag"] or "", r["author"] or "",
                         issues, dupe, cov_cell]).lower()
        rows.append(
            '<tr class="prow" data-s="%s"><td><button class="pv" '
            'onclick="tg(%d)">Xem</button> %s</td><td>%s</td><td>%s</td>'
            "<td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>"
            '<tr id="pv%d" style="display:none"><td colspan="8">%s</td></tr>'
            % (html_mod.escape(data), idx, html_mod.escape(r["name"]),
               html_mod.escape(r["tag"] or "—"),
               html_mod.escape(r["engine_ver"] or "—"),
               html_mod.escape(r["author"] or "—"), n_sec,
               len(r["assets"]), dupe, cov_cell, idx, preview))
    dupe_rows = "".join(
        "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            g["nhóm"], g["số_file"], g["bản_chuẩn"],
            ", ".join(g["bản_trùng"])) for g in dupes)
    total_size = sum(r["size"] for r in records)
    khop_line = ("<p>Khớp APK <code>%s</code>: <b>%d</b>/%d patch</p>"
                 % (html_mod.escape(cov_apk), n_khop, len(records))
                 if cov_apk else "")
    html = """<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8">
<title>patchx — Báo cáo bộ sưu tập</title>
<style>
body{font-family:system-ui,sans-serif;margin:24px;color:#222}
table{border-collapse:collapse;width:100%%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}
th{background:#f2f2f2}h1{font-size:22px}h2{font-size:18px;margin-top:28px}
.bad{color:#b00020}.ok{color:#0a7d32}.del{color:#b00020}
.add{color:#0a7d32}pre{background:#fafafa;padding:8px;font-size:12px;
white-space:pre-wrap;word-break:break-all}
button.pv{font-size:11px;margin-right:6px;cursor:pointer}
input#q{width:100%%;padding:8px;font-size:14px;margin-bottom:12px;
box-sizing:border-box}
</style></head><body>
<h1>patchx — Báo cáo bộ sưu tập patch</h1>
<p>Thời gian: %s · Thư mục: <code>%s</code></p>
<p>Tổng: <b>%d</b> file · <b>%s</b> · <b>%d</b> nhóm trùng nội dung</p>
%s
<input id="q" placeholder="Tìm nhanh theo tên / nhóm / tác giả / vấn đề...">
<h2>Danh sách patch</h2>
<table><tr><th>Patch</th><th>Nhóm</th><th>Engine</th><th>Tác giả</th>
<th>Khối</th><th>Tài nguyên</th><th>Trùng</th><th>Độ phủ</th></tr>
%s</table>
<h2>Nhóm trùng nội dung</h2>
<table><tr><th>Nhóm</th><th>Số file</th><th>Bản chuẩn</th><th>Bản trùng</th></tr>
%s</table>
<script>
function tg(id){var el=document.getElementById('pv'+id);
if(el){el.style.display=el.style.display==='none'?'table-row':'none';}}
var q=document.getElementById('q');
if(q){q.addEventListêner('input',function(){
var t=q.value.toLowerCase();
document.querySelectorAll('tr.prow').forEach(function(tr){
tr.style.display=tr.getAttribute('data-s').indexOf(t)>-1?'':'none';});});}
</script>
</body></html>""" % (
        time.strftime("%Y-%m-%d %H:%M:%S"), html_mod.escape(args.thu_muc),
        len(records), _fmt_size(total_size), len(dupes), khop_line,
        "".join(rows), dupe_rows)
    out = args.o or os.path.join(BASE_DIR, "outputs", "scan", "report.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(html)
    print("[patchx] Đã tạo báo cáo HTML:", out)
    return 0


def _fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


def cmd_ci(args):
    """T7: dây chuyền CI — audit → upgrade → optimize → combo-auto → simulate."""
    from argparse import Namespace
    from .indexer import scan_dir, dedupe_report
    from .audit import audit_patch, LEVEL_ERROR, upgrade_zip
    from .simulate import run_simulation
    root = os.path.abspath(args.thu_muc)
    wd = args.o or os.path.join(BASE_DIR, "outputs", "ci")
    os.makedirs(wd, exist_ok=True)
    t0 = time.monotonic()

    def stats(d):
        recs = scan_dir(d, recursive=True)
        n_err = 0
        for z in sorted(glob.glob(os.path.join(d, "*.zip"))):
            try:
                p = parse_patch_file(z)
                for f in audit_patch(p):
                    if f.level == LEVEL_ERROR:
                        n_err += 1
            except Exception:
                n_err += 1
        return {"files": len(recs),
                "size": sum(r["size"] for r in recs),
                "audit_lỗi": n_err,
                "nhóm_trùng": len(dedupe_report(recs))}

    before = stats(root)
    up = os.path.join(wd, "upgraded")
    os.makedirs(up, exist_ok=True)
    n_up = 0
    for z in sorted(glob.glob(os.path.join(root, "*.zip"))):
        try:
            upgrade_zip(z, up, dry_run=False,
                        header="Bản nâng cấp bởi CI patchx")
            n_up += 1
        except Exception:
            pass
    after_up = stats(up)
    opt = os.path.join(wd, "optimized")
    cmd_optimize(Namespace(thu_muc=up, o=opt))
    n_opt = len(glob.glob(os.path.join(opt, "*.patch")))
    cb = os.path.join(wd, "combos_auto")
    cmd_combo(Namespace(thu_muc=up, o=cb, auto=True, only=None,
                        recursive=False, apk=None))
    n_combo = len(glob.glob(os.path.join(cb, "*.patch")))
    sim = run_simulation(up, quick=args.quick, dex_runner=None,
                         dex_timeout=60, apk_tree=None)
    sim_s = {"đạt": sim["đạt"], "thất_bại": sim["thất_bại"],
             "bỏ_qua": sim["bỏ_qua"], "lỗi": sim["lỗi"],
             "tỷ_lệ_đạt": sim["tỷ_lệ_đạt"]}
    golden_rc = None
    if getattr(args, "golden", False):
        golden_rc = cmd_golden(Namespace(o=os.path.join(wd, "golden"), fw=True))
    total_s = round(time.monotonic() - t0, 1)
    report = {
        "thời_gian": time.strftime("%Y-%m-%d %H:%M:%S"),
        "thu_muc": root, "tong_giay": total_s,
        "trước": before, "sau_nâng_cấp": after_up,
        "số_patch_nâng_cấp": n_up,
        "số_tệp_optimize": n_opt, "số_combo_tự_động": n_combo,
        "simulate": sim_s,
        "golden_gate": (0 if golden_rc == 0 else 1) if golden_rc is not None else None,
    }
    with open(os.path.join(wd, "ci_report.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    lines = ["# Báo cáo CI patchx", "",
             "- Thời gian: %s" % report["thời_gian"],
             "- Thư mục: `%s`" % root,
             "- Tổng thời gian: %s giây" % total_s, "",
             "## Trước (kho gốc)",
             "- File: %(files)d · Dung luong: %(size)d byte · "
             "Loi audit: %(audit_lỗi)d · Nhóm trung: %(nhóm_trùng)d"
             % before, "",
             "## Sau (upgrade → optimize → combo)",
             "- File sau nang cap: %(files)d · Loi audit: %(audit_lỗi)d · "
             "Nhóm trung: %(nhóm_trùng)d" % after_up,
             "- Patch nâng cấp: %d · Tệp optimize: %d · Combo tự động: %d"
             % (n_up, n_opt, n_combo), "",
             "## Mô phỏng (bộ nâng cấp)",
             "- DAT %(đạt)d · THAT-BAI %(thất_bại)d · BO-QUA %(bỏ_qua)d · "
             "LỖI %(lỗi)d · Ty le đạt %(tỷ_lệ_đạt)s%%" % sim_s, ""]
    with open(os.path.join(wd, "ci_report.md"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(lines))
    print("[patchx] CI: %d file → %d file, lỗi audit %d → %d, "
          "%d combo, mo phong %d%% đạt (%.1fs)" % (
              before["files"], after_up["files"], before["audit_lỗi"],
              after_up["audit_lỗi"], n_combo, sim["tỷ_lệ_đạt"], total_s))
    print("Đã ghi:", os.path.join(wd, "ci_report.md"))
    ok = after_up["audit_lỗi"] == 0 and sim["thất_bại"] == 0
    if golden_rc is not None:
        ok = ok and golden_rc == 0
    return 0 if ok else 2


def cmd_golden(args):
    """P10 — Golden Build gate: chỉ chạy hai golden test, trả 1 nếu fail."""
    import importlib.util
    test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "tests", "run_tests.py")
    if getattr(args, "fw", False):
        os.environ["PATCHX_GOLDEN_FW"] = "1"
    spec = importlib.util.spec_from_file_location("patchx_golden_tests",
                                                   test_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    start = len(mod.RESULTS)
    mod.test_golden_rebuild()
    mod.test_golden_framework_res()
    checks = mod.RESULTS[start:]
    ok = sum(1 for _, passed, _ in checks if passed)
    total = len(checks)
    report = {
        "thời_gian": time.strftime("%Y-%m-%d %H:%M:%S"),
        "golden_build_pass": ok,
        "golden_build_total": total,
        "chi_tiết": [{"tên": name, "đạt": bool(passed), "chi_tiết": detail}
                     for name, passed, detail in checks],
    }
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "golden")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "golden_gate.json"), "w",
              encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    for name, passed, detail in checks:
        print("  [%s] %s — %s" % ("PASS" if passed else "FAIL", name,
                                  detail or ""))
    print("[patchx] Golden gate: %d/%d đạt — %s" % (
        ok, total, "PASS" if ok == total else "FAIL"))
    return 0 if ok == total else 1


def cmd_validate(args):
    """P9 — Xác thực cây APK đã giải mã."""
    from patchx_core.smali_validate import validate_file, validate_tree_v2

    if not args.cay:
        print("[patchx] Thiếu cây APK đã giải mã.")
        return 2
    if not os.path.isdir(args.cay):
        print("[patchx] Không phải thư mục cây: %s" % args.cay)
        return 2
    if args.files:
        bad = 0
        for rel in args.files:
            p = os.path.join(args.cay, rel)
            if not os.path.isfile(p):
                print("[FAIL] %s: không tồn tại" % rel)
                bad += 1
                continue
            with open(p, encoding="utf-8", errors="replace") as fh:
                errs, _nm = validate_file(fh.read())
            if errs:
                print("[FAIL] %s: %s" % (rel, "; ".join(errs)))
                bad += 1
            else:
                print("[PASS] %s" % rel)
        return 1 if bad else 0
    t0 = time.monotonic()
    r = validate_tree_v2(args.cay, level=args.level,
                         changed_only=args.changed_only,
                         max_files=getattr(args, "max_files", None))
    secs = time.monotonic() - t0
    print("[patchx] Xac thuc [%s]: %d/%d tệp, %d method, "
          "%d lỗi, %d canh bao (%.1fs)%s"
          % (r["level"], r["files"], r["files"], r["methods"],
             len(r["errors"]), len(r["warnings"]), secs,
             " — chỉ tệp đổi mới" if args.changed_only else ""))
    shown = 0
    for f in r["findings"]:
        if f["mức"] != "lỗi" and args.level == "RELEASE":
            pass
        if shown >= args.limit:
            break
        shown += 1
        print("[%s] %s%s: %s"
              % ("FAIL" if f["mức"] == "lỗi" else "WARN",
                 f["loại"], (" " + f["path"]) if f["path"] else "",
                 f["nội_dung"]))
    if len(r["findings"]) > shown:
        print("[patchx] … còn %d finding nữa"
              % (len(r["findings"]) - shown))
    if r["errors"]:
        print("[patchx] %d lỗi (hiện %d)"
              % (len(r["errors"]), min(args.limit, shown)))
        return 1
    return 0


def cmd_apk_prepare(args):
    import shutil as _sh
    apktool = _sh.which("apktool")
    if not apktool:
        print("[patchx] Thiếu công cụ apktool — cài bằng: pkg install apktool")
        return 0
    out = args.o or args.apk + ".decoded"
    os.makedirs(out, exist_ok=True)
    print("[patchx] Giải mã APK bằng apktool (có thể mất vài phút)...")
    cmd = [apktool, "d", "-f", "-o", out, args.apk]
    try:
        subprocess.run(cmd, check=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print("[patchx] apktool quá thời gian (%ss)" % args.timeout)
        return 1
    except (OSError, subprocess.CalledProcessError) as e:
        print("[patchx] apktool thất bại: %s" % e)
        return 1
    print("[patchx] Đã giải mã vào:", out)
    try:
        import hashlib as _hl
        cdir = os.path.join(out, ".patchx", "cache")
        os.makedirs(cdir, exist_ok=True)
        sha = _hl.sha256()
        with open(args.apk, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
        with open(os.path.join(cdir, "decode.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"apk_sha256": sha.hexdigest(),
                       "apk": os.path.abspath(args.apk),
                       "time": time.strftime("%Y-%m-%d %H:%M:%S")},
                      fh, ensure_ascii=False, indent=1)
    except OSError as e:
        print("[patchx] Cảnh báo: không ghi được cache decode: %s" % e)
    return 0


def cmd_audit(args):
    from .audit import audit_patch
    patches = _load_patches(args.thu_muc, recursive=args.recursive)
    out = []
    lines = ["# Báo cáo kiểm tra kiến trúc patch", "",
             "- Thời gian: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
             "- Số patch: %d" % len(patches), ""]
    n_err = n_warn = n_fix = 0
    for p in patches:
        findings = audit_patch(p)
        rec = {"patch": p.name, "source": p.source, "findings":
               [f.to_dict() for f in findings]}
        out.append(rec)
        lines.append("## %s" % p.name)
        if not findings:
            lines.append("- Không phát hiện vấn đề.")
        for f in findings:
            lines.append("- [%s] %s — %s%s" % (
                f.code, {"lỗi": "LỖI", "cảnh-báo": "CẢNH BÁO",
                         "thông-tin": "thông tin"}[f.level],
                f.message, " (tự sửa được)" if f.fixable else ""))
            if f.level == LEVEL_ERROR:
                n_err += 1
            elif f.level == LEVEL_WARN:
                n_warn += 1
            if f.fixable:
                n_fix += 1
        lines.append("")
    lines.insert(3, "- Lỗi: %d, cảnh báo: %d, vấn đề tự sửa được: %d"
                 % (n_err, n_warn, n_fix))
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "audit")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, "audit")
    with open(base + ".json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "total": len(patches), "errors": n_err,
                   "warnings": n_warn, "fixable": n_fix,
                   "patches": out}, fh, ensure_ascii=False, indent=2)
    with open(base + "_report.md", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print("Đã ghi:", base + ".json")
    print("Đã ghi:", base + "_report.md")


def cmd_upgrade(args):
    from .audit import upgrade_zip
    out_dir = args.o or os.path.join(args.thu_muc, "_patchx", "upgraded")
    header = ("Ban nang cap boi patchx %s — chuan hoa kien truc, "
              "noi dung giu nguyen goc" % __version__)
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for z in sorted(glob.glob(os.path.join(args.thu_muc, "*.zip"))):
        try:
            res = upgrade_zip(z, out_dir, dry_run=args.dry_run, header=header)
            for src, patch, out_name in res:
                results.append({"source": src, "output": out_name,
                                "sections": len(patch.sections)})
                print("[patchx] %s -> %s (%d khối)" % (
                    os.path.basename(src), out_name, len(patch.sections)))
        except Exception as e:
            print("[patchx] LỖI khi nâng cấp %s: %s"
                  % (os.path.basename(z), e))
    if not args.dry_run:
        with open(os.path.join(out_dir, "upgrade_summary.json"), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "total": len(results), "results": results},
                      fh, ensure_ascii=False, indent=2)
        print("Đã nâng cấp %d patch vào %s" % (len(results), out_dir))
    else:
        print("(dry-run) Sẽ nâng cấp %d patch vào %s" % (len(results), out_dir))


def _components(patches):
    from .optimizer import find_conflicts
    conflicts = find_conflicts(patches)
    conf_sets = [set(c["patches"]) for c in conflicts]

    def clashes(p, group):
        for q in group:
            for cs in conf_sets:
                if p.name in cs and q.name in cs:
                    return True
        return False

    groups = []
    for p in patches:
        placed = False
        for g in groups:
            if not clashes(p, g):
                g.append(p)
                placed = True
                break
        if not placed:
            groups.append([p])
    return groups, conflicts


def cmd_optimize(args):
    from .optimizer import target_similarity, cluster_tag, merge_patches, render_patch_text, find_conflicts
    patches = _load_patches(args.thu_muc)
    by_tag = {}
    for p in patches:
        by_tag.setdefault(cluster_tag(p.name), []).append(p)

    components = []
    conflicts_all = []
    for tag, group in sorted(by_tag.items()):
        comps, conflicts = _components(group)
        for comp in comps:
            components.append({"tag": tag, "patches": comp})
        conflicts_all.extend(conflicts)

    global_conflicts = find_conflicts(patches)
    global_conf_sets = [set(c["patches"]) for c in global_conflicts]

    def clash(a, b):
        na = {p.name for p in a["patches"]}
        nb = {p.name for p in b["patches"]}
        return any((na & cs) and (nb & cs) for cs in global_conf_sets)

    merged_any = True
    merge_pairs = []
    while merged_any:
        merged_any = False
        best = None
        for i in range(len(components)):
            for j in range(i + 1, len(components)):
                if clash(components[i], components[j]):
                    continue
                sim = target_similarity(components[i]["patches"],
                                        components[j]["patches"])
                if sim >= 0.7 and (best is None or sim > best[0]):
                    best = (sim, i, j)
        if best:
            sim, i, j = best
            merge_pairs.append("%s + %s (độ tương đồng %.0f%%)" % (
                components[i]["tag"], components[j]["tag"], sim * 100))
            components[i]["patches"].extend(components[j]["patches"])
            components[i]["tag"] += "+" + components[j]["tag"]
            components.pop(j)
            merged_any = True

    out_dir = args.o or os.path.join(args.thu_muc, "_patchx", "optimized")
    os.makedirs(out_dir, exist_ok=True)
    total_in = sum(len(c["patches"]) for c in components)
    total_rules_in = 0
    saved_rules = 0
    stats = {"patches": total_in, "files": [], "merged_across_groups":
             merge_pairs, "saved_rules": 0}
    used_names = {}
    for idx, comp in enumerate(components, 1):
        tag = comp["tag"]
        merged = merge_patches(comp["patches"], tag)
        rules_in = sum(1 for p in comp["patches"] for s in p.sections
                       if s.type not in ("MIN_ENGINE_VER", "AUTHOR", "PACKAGE"))
        total_rules_in += rules_in
        rules_out = len(merged.sections)
        saved = rules_in - rules_out
        saved_rules += saved
        base = tag + ".patch"
        used_names[base] = used_names.get(base, 0) + 1
        fname = "%s_%d.patch" % (tag, used_names[base]) if used_names[base] > 1 else base
        fpath = os.path.join(out_dir, fname)
        with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_patch_text(merged, header=(
                "Gộp tối ưu bởi patchx: %s" % tag)))
        stats["files"].append({
            "input_patches": len(comp["patches"]),
            "rules_in": rules_in, "rules_out": rules_out,
            "saved_rules": saved,
            "file": fname,
            "source_patches": [p.name for p in comp["patches"]]})
        print("[patchx] %s -> %s (%d khối từ %d patch, gộp trùng %d)" % (
            tag, fname, rules_out, len(comp["patches"]), saved))
    stats["saved_rules"] = saved_rules
    stats["conflicts"] = len(conflicts_all)
    if conflicts_all:
        with open(os.path.join(out_dir, "_conflicts.json"), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump(conflicts_all, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "_stats.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=2)
    print("Đã gộp %d patch -> %d tệp, gộp trùng %d khối, %d xung đột tách riêng"
          % (total_in, len(components), saved_rules, len(conflicts_all)))
    if merge_pairs:
        print("Gộp chéo nhóm giống nhau (%d cặp):" % len(merge_pairs))
        for m in merge_pairs[:12]:
            print("  - " + m)
        if len(merge_pairs) > 12:
            print("  ... và %d cặp nữa" % (len(merge_pairs) - 12))


def cmd_apply(args):
    if getattr(args, "dag", False):
        from .pipeline_registry import get_pipeline_registry
        reg = get_pipeline_registry()
        res = reg.run_pipeline("auto", args.cay_apk)
        return 0 if res.success else 1

    from .engine import Engine
    patches = [parse_patch_file(p) for p in args.patch]
    engine = Engine(args.cay_apk, dry_run=args.dry_run, backup=not args.no_backup,
                    force=args.force, no_dex=not args.dex_runner,
                    dex_runner=args.dex_runner, strict=args.strict,
                    quiet=args.quiet, reset_state=args.reset_state,
                    dex_allow_extra=args.dex_allow or ())
    for p in patches:
        print("[patchx] Áp patch: %s" % p.name)
        engine.apply(p)
    engine.finalize()

    if not args.dry_run and not engine.errors:
        try:
            from .learn import record_success, categorize
            pkg = engine.package or os.path.basename(os.path.abspath(args.cay_apk))
            record_success(
                BASE_DIR,
                {
                    "package": pkg,
                    "danh_mục": categorize(pkg),
                    "combo": [p.name for p in patches],
                    "target_tree": args.cay_apk,
                    "applied_count": len(patches),
                }
            )
            print("[patchx] Đã tự động cập nhật tri thức thành công vào kho combos_success.json")
        except Exception:
            pass

    if engine.errors and args.strict:
        return 1
    return 0


def cmd_test(args):
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    tests = os.path.join(here, "..", "tests", "run_tests.py")
    spec = importlib.util.spec_from_file_location("run_tests", tests)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main()


def cmd_axml_patch(args):
    """Patch chuỗi nhị phân AXML/ARSC in-place, có dry-run và backup."""
    from .axml_editor import (
        inspect_binary, replace_string_inplace,
        inspect_manifest_security, bypass_network_security_config,
        replace_permission
    )
    try:
        if getattr(args, "inspect_security", False):
            sec = inspect_manifest_security(args.binary)
            print("[axml-patch] BẢO MẬT MANIFEST: %s (%d chuỗi)" % (args.binary, sec["total_strings"]))
            print("  networkSecurityConfig : %s" % sec["has_network_security_config"])
            print("  usesCleartextTraffic  : %s" % sec["has_uses_cleartext_traffic"])
            print("  debuggable            : %s" % sec["has_debuggable"])
            print("  permissions (%d)       : %s" % (len(sec["permissions"]), ", ".join(sec["permissions"][:5])))
            if len(sec["permissions"]) > 5:
                print("                          ... và %d quyền khác" % (len(sec["permissions"]) - 5))
            return 0

        backup = args.backup or args.binary + ".bak"

        if getattr(args, "bypass_nsc", False):
            if args.dry_run:
                print("[axml-patch] DRY-RUN bypass networkSecurityConfig trên %s" % args.binary)
                return 0
            res = bypass_network_security_config(args.binary, backup_path=backup)
            print("[axml-patch] Bypass networkSecurityConfig: %d hit, backup: %s" % (res["hits"], res["backup"] or "không tạo"))
            return 0

        if getattr(args, "replace_perm", None):
            item = args.replace_perm
            if "=" not in item:
                print("[axml-patch] --replace-perm phải có dạng OLD_PERM=NEW_PERM")
                return 2
            old_p, new_p = item.split("=", 1)
            if args.dry_run:
                print("[axml-patch] DRY-RUN đổi quyền: %s -> %s" % (old_p, new_p))
                return 0
            res = replace_permission(args.binary, old_p, new_p, backup_path=backup)
            print("[axml-patch] Đổi permission: %d hit, backup: %s" % (res["hits"], res["backup"] or "không tạo"))
            return 0

        if not getattr(args, "old", None) or not getattr(args, "new", None):
            print("[axml-patch] Cần truyền chuỗi OLD và NEW hoặc dùng --inspect-security / --bypass-nsc / --replace-perm")
            return 2

        info = inspect_binary(args.binary)
        if args.dry_run:
            print("[axml-patch] DRY-RUN %s: %d bytes, %d chunk" % (args.binary, info["size"], len(info["chunks"])))
            return 0
        result = replace_string_inplace(args.binary, args.old, args.new, backup)
        print("[axml-patch] %d hit (%s), backup: %s" % (result["hits"], result.get("encoding", "unknown"), result["backup"] or "không tạo"))
        return 0
    except (OSError, ValueError) as exc:
        print("[axml-patch] LỖI: %s" % exc)
        return 2

def cmd_signature_cert(args):
    from .signature_spoof import signature_context, write_context
    try:
        ctx=signature_context(args.apk)
        if args.output:
            write_context(args.apk,args.output)
            print("[signature-cert] đã ghi %s" % args.output)
        print("[signature-cert] DER=%d bytes SHA-256=%s" % (ctx["cert_bytes"],ctx["sha256"]))
        return 0
    except (OSError,ValueError) as exc:
        print("[signature-cert] LỖI: %s" % exc); return 2


def cmd_intake(args):
    """Tiếp nhận artifact Android trước khi chạy pipeline có thay đổi."""
    from .intake import run_intake
    out_dir = args.output_dir or os.path.join(BASE_DIR, "outputs", "intake")
    try:
        report = run_intake(args.artifact, out_dir,
                            include_tools=not args.no_tool_probe)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print("[intake] LỖI: %s" % exc)
        return 2
    artifact = report["artifact"]
    summary = report["summary"]
    print("[intake] %s (%s)" % (artifact["name"], artifact["kind"]))
    print("[intake] %s | %d cảnh báo | %d DEX | ABI: %s" % (
        summary["verdict"], summary.get("warnings", 0),
        report.get("structure", {}).get("dex_count", 0),
        ", ".join(report.get("structure", {}).get("abis", [])) or "—",
    ))
    print("Đã ghi:", report["outputs"]["json"])
    print("Đã ghi:", report["outputs"]["markdown"])
    if report["outputs"].get("capabilities"):
        print("Đã ghi:", report["outputs"]["capabilities"]["json"])
    return 0


def cmd_capabilities(args):
    """Ghi snapshot công cụ hiện có mà không cài thêm dependency."""
    from .intake import collect_tool_capabilities, write_capabilities
    out_dir = args.output_dir or os.path.join(BASE_DIR, "outputs", "intake")
    capabilities = collect_tool_capabilities()
    outputs = write_capabilities(capabilities, out_dir)
    summary = capabilities["summary"]
    print("[capabilities] Có %d/%d công cụ" % (
        summary["available"], summary["total"]))
    if summary["missing"]:
        print("[capabilities] Thiếu: %s" % ", ".join(summary["missing"]))
    print("Đã ghi:", outputs["json"])
    print("Đã ghi:", outputs["markdown"])
    return 0


def cmd_pipeline(args):
    """Điều phối Pipeline Thống Nhất cho artifact Android."""
    from .pipeline_unified import run_pipeline
    out_dir = args.output_dir or os.path.join(BASE_DIR, "outputs", "pipeline")
    dex_str = {}
    for kv in args.dex_str or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            dex_str[k] = v
    dex_hex = {}
    for kv in args.dex_hex or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            dex_hex[k] = v
    axml_str = {}
    for kv in args.axml or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            axml_str[k] = v
    arsc_str = {}
    for kv in args.arsc or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            arsc_str[k] = v

    print(f"[pipeline] Khởi chạy Unified Pipeline (mode: {args.mode})")
    print(f"[pipeline] Artifact: {args.artifact}")
    report = run_pipeline(
        args.artifact,
        mode=args.mode,
        output_dir=out_dir,
        out_apk=args.out,
        dex_str_replaces=dex_str,
        dex_hex_replaces=dex_hex,
        axml_replaces=axml_str,
        arsc_replaces=arsc_str,
        dry_run=args.dry_run,
        auto_patch=args.auto_patch,
        build_apk=args.build_apk,
    )
    print(f"[pipeline] Kết quả: {report['verdict']} ({report['elapsed_seconds']}s)")
    for stage in report.get("stages", []):
        print(f"  - Stage [{stage['name']}]: {stage['status']}")
    if report["outputs"].get("report_markdown"):
        print("Đã ghi:", report["outputs"]["report_markdown"])
    return 0 if report["verdict"] in ("SUCCESS", "READY") else 1


def cmd_dag(args):
    """Quản lý sơ đồ điều phối thứ tự công việc và sổ bộ quy trình mẫu."""
    from .pipeline_registry import get_pipeline_registry
    from .orchestrator import ensure_autopilot_pipeline
    ensure_autopilot_pipeline()
    registry = get_pipeline_registry()

    if getattr(args, "list", False):
        print("\n=== SỔ BỘ QUY TRÌNH — DANH SÁCH CÁC QUY TRÌNH MẪU ĐÃ CHUẨN HÓA ===")
        for pipe in registry.list_pipelines():
            dag = pipe.dag
            order = dag.toposort() if dag.nodes else []
            tags_str = f" [{', '.join(pipe.tags)}]" if pipe.tags else ""
            print(f"  • \033[1m\033[96m{pipe.name}\033[0m{tags_str}: {pipe.description}")
            print(f"    Sơ đồ luồng: {' -> '.join(order)} ({len(dag.nodes)} bước, {len(dag.get_execution_levels())} tầng thực hiện)")

        print("\n=== CÁC BƯỚC XỬ LÝ (STEPS) KHẢ DỤNG ===")
        for step in registry.list_steps():
            cost_color = "\033[92m" if step.cost == "FAST" else ("\033[93m" if step.cost == "MEDIUM" else "\033[91m")
            deps = f" (phụ thuộc bước: {', '.join(sorted(step.depends_on))})" if step.depends_on else ""
            print(f"  [{cost_color}{step.cost}\033[0m] \033[1m{step.name}\033[0m{deps}: {step.description}")
        return 0

    if getattr(args, "inspect", None):
        target = args.inspect
        pipe = registry.get_pipeline(target)
        if not pipe:
            print(f"[dag] Lỗi: Không tìm thấy quy trình '{target}'. Dùng --list để xem danh sách.")
            return 1
        print(f"\n=== CHI TIẾT SƠ ĐỒ QUY TRÌNH: {pipe.name} (v{pipe.version}) ===")
        print(f"Mô tả: {pipe.description}")
        print(f"Tác giả: {pipe.author} | Thẻ phân loại: {', '.join(pipe.tags)}")
        print("\n" + pipe.dag.render_ascii())
        print("\n[Chi tiết từng bước xử lý]")
        for name in pipe.dag.toposort():
            node = pipe.dag.get_node(name)
            print(f"  • {name} [{node.cost}]: {node.description}")
            if node.inputs:
                print(f"    - Dữ liệu đầu vào cần có: {', '.join(node.inputs)}")
            if node.outputs:
                print(f"    - Dữ liệu đầu ra sinh ra: {', '.join(node.outputs)}")
        return 0

    if getattr(args, "mermaid", None):
        target = args.mermaid
        pipe = registry.get_pipeline(target)
        if not pipe:
            print(f"[dag] Lỗi: Không tìm thấy quy trình '{target}'.")
            return 1
        print("```mermaid")
        print(pipe.dag.to_mermaid())
        print("```")
        return 0

    if getattr(args, "run", None):
        pipe_name = args.run
        if not getattr(args, "artifact", None):
            print("[dag] Lỗi: Cần cung cấp đường dẫn tệp ứng dụng khi chạy --run <tên_quy_trình> <tệp_ứng_dụng>.")
            return 1
        pipe = registry.get_pipeline(pipe_name)
        if not pipe:
            print(f"[dag] Lỗi: Quy trình '{pipe_name}' không tồn tại trong Sổ bộ.")
            return 1
        print(f"[dag] Khởi chạy quy trình '{pipe_name}' cho tệp: {args.artifact}")
        res = pipe.execute(
            args.artifact,
            output_dir=getattr(args, "output_dir", None),
            dry_run=getattr(args, "dry_run", False),
        )
        print(f"[dag] Trạng thái chung: {res.verdict} ({round(res.elapsed_seconds, 3)} giây)")
        for name, rec in res.records.items():
            st_color = "\033[92mTHÀNH CÔNG\033[0m" if rec.status == "SUCCESS" else ("\033[93mBỎ QUA\033[0m" if rec.status == "SKIPPED" else "\033[91mTHẤT BẠI\033[0m")
            dur = f"({round(rec.elapsed_seconds, 3)}s)" if rec.elapsed_seconds > 0 else ""
            print(f"  [{st_color}] {name} {dur}")
            if rec.error_message:
                print(f"         Lỗi: {rec.error_message}")
            if rec.skip_reason:
                print(f"         Lý do bỏ qua: {rec.skip_reason}")
        return 0 if res.verdict in ("SUCCESS", "PARTIAL", "DRY_RUN") else 1

    if getattr(args, "export_all", None) or getattr(args, "export", None):
        target_dir = args.export_all or args.export or os.path.join(BASE_DIR, "outputs", "pipeline", "dag")
        exported = registry.export_blueprint(target_dir)
        print(f"[dag] Đã xuất toàn bộ tài liệu và sơ đồ thành công vào: {target_dir}")
        print(f"  • Cấu trúc tổng thể (JSON): {exported.get('schema_json')}")
        print(f"  • Sơ đồ tổng thể (Markdown): {exported.get('blueprint_md')}")
        pipes_count = len([k for k in exported if k.endswith('_mermaid')])
        print(f"  • Số quy trình đã xuất: {pipes_count} quy trình")
        return 0

    print("[dag] Vui lòng chọn một tùy chọn: --list, --inspect <tên>, --mermaid <tên>, --export-all, hoặc --run <tên> <tệp_ứng_dụng>")
    return 0


def cmd_macro_list(args):
    from .macro_registry import list_macros, validate_macro
    for name in list_macros():
        print("%s: required_registers=%d safe=%s" % (name, validate_macro(name,args.registers)["required_registers"], validate_macro(name,args.registers)["safe"]))
    return 0

def cmd_dex_patch(args):
    """Direct DEX string & bytecode patch, có backup và không qua apktool."""
    from .dex_inplace import inspect_dex, patch_dex_file_strings, patch_dex_file_bytecode
    replace_hex = getattr(args, "replace_hex", [])
    if not args.replace and not replace_hex:
        print("[patchx] cần ít nhất một --replace OLD=NEW hoặc --replace-hex TARGET_HEX=REPL_HEX")
        return 2
    try:
        with open(args.dex, "rb") as fh:
            raw = fh.read()
        info = inspect_dex(raw)
        if args.dry_run:
            print("[dex-patch] DRY-RUN %s: %d bytes, %s" %
                  (args.dex, len(raw), info["magic"]))
            for item in args.replace:
                if "=" in item:
                    old, new = item.split("=", 1)
                    print("  str: %r -> %r (%d hit)" % (old, new, raw.count(old.encode("utf-8"))))
            for item in replace_hex:
                if "=" in item:
                    old_h, new_h = item.split("=", 1)
                    old_b = bytes.fromhex(old_h.replace(" ", "").replace("0x", ""))
                    print("  hex: %s -> %s (%d hit)" % (old_h, new_h, raw.count(old_b)))
            return 0
        backup = args.backup or os.path.join(BASE_DIR, "outputs", "backup", "dex_inplace")
        total_replaced = 0
        if args.replace:
            replacements = []
            for item in args.replace:
                if "=" not in item:
                    print("[patchx] --replace phải có dạng OLD=NEW: %s" % item)
                    return 2
                old, new = item.split("=", 1)
                if not old:
                    print("[patchx] OLD không được rỗng")
                    return 2
                replacements.append((old, new))
            res_str = patch_dex_file_strings(args.dex, replacements, backup_dir=backup)
            total_replaced += res_str["total_replaced"]
        if replace_hex:
            hex_repls = []
            for item in replace_hex:
                if "=" not in item:
                    print("[patchx] --replace-hex phải có dạng TARGET=REPL: %s" % item)
                    return 2
                t_h, r_h = item.split("=", 1)
                if not t_h:
                    print("[patchx] TARGET hex không được rỗng")
                    return 2
                hex_repls.append((t_h, r_h))
            res_hex = patch_dex_file_bytecode(args.dex, hex_repls, backup_dir=backup)
            total_replaced += res_hex["total_replaced"]
        print("[dex-patch] đã sửa %d hit, backup: %s" %
              (total_replaced, backup))
        return 0
    except (OSError, ValueError) as exc:
        print("[dex-patch] LỖI: %s" % exc)
        return 2


def cmd_apk_repack_fast(args):
    """Fast repack chỉ thay entry được chỉ định; không ký APK."""
    from .apk_fast_repack import fast_repack_apk
    updates = {}
    for item in args.update:
        if "=" not in item:
            print("[apk-repack-fast] --update phải có dạng ENTRY=FILE: %s" % item)
            return 2
        entry, source = item.split("=", 1)
        if not entry or not source or not os.path.isfile(source):
            print("[apk-repack-fast] entry hoặc file không hợp lệ: %s" % item)
            return 2
        updates[entry] = source
    if args.dry_run:
        print("[apk-repack-fast] DRY-RUN: %s -> %s (%d entry)" %
              (args.apk, args.output, len(updates)))
        return 0
    try:
        result = fast_repack_apk(args.apk, updates, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print("[apk-repack-fast] LỖI: %s" % exc)
        return 2
    print("[apk-repack-fast] %d entry cập nhật, %d entry giữ nguyên; chưa ký APK" %
          (result["updated_entries"], result["copied_entries"]))
    return 0


def cmd_fast_patch(args):
    """Quy trình Fast-Patch 1-Click: sửa DEX/AXML/ARSC in-place và repack siêu tốc."""
    from .apk_fast_repack import fast_patch_and_repack
    dex_reps = []
    for item in getattr(args, "dex_str", []) or []:
        if "=" not in item:
            print("[fast-patch] --dex-str phải có dạng OLD=NEW: %s" % item)
            return 2
        old, new = item.split("=", 1)
        dex_reps.append((old, new, False))
    for item in getattr(args, "dex_hex", []) or []:
        if "=" not in item:
            print("[fast-patch] --dex-hex phải có dạng TARGET=REPL: %s" % item)
            return 2
        old_h, new_h = item.split("=", 1)
        dex_reps.append((old_h, new_h, True))
    axml_reps = []
    for item in getattr(args, "axml", []) or []:
        if "=" not in item:
            print("[fast-patch] --axml phải có dạng OLD=NEW: %s" % item)
            return 2
        old, new = item.split("=", 1)
        axml_reps.append((old, new))
    arsc_reps = []
    for item in getattr(args, "arsc", []) or []:
        if "=" not in item:
            print("[fast-patch] --arsc phải có dạng OLD=NEW: %s" % item)
            return 2
        old, new = item.split("=", 1)
        arsc_reps.append((old, new))

    if not dex_reps and not axml_reps and not arsc_reps:
        print("[fast-patch] Cần ít nhất một --dex-str, --dex-hex, --axml hoặc --arsc")
        return 2

    if getattr(args, "dag", False):
        from .pipeline_registry import get_pipeline_registry
        reg = get_pipeline_registry()
        res = reg.run_pipeline("fast", args.apk)
        return 0 if res.success else 1

    strip = not getattr(args, "no_strip", False)
    try:
        res = fast_patch_and_repack(
            args.apk,
            dex_replacements=dex_reps if dex_reps else None,
            axml_replacements=axml_reps if axml_reps else None,
            arsc_replacements=arsc_reps if arsc_reps else None,
            output_apk=args.output,
            strip_signatures=strip,
        )
        if not res.get("success"):
            print("[fast-patch] Không tìm thấy pattern để vá: %s" % res.get("message"))
            return 1
        print("[fast-patch] THÀNH CÔNG: DEX hits=%d, AXML hits=%d, ARSC hits=%d, stripped=%d, file ra: %s (%d bytes)" %
              (res["dex_hits"], res["axml_hits"], res.get("arsc_hits", 0), res["stripped_signatures"], res["apk_out"], res["out_size"]))
        try:
            from .learn import record_success, categorize
            pkg = os.path.basename(args.apk)
            record_success(
                BASE_DIR,
                {
                    "package": pkg,
                    "danh_mục": categorize(pkg),
                    "combo": ["fast-patch-inplace"],
                    "target_apk": args.apk,
                    "dex_hits": res.get("dex_hits", 0),
                    "axml_hits": res.get("axml_hits", 0),
                }
            )
        except Exception:
            pass
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print("[fast-patch] LỖI: %s" % exc)
        return 2


def cmd_auto_gate(args):
    """Tự động can thiệp các cổng kiểm tra an ninh (Security Gates) bằng Smali AST Mutator và Micro-DEX Emulator."""
    from .auto_gate_patcher import apply_security_gates
    from .smali_sem import detect_security_gates

    tree = args.tree
    min_conf = getattr(args, "min_confidence", 75.0)
    max_gates = getattr(args, "max_gates", 50)
    backup = not getattr(args, "no_backup", False)

    print(f"[auto-gate] Đang phân tích đồ thị luồng taint để tìm Security Gates trong {tree}...")
    gates = detect_security_gates(tree, max_gates=max_gates)
    print(f"[auto-gate] Tìm thấy {len(gates)} cổng kiểm tra an ninh tiềm năng.")

    res = apply_security_gates(tree, gates=gates, min_confidence=min_conf, backup=backup)

    print("\n[auto-gate] KẾT QUẢ CAN THIỆP TỰ ĐỘNG (SMALI AST + MICRO-DEX EMULATOR):")
    print(f"  - Tổng số cổng phát hiện: {res['total_gates']}")
    print(f"  - Số cổng can thiệp thành công: {res['applied_count']}")
    print(f"  - Số cổng bỏ qua: {res['skipped_count']}")
    print(f"  - Lỗi: {res['errors_count']}")

    if res['applied']:
        print("\n  Chi tiết các cổng đã can thiệp:")
        for it in res['applied']:
            ver_str = " [ĐÃ KIỂM CHỨNG TOÁN HỌC]" if it.get("emulated_verified") else ""
            print(f"    * {it['class']}->{it['method']} ({it['type']}) - Tin cậy: {it['confidence']:.1f}%{ver_str}")

    return 0 if res["applied_count"] > 0 or res["total_gates"] == 0 else 1


def cmd_network_bypass(args):
    """Đột phá tầng mạng: mở khóa NSC, Cleartext và sinh tập lệnh vô hiệu hóa SSL Pinning đa tầng."""
    from .network_breakthrough import apply_network_bypass

    target = args.target
    out_dir = getattr(args, "output_dir", "outputs/network_bypass")

    print(f"[network-bypass] Đang áp dụng đột phá tầng mạng cho {target}...")
    res = apply_network_bypass(
        target_path=target,
        output_dir=out_dir,
        enable_cleartext=not getattr(args, "no_cleartext", False),
        gen_ssl_script=not getattr(args, "no_ssl_script", False),
    )

    print("\n[network-bypass] KẾT QUẢ XỬ LÝ TẦNG MẠNG:")
    if res.get("nsc_enabler"):
        nsc = res["nsc_enabler"]
        print(f"  - Cấu hình an ninh mạng (NSC/Cleartext): {'THÀNH CÔNG' if nsc.get('success') else 'CHƯA ĐỔI'}")
        for d in nsc.get("details", []):
            print(f"    * {d}")
    if res.get("ssl_script_path"):
        print(f"  - Tập lệnh Universal SSL Pinning Nullifier: {res['ssl_script_path']}")
    print(f"  - Số quy tắc giả lập gói tin tự động: {res['forge_rules_count']}")

    return 0 if res.get("success") else 1


def cmd_native_auto_patch(args):
    """Đột phá tầng thư viện: quét và đột biến nhị phân zero-drift vô hiệu hóa chốt chặn Native C/C++."""
    from .behavior.native_mutator import auto_mutate_native

    target = args.target
    out_dir = getattr(args, "output_dir", "outputs/native_mutator")
    apply_disk = not getattr(args, "dry_run", False)

    print(f"[native-auto-patch] Đang quét và xử lý chốt chặn an ninh Native trong {target}...")
    res = auto_mutate_native(
        target_path=target,
        output_dir=out_dir,
        apply_disk=apply_disk,
        gen_frida=True,
    )

    print("\n[native-auto-patch] KẾT QUẢ XỬ LÝ TẦNG THƯ VIỆN (.SO):")
    print(f"  - Tổng số tệp .so đã duyệt: {res['total_so_files']}")
    print(f"  - Số chốt chặn an ninh phát hiện: {res['findings_count']}")
    print(f"  - Số tệp .so đã đột biến trực tiếp: {len(res['patched_files'])}")
    for pf in res['patched_files']:
        print(f"    * {pf['so_path']} (Đã patch: {pf['patched_count']} vị trí, Backup: {pf.get('backup')})")
    if res.get("frida_script"):
        print(f"  - Tập lệnh Native Frida Hook: {res['frida_script']}")

    return 0 if res.get("success") else 1


def cmd_arsc_patch(args):
    """Phân tích và patch chuỗi nhị phân trong resources.arsc in-place."""
    from .axml_editor import inspect_arsc, replace_arsc_strings
    try:
        if getattr(args, "inspect", False):
            info = inspect_arsc(args.arsc)
            print("[arsc-patch] THÔNG TIN RESOURCES.ARSC: %s" % args.arsc)
            print("  Hợp lệ        : %s" % info["is_valid_arsc"])
            print("  Kích thước    : %d bytes" % info["size"])
            print("  Tổng chuỗi    : %d chuỗi trong String Pool" % info["total_strings"])
            for pkg in info["packages"]:
                print("  Package       : ID=0x%02X, Tên=%s" % (pkg["id"], pkg["name"]))
            return 0

        reps = []
        if getattr(args, "replace", []):
            for item in args.replace:
                if "=" not in item:
                    print("[arsc-patch] --replace phải có dạng OLD=NEW: %s" % item)
                    return 2
                o, n = item.split("=", 1)
                reps.append((o, n))

        if getattr(args, "old", None) and getattr(args, "new", None):
            reps.append((args.old, args.new))

        if not reps:
            print("[arsc-patch] Cần chỉ định chuỗi OLD và NEW hoặc dùng --replace OLD=NEW, hoặc --inspect")
            return 2

        if args.dry_run:
            info = inspect_arsc(args.arsc)
            print("[arsc-patch] DRY-RUN %s: %d bytes, %d chuỗi" % (args.arsc, info["size"], info["total_strings"]))
            with open(args.arsc, "rb") as fh:
                raw = fh.read()
            for o, n in reps:
                cnt_u8 = raw.count(o.encode("utf-8"))
                cnt_u16 = raw.count(o.encode("utf-16le"))
                print("  Pattern %r -> %r (hit UTF-8: %d, UTF-16LE: %d)" % (o, n, cnt_u8, cnt_u16))
            return 0

        backup = args.backup or args.arsc + ".bak"
        res = replace_arsc_strings(args.arsc, reps, backup_path=backup)
        print("[arsc-patch] THÀNH CÔNG: %d hit trên %d mẫu, backup: %s" %
              (res["total_hits"], res["replacements"], res["backup"] or "không tạo"))
        return 0
    except (OSError, ValueError) as exc:
        print("[arsc-patch] LỖI: %s" % exc)
        return 2


def cmd_native_sig_bypass(args):
    """Quy trình 1-Click tự động quét và bypass SHA-256 cert hash trong các thư viện native .so."""
    from .signature_spoof import multi_layer_spoof_pipeline, signature_context
    from .apk_fast_repack import fast_repack_apk
    import tempfile, shutil, zipfile
    try:
        if not os.path.isfile(args.apk):
            print("[native-sig-bypass] Không tìm thấy APK: %s" % args.apk)
            return 2

        orig_apk = args.orig_apk or args.apk
        if not os.path.isfile(orig_apk):
            print("[native-sig-bypass] Không tìm thấy APK gốc: %s" % orig_apk)
            return 2

        orig_ctx = signature_context(orig_apk)
        print("[native-sig-bypass] APK gốc cert SHA-256: %s (%d bytes)" %
              (orig_ctx["sha256"], orig_ctx["cert_bytes"]))

        mod_ctx = signature_context(args.apk)
        print("[native-sig-bypass] APK đích cert SHA-256: %s" % mod_ctx["sha256"])

        with tempfile.TemporaryDirectory() as td:
            # Giải nén các thư viện .so từ APK
            so_dir = os.path.join(td, "lib")
            extracted_sos = []
            with zipfile.ZipFile(args.apk, "r") as zin:
                for name in zin.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        dest = os.path.join(td, name)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "wb") as fh:
                            fh.write(zin.read(name))
                        extracted_sos.append(name)

            if not extracted_sos:
                print("[native-sig-bypass] APK không chứa thư viện native (lib/**/*.so).")
            else:
                print("[native-sig-bypass] Đã tìm thấy %d thư viện native .so" % len(extracted_sos))

            frida_out = args.frida_out or os.path.join(BASE_DIR, "outputs", "behavior", "native_sig_hook.js")
            if args.dry_run:
                print("[native-sig-bypass] DRY-RUN: Quét tìm SHA-256 cert hash...")
                for so_rel in extracted_sos:
                    so_path = os.path.join(td, so_rel)
                    with open(so_path, "rb") as fh:
                        raw = fh.read()
                    h_mod = mod_ctx["sha256"].encode("ascii")
                    cnt = raw.count(h_mod) + raw.count(h_mod.lower())
                    print("  %s: %d hit" % (so_rel, cnt))
                print("[native-sig-bypass] Kịch bản Frida sẽ sinh: %s" % frida_out)
                return 0

            # Thực thi pipeline
            res = multi_layer_spoof_pipeline(
                original_apk=orig_apk,
                so_dir=so_dir if extracted_sos else None,
                new_cert_apk=args.apk if extracted_sos else None,
                frida_script_out=frida_out
            )

            patched_sos = {}
            for p in res.get("native_patches", []):
                rel_name = os.path.relpath(p["so"], td)
                with open(p["so"], "rb") as fh:
                    patched_sos[rel_name] = fh.read()
                print("[native-sig-bypass] Đã vá %d hit trong: %s" % (p["hits"], rel_name))

            if patched_sos:
                out_apk = args.output or (args.apk[:-4] + "_native_spoofed.apk")
                fast_repack_apk(args.apk, patched_sos, apk_out_path=out_apk, strip_signatures=True)
                print("[native-sig-bypass] APK đã cập nhật .so và gỡ chữ ký cũ: %s" % out_apk)
            else:
                print("[native-sig-bypass] Không tìm thấy chuỗi hash cần vá trong các file .so (khuyến nghị dùng Frida hook).")

            print("[native-sig-bypass] Kịch bản Frida Multi-Layer đã sinh: %s" % res["frida_script"])
            return 0
    except Exception as exc:
        print("[native-sig-bypass] LỖI: %s" % exc)
        return 2


def cmd_smart_combo(args):
    """Máy sinh Smart-Combo tự động dựa trên Active Learning từ kho combos_success.json."""
    from .learn import generate_smart_combo, save_smart_combo
    coll = getattr(args, "collection", "upgraded") or "upgraded"
    if not os.path.isdir(coll):
        coll = os.path.join(BASE_DIR, coll)
    if not os.path.isdir(coll):
        print("[smart-combo] Không tìm thấy kho patch: %s" % coll)
        return 2

    print("[smart-combo] Đang phân tích cây APK và dữ liệu Active Learning...")
    res = generate_smart_combo(
        tree=args.cay,
        collection=coll,
        intent=getattr(args, "intent", None),
        max_patches=getattr(args, "max_patches", 4) or 4,
        name=getattr(args, "name", None)
    )

    print("[smart-combo] Kết quả phân tích Active Learning:")
    print("  Gói ứng dụng    : %s (Danh mục: %s)" % (res["package"] or "Chung", res["category"]))
    print("  Dữ liệu lịch sử : Sử dụng %d bản ghi thành công" % res["historical_records_used"])
    print("  Patch đã chọn   : %d patch (%s)" % (res["patch_count"], ", ".join(res["selected_patches"])))
    print("  Xung đột phát hiện: %d xung đột" % res["conflicts"])

    if not res["selected_patches"]:
        print("[smart-combo] Không tìm thấy patch phù hợp với tiêu chí/ý định.")
        return 1

    out_dir = args.output_dir or os.path.join(BASE_DIR, "combos")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "%s.txt" % res["combo_name"])

    if args.dry_run:
        print("[smart-combo] DRY-RUN: File combo dự kiến tạo: %s" % out_file)
        return 0

    save_smart_combo(res["merged_patch"], out_file, header="Smart-Combo sinh tự động bởi Active Learning")
    print("[smart-combo] Đã tạo combo thành công: %s (%d bytes)" % (out_file, os.path.getsize(out_file)))

    if getattr(args, "apply", False):
        print("[smart-combo] Đang tự động áp combo vào cây: %s" % args.cay)
        from .applier import apply_patches
        app_res = apply_patches([res["merged_patch"]], args.cay)
        print("[smart-combo] Kết quả áp patch: %s" % app_res)

    return 0


def cmd_discover(args):
    """Lệnh phân tích thông minh toàn diện & khai phá mở rộng không giới hạn từ điển."""
    from .comprehensive_analyzer import UniversalDiscoveryEngine
    if not os.path.exists(args.target):
        print("[discover] LỖI: Không tìm thấy mục tiêu: %s" % args.target)
        return 2
    engine = UniversalDiscoveryEngine(args.target, output_dir=args.output)
    res = engine.run_full_discovery()
    summary = res.get("summary", {})
    print("\n" + "=" * 70)
    print("🎯 BÁO CÁO PHÂN TÍCH TOÀN DIỆN & KHAI PHÁ MỞ RỘNG (DISCOVERY)")
    print("=" * 70)
    print("Mục tiêu: %s" % res["target"])
    print("1. Tệp nhạy cảm phát hiện: %d" % summary.get("total_sensitive_assets", 0))
    for f in res.get("assets_sensitive", {}).get("findings", [])[:8]:
        sec = f.get("secret_detected") or f.get("type_desc")
        print("   - [%s] %s (Entropy: %.2f, Tin cậy: %.0f%%)" % (sec, f["file"], f["entropy"], f["confidence"]))
    print("2. Cổng an ninh hình thái học (Zero-Keyword Gates): %d" % summary.get("total_proven_gates", 0))
    for g in res.get("morphological_gates", [])[:5]:
        cond = g.get("proof_chain", {}).get("condition", "")
        print("   - [%s] %s->%s (%d%%)" % (g["pattern"], g["class"], g["method"], g["confidence"]))
        print("     Chứng minh: %s" % cond)
    print("3. Từ vựng & Cờ logic tự học từ APK: %d" % summary.get("total_dynamic_lexicon_terms", 0))
    lex = res.get("lexicon_mined", {})
    if lex.get("discovered_flags"):
        print("   - Cờ logic khai phá: %s" % ", ".join(lex["discovered_flags"][:12]))
    if lex.get("high_entropy_tokens"):
        print("   - Token/Key entropy cao: %d chuỗi" % len(lex["high_entropy_tokens"]))
    print("=" * 70)
    print("Đã lưu kết quả chi tiết: %s/universal_discovery.json" % engine.output_dir)
    return 0


def cmd_subtitle_tts(args):
    """Công cụ điều phối & chẩn đoán đọc phụ đề thời gian thực bằng TTS."""
    from .subtitle_tts_engine import (
        SubtitleStreamBuffer, SubtitleSpeechQueueManager,
        SubtitleAccessibilityInspector, format_status_report
    )
    print("\n" + "=" * 70)
    print("🎙️ ĐỘNG CƠ ĐỌC PHỤ ĐỀ THỜI GIAN THỰC (REAL-TIME SUBTITLE TTS)")
    print("=" * 70)
    target = getattr(args, "target", None)
    if target and os.path.exists(target):
        print("Mục tiêu phân tích: %s" % target)
        smali_files = glob.glob(os.path.join(target, "**", "*Subtitle*.smali"), recursive=True)
        if not smali_files:
            smali_files = glob.glob(os.path.join(target, "**", "*.smali"), recursive=True)
        found_svc = False
        for sf in smali_files:
            try:
                content = open(sf, encoding="utf-8", errors="ignore").read()
                if "AccessibilityService" in content or "SubtitleAccessibilityService" in sf:
                    found_svc = True
                    insp = SubtitleAccessibilityInspector.inspect_accessibility_smali(content)
                    print("\n[Phát hiện dịch vụ] %s" % os.path.basename(sf))
                    if insp["has_issues"]:
                        for issue in insp["issues"]:
                            print("  ⚠️ [%s] %s" % (issue["type"], issue["message"]))
                    else:
                        print("  ✅ Cấu hình và bộ lọc hợp lệ.")
            except Exception:
                pass
        if not found_svc:
            print("[subtitle-tts] Đã phân tích mục tiêu. Sử dụng chế độ mô phỏng trực tiếp.")
    else:
        print(format_status_report())
        buf = SubtitleStreamBuffer(debounce_ms=350)
        chunks = ["Hôm", "Hôm nay", "Hôm nay tôi xin chia sẻ", "Hôm nay tôi xin chia sẻ về cách học ngoại ngữ."]
        print("Mô phỏng luồng phụ đề streaming:")
        for c in chunks:
            emitted = buf.feed(c)
            if emitted:
                print("  -> TTS Utterance phát âm: '%s'" % emitted[0])
        flushed = buf.flush_if_timeout()
        for f in flushed:
            print("  -> TTS Debounce phát âm: '%s'" % f)

    print("=" * 70)
    return 0


def cmd_auto_refresh(args):
    """Tự động reset và bật lại dịch phụ đề + chia sẻ toàn màn hình sau mỗi 2 phút 40 giây."""
    from .auto_session_refresher import AutoSessionRefresher
    refresher = AutoSessionRefresher(
        package=args.package,
        interval=args.interval,
        adb_device=args.device,
        use_root=args.root,
        speak_tts=not args.no_tts
    )
    if args.once:
        refresher.detect_screen_size()
        refresher.trigger_reset_cycle()
    else:
        refresher.run_loop()
    return 0


def cmd_dex_budget(args):
    """P5 — DEX Resource Manager: ước lượng refs + mức an toàn."""
    from .dex_budget import DEX_METHOD_MAX, budget_report, strategy_for
    from .parser import parse_patch_file, parse_text
    sections = []
    if getattr(args, "patch", None):
        p = parse_patch_file(args.patch) if os.path.isfile(args.patch) \
            else parse_text(open(args.patch, encoding="utf-8").read())
        sections = p.sections
    rep = budget_report(args.cay, sections=sections,
                        max_refs=getattr(args, "max", None) or DEX_METHOD_MAX,
                        max_files=getattr(args, "max_files", None),
                        workers=getattr(args, "workers", 1) or 1)
    u = rep["used"]
    print("[dex-budget] %s" % args.cay)
    print("  files  : %d tệp smali" % u["files"])
    print("  classes: %d" % u["classes"])
    print("  methods: %d (used)" % u["methods"])
    print("  fields : %d" % u["fields"])
    print("  strings: %d" % u["strings"])
    print("  delta  : %+d method refs (patch: %d khối)"
          % (rep["delta"], len(sections)))
    if rep["per_type"]:
        print("  theo loại:", "; ".join(
            "%s %+d" % (t, d) for t, d in sorted(rep["per_type"].items())))
    print("  tổng   : %d / %d" % (rep["total"], rep["max_refs"]))
    print("  còn lại: %d" % rep["remaining"])
    print("  MỨC    : %s" % rep["level"])
    st = strategy_for(rep)
    print("  CHIẾN LƯỢC: %s (risk=%s, confidence=%d%%)"
          % (st["strategy"], st["risk"], st["confidence"]))
    print("  lý do  : %s" % st["reason"])
    return 0 if rep["level"] in ("SAFE", "WATCH") else 1


def cmd_preflight(args):
    """P7 — Preflight: cổng kiểm tra trước khi áp patch."""
    from .parser import parse_patch_file, parse_text
    from .preflight import preflight_patch
    src = args.patch
    p = parse_patch_file(src) if os.path.isfile(src) else \
        parse_text(open(src, encoding="utf-8").read())
    rep = preflight_patch(p, args.cay,
                          max_files=getattr(args, "max_files", None))
    print("[preflight] %s → %s" % (p.name, rep["verdict"]))
    for c in rep["checks"]:
        print("  [%s] %s: %s" % (c["mức"], c["loại"], c["nội_dung"]))
    print("  %s" % rep["summary"])
    return 0 if rep["verdict"] in ("READY", "READY_WITH_WARNING") else 2


def cmd_fuzz(args):
    """P12 — Fuzz/Chaos: tấn công parser + engine bằng dữ liệu ngẫu nhiên."""
    from .fuzz import run_fuzz
    rep = run_fuzz(iterations=args.iter, seed=args.seed,
                   workdir=args.workdir)
    print("[fuzz] %d lượt (seed=%d): %s"
          % (rep["iterations"], rep["seed"],
             "SẠCH" if rep["ok"] else "CÓ VẤN ĐỀ"))
    for tag, item, detail in rep["crashes"][:10]:
        print("  [CRASH] %s %s: %s" % (item, tag, detail))
    for tag, item, detail in rep["violations"][:10]:
        print("  [VIOLATION] %s %s: %s" % (item, tag, detail))
    if len(rep["crashes"]) + len(rep["violations"]) > 10:
        print("  … còn %d vấn đề nữa"
              % (len(rep["crashes"]) + len(rep["violations"]) - 10))
    return 0 if rep["ok"] else 1


def cmd_failure(args):
    """P15 — Failure Intelligence: DB lỗi, phân loại, sinh regression test."""
    from .failure_db import (add_failure, classify_failure, gen_regression_test,
                             load_db, render_report, save_db)
    act = args.hanh_dong
    if act == "list":
        entries = load_db(args.db)
        print("%d lỗi trong DB:" % len(entries))
        for e in entries:
            print("  %-12s %-12s %s" % (e.get("error_id"), e.get("stage"),
                                        (e.get("pattern") or "")[:70]))
        return 0
    if act == "report":
        print(render_report(args.db))
        return 0
    if act == "lookup":
        if not args.message:
            print("Cần --message để tra cứu.")
            return 2
        hit = classify_failure(args.message, stage=args.stage, db_path=args.db)
        if not hit:
            print("[failure] Không tìm thấy entry khớp.")
            return 1
        print("ERROR_ID : %s" % hit.get("error_id"))
        print("STAGE    : %s" % hit.get("stage"))
        print("PATTERN  : %s" % hit.get("pattern"))
        print("NGUYÊN NHÂN: %s" % hit.get("cause"))
        print("XỬ LÝ    : %s" % hit.get("fix"))
        print("REGRESSION: %s" % hit.get("regression"))
        return 0
    if act == "add":
        entry = {"error_id": args.error_id, "stage": args.stage or "",
                 "pattern": args.pattern, "cause": args.cause or "",
                 "fix": args.fix or "", "regression": args.regression or ""}
        added, path = add_failure(entry, args.db)
        print("[failure] Đã thêm %s → %s" % (added["error_id"], path))
        return 0
    if act == "gen-regression":
        hit = None
        if args.error_id:
            for e in load_db(args.db):
                if e.get("error_id") == args.error_id:
                    hit = e
                    break
        elif args.message:
            hit = classify_failure(args.message, stage=args.stage,
                                   db_path=args.db)
        if not hit:
            print("Cần --error-id (hoặc --message) để sinh test.")
            return 2
        src = gen_regression_test(hit, args.test_name)
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)),
                        exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(src)
            print("[failure] Đã ghi %s" % args.out)
        else:
            print(src)
        return 0
    print("Hành động không hợp lệ: %s" % act)
    return 2


def cmd_baseline(args):
    """PHASE 0 — Baseline: chụp, xem, so sánh và chặn hồi quy."""
    from .baseline import (METRICS, capture_metrics, compare_metrics,
                           capture_full, load_metrics, render_compare,
                           write_baseline, run_compare, DEFAULT_BASELINE_DIR)
    bdir = getattr(args, "dir", None) or DEFAULT_BASELINE_DIR
    if args.hanh_dong == "capture":
        overrides = {}
        for kv in (getattr(args, "set", None) or []):
            if "=" in kv:
                k, v = kv.split("=", 1)
                overrides[k.strip()] = v.strip()
        if getattr(args, "full", False):
            metrics, env = capture_full(overrides, bdir)
            from .baseline import save_metrics
            mpath = save_metrics(os.path.join(bdir, "metrics.json"), metrics)
            with open(os.path.join(bdir, "environment.json"), "w",
                      encoding="utf-8", newline="\n") as fh:
                json.dump(env, fh, ensure_ascii=False, indent=2)
        else:
            mpath = write_baseline(bdir, overrides)
            metrics, env = capture_metrics(overrides, bdir)
        print("[patchx] Đã chụp baseline: %s" % mpath)
        print("  Môi trường: %s · Python %s · load %s" % (
            env.get("machine", "?"), env.get("python", "?"),
            env.get("loadavg_1_5_15")))
        for k, v in metrics.items():
            if v is not None:
                meta = METRICS[k]
                print("  %-18s %s %s (%s)" % (k, v, meta["unit"],
                                              meta["name"]))
        return 0
    if args.hanh_dong == "show":
        metrics = load_metrics(os.path.join(bdir, "metrics.json"))
        if not metrics:
            print("[patchx] Chưa có baseline — chạy: patchx baseline capture")
            return 1
        for k, v in metrics.items():
            if v is not None:
                meta = METRICS[k]
                print("%-18s %s %s (%s)" % (k, v, meta["unit"], meta["name"]))
        return 0
    if args.hanh_dong == "compare":
        verdict, result = run_compare(args.metrics_moi, bdir)
        print(render_compare(result))
        print("[patchx] Cổng hồi quy: %s" % verdict)
        with open(os.path.join(bdir, "compare_latest.json"),
                  "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        return 0 if verdict == "ACCEPT" else 1
    return 1


def cmd_coverage(args):
    from .advisor import coverage_patch
    from .smali_sem import find_method_matches
    patch = parse_patch_file(args.patch)
    cov = coverage_patch(patch, args.cay_apk, mode=args.mode)
    print("[patchx] %s (mode %s): %d/%d quy tắc khớp, %d lần khớp" % (
        patch.name, cov["mode"], cov["quy_tắc_khớp"], cov["quy_tắc"], sum(
            d["khớp"] for d in cov["chi_tiết"])))
    for d in cov["chi_tiết"]:
        print("  khối %d (%s) target=%s: %d khớp%s" % (
            d["khối"], d["loại"], d["target"] or "<rỗng>", d["khớp"],
            "  TRƯỢT: " + ", ".join(d["tệp_trượt"][:5])
            if d["tệp_trượt"] and not d["khớp"] else ""))
        for v in d["biến_thể"][:3]:
            print("    - đề xuất mở rộng: " + v)
        if getattr(args, "method", False) and d["khớp"]:
            sec = next((s for s in patch.sections if s.order == d["khối"]), None)
            if sec is None:
                continue
            pat = (sec.get("MATCH") or "").strip()
            is_regex = sec.get("REGEX", "").strip().lower() in ("true", "1")
            for tf in d.get("tệp_trúng", [])[:10]:
                tpath = os.path.join(args.cay_apk, tf)
                if not os.path.isfile(tpath):
                    continue
                try:
                    text = open(tpath, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for mm in find_method_matches(text, pat, is_regex)[:5]:
                    print("      method %s (dòng %d): %d lần" % (
                        mm["method"], mm["line"], mm["lần"]))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(cov, fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", args.o)
    return 0


def cmd_suggest(args):
    from .advisor import suggest_patch
    from .risk import risk_findings
    patch = parse_patch_file(args.patch)
    items = suggest_patch(patch, args.cay_apk)
    risks = risk_findings(patch)
    print("[patchx] %d đề xuất cho %s:" % (len(items), patch.name))
    for it in items:
        print("  [%s] %s" % (it["mức"], it["nội_dung"]))
        print("        lý do: %s" % it["lý_do"])
    if risks:
        print("  ⚠ Cờ rủi ro (T5): %d" % len(risks))
        for r in risks:
            print("    - [%s] %s (khối %d)" % (
                r["loại"], r["nội_dung"], r["khối"]))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"patch": patch.name, "suggestions": items, "risks": risks},
                      fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", args.o)
    return 0


def cmd_analyze(args):
    if getattr(args, "dag", False):
        from .pipeline_registry import get_pipeline_registry
        reg = get_pipeline_registry()
        res = reg.run_pipeline("deep_audit", args.cay_apk)
        return 0 if res.success else 1

    from .smali_sem import build_semantic_report
    report = build_semantic_report(args.cay_apk, top=args.top)
    w = 78
    print(f"\n{C.BLD}{C.CYN}╔{'═' * (w - 2)}╗{C.RST}")
    print(f"{C.BLD}{C.CYN}║{C.RST} {C.BLD}{C.WHT}KẾT QUẢ PHÂN TÍCH NGỮ NGHĨA SÂU (SEMANTIC & TAINT FLOW){C.RST}{' ' * (w - 58)}{C.BLD}{C.CYN}║{C.RST}")
    print(f"{C.BLD}{C.CYN}╚{'═' * (w - 2)}╝{C.RST}")
    print(f"{C.BLD}Mục tiêu:{C.RST} {C.CYN}{args.cay_apk}{C.RST}")
    print(f"  {C.BLD}Application:{C.RST} {report['application'] or (C.DIM + '(không khai báo)' + C.RST)}")
    if report["launchers"]:
        print(f"  {C.BLD}Launcher:   {C.RST} {C.GRN}{', '.join(report['launchers'])}{C.RST}")

    # 1. Vấn đề Packer / Vỏ bọc (Đỏ nguy hiểm)
    if report["packers"]:
        print(f"\n  {C.BLD}{C.RED}🚨 PHÁT HIỆN PACKER / BẢO VỆ GỐC ({len(report['packers'])} phát hiện):{C.RST}")
        for pk in report["packers"][:8]:
            print(f"    {C.RED}•{C.RST} {C.BLD}{pk['nghi_ngờ']}{C.RST} ({pk['tệp']}) — {C.DIM}{pk['đường_dẫn']}{C.RST}")
    else:
        print(f"  {C.BLD}Packer:     {C.RST} {C.GRN}✅ Không phát hiện (mã nguồn mở/không đóng gói){C.RST}")

    # 2. Vấn đề Mã hóa chuỗi / R8 Obfuscation (Vàng cảnh báo)
    if report["string_encryption_suspects"]:
        print(f"\n  {C.BLD}{C.YEL}⚠️ PHÁT HIỆN MÃ HÓA CHUỖI / R8 OBFUSCATION ({len(report['string_encryption_suspects'])} tệp nghi ngờ):{C.RST}")
        for s in report["string_encryption_suspects"][:6]:
            print(f"    {C.YEL}•{C.RST} {s['tệp']} {C.DIM}(điểm nghi vấn: {s['điểm']}){C.RST}")
    else:
        print(f"  {C.BLD}Mã hóa chuỗi:{C.RST} {C.GRN}✅ Không phát hiện mã hóa chuỗi diện rộng{C.RST}")

    # 3. Đồ thị gọi hàm từ Entry (Xanh dương)
    print(f"\n  {C.BLD}{C.BLU}🌐 ĐỒ THỊ GỌI HÀM TOP {len(report['call_graph_top'])} (Tính từ Entrypoint):{C.RST}")
    for c in report["call_graph_top"][:8]:
        print(f"    {C.BLU}↳{C.RST} {c['class']:<45} {C.DIM}(gọi {c['lần']} lần){C.RST}")

    # 4. Cổng Bảo Vệ Logic (Security Gates — Zero-Workkey) (Magenta & Xanh lá)
    gates = report.get("security_gates", [])
    if gates:
        print(f"\n  {C.BLD}{C.MAG}🛡️ PHÁT HIỆN CỔNG BẢO VỆ LOGIC (SECURITY GATES — ZERO-WORKKEY): {len(gates)} CỔNG{C.RST}")
        for g in gates[:8]:
            conf = g["confidence"]
            conf_badge = f"{C.GRN}[{conf:.0f}% CAO]{C.RST}" if conf >= 80 else (f"{C.YEL}[{conf:.0f}% TB]{C.RST}" if conf >= 65 else f"{C.RED}[{conf:.0f}% THẤP]{C.RST}")
            print(f"    {C.MAG}◆{C.RST} {conf_badge} {C.BLD}{g['class']}{C.RST} -> {C.CYN}{g['method']}{C.RST}")
            print(f"      {C.DIM}Taint Source:{C.RST} {C.YEL}{g['taint_source']}{C.RST}")
            print(f"      {C.DIM}Decision:    {C.RST} {C.RED}{g['decision_branch']}{C.RST} ➔ {C.GRN}{C.BLD}Gợi ý: {g['suggested_patch']['type']}{C.RST}")
    else:
        print(f"\n  {C.DIM}Security Gates: Không phát hiện cổng logic rẽ nhánh trực tiếp.{C.RST}")

    print(f"\n  {C.BLD}{C.CYN}💡 Đề xuất can thiệp:{C.RST} {report['gợi_ý_điểm_chèn']}")
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"  {C.GRN}Đã ghi báo cáo JSON:{C.RST} {args.o}")
    print()
    return 0


def cmd_model(args):
    from .smali_sem import build_app_model, build_app_model_v2
    builder = build_app_model_v2 if args.v2 else build_app_model
    start = time.time()
    report = builder(args.cay_apk, include_bodies=args.with_bodies)
    elapsed = time.time() - start
    s = report["summary"]
    extra = (", %d method từ entry" % s["reachable_from_entry"]
             if args.v2 else ", %d nguồn dữ liệu" % s["data_sources"])
    print("[patchx] Mô hình ứng dụng %s: %d method, %d cạnh gọi, %d điểm quyết định%s" % (
        "V2" if args.v2 else "V1", s["methods"], s["call_edges"],
        s["decision_points"], extra))
    if args.bench:
        print("[patchx] model %s cache lạnh: %.3f giây" % (
            "V2" if args.v2 else "V1", elapsed))
        return 0
    default_name = "app_model_v2.json" if args.v2 else "app_model.json"
    out = args.o or os.path.join(args.cay_apk, ".patchx", default_name)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print("Đã ghi:", out)
    return 0


def cmd_semantic_plan(args):
    from .semantic_plan import (SCHEMA_V2, evaluate_plan, evaluate_plan_v2,
                                load_plan, suggest_selector_fix)
    from .smali_sem import build_app_model, build_app_model_v2
    plan = load_plan(args.ke_hoach)
    is_v2 = plan.get("schema") == SCHEMA_V2
    if args.model:
        with open(args.model, encoding="utf-8") as fh:
            model = json.load(fh)
    else:
        model = build_app_model_v2(args.cay_apk) if is_v2 else build_app_model(args.cay_apk)
    result = evaluate_plan_v2(plan, model) if is_v2 else evaluate_plan(plan, model)
    print("[patchx] Kế hoạch ngữ nghĩa: %s — %s" % (
        result["goal"], result["verdict"]))
    for target in result["targets"]:
        threshold = (target["policy"]["min_score"] if is_v2
                     else target["min_score"])
        suffix = " — MƠ HỒ, đã chặn" if target.get("ambiguous") else ""
        print("  %s: %d ứng viên đạt ngưỡng %.0f%%%s" % (
            target["name"], len(target["accepted"]), threshold, suffix))
        for candidate in target["accepted"][:5]:
            print("    - %s (%s:%d, %.1f%%)" % (
                candidate["method"], candidate["file"], candidate["line"],
                candidate["score"]))
        if getattr(args, "verbose", False):
            for candidate in target.get("rejected", [])[:5]:
                print("    x %s (%s:%d, %.1f%%) — thiếu: %s" % (
                    candidate["method"], candidate["file"], candidate["line"],
                    candidate["score"], ", ".join(candidate.get("missing", []))))
        elif target.get("rejected"):
            print("    (%d ứng viên dưới ngưỡng — dùng --verbose để xem lý do)"
                  % len(target["rejected"]))
    if result["verdict"] == "READY_FOR_PREFLIGHT":
        print("  Bước kế: người dùng duyệt thao tác → preflight → simulate/build.")
    elif result["verdict"] == "AMBIGUOUS_TARGET":
        print("  Không tự chọn mục tiêu: cần siết selector hoặc người dùng chọn ứng viên.")
    elif result["verdict"] == "INSUFFICIENT_EVIDENCE":
        print("  Thiếu evidence: cần sinh app-model/v2 trước khi đánh giá lại.")
    else:
        print("  Không tự áp thay đổi: cần bổ sung điều kiện hoặc APK mẫu.")
    if result["verdict"] != "READY_FOR_PREFLIGHT":
        if is_v2:
            for tip in suggest_selector_fix(plan, result):
                print("  Gợi ý cải thiện [%s] %s:" % (tip["target"], tip["kind"]))
                if tip.get("common_missing"):
                    print("    - thiếu chung: %s" % ", ".join(tip["common_missing"]))
                for line in tip.get("advice", []):
                    print("    - %s" % line)
        from .failure_db import classify_failure
        failure = classify_failure(result["verdict"], stage="PLAN")
        if failure:
            print("  Phân loại lỗi: %s — %s" % (
                failure["error_id"], failure["fix"]))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", args.o)
    return 0 if result["verdict"] == "READY_FOR_PREFLIGHT" else 2


def cmd_acceptance(args):
    from .acceptance import run_acceptance
    report = run_acceptance(args.fixture)
    m = report["metrics"]
    print("[patchx] Nghiệm thu V2: %s" % report["fixture"])
    print("  Tái lập model      : %.2f%% (%d/%d)" % (
        report["reproducibility"]["rate"],
        report["reproducibility"]["same"],
        report["reproducibility"]["total"]))
    if report["reidentification_rate"] is not None:
        print("  Tái nhận diện      : %.2f%%" % report["reidentification_rate"])
    variants = report.get("reidentification_variants", {})
    for name, rate in sorted(variants.items()):
        print("    Biến thể %-12s: %.2f%%" % (name, rate))
    if m["ready_total"]:
        print("  READY đúng         : %d/%d (%.2f%%)" % (
            m["ready_ok"], m["ready_total"], m["ready_rate"]))
        print("  Dương tính giả     : %.2f%%" % m["false_positive_rate"])
    if m["ambiguity_total"]:
        print("  Mơ hồ bị chặn      : %d/%d (%.2f%%)" % (
            m["ambiguity_blocked"], m["ambiguity_total"], m["ambiguity_rate"]))
    if m["no_confident_total"]:
        print("  Không tự tin bị chặn: %d/%d" % (
            m["no_confident_blocked"], m["no_confident_total"]))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", args.o)
    return 0


def cmd_knowledge(args):
    from .knowledge import (load_store, query_similar, query_similar_v2,
                            record_verified, suggest_plan_v2)
    if args.hanh_dong == "record":
        with open(args.record, encoding="utf-8") as fh:
            record = json.load(fh)
        added, total = record_verified(args.db, record)
        print("[knowledge] %s — kho có %d bản ghi" % (
            "Đã ghi outcome đã nghiệm thu" if added else "Bản ghi đã tồn tại", total))
        return 0
    if args.hanh_dong == "query":
        from .smali_sem import build_app_model, build_app_model_v2
        model = build_app_model_v2(args.cay_apk) if args.v2 else build_app_model(args.cay_apk)
        rows = (query_similar_v2(args.db, model, goal=args.goal, limit=args.top)
                if args.v2 else query_similar(args.db, model, goal=args.goal, limit=args.top))
        print("[knowledge] %d trường hợp tương tự đã verified" % len(rows))
        for row in rows:
            record = row["record"]
            print("  - %s | %s | %s → %s (%s:%d)%s" % (
                record["app"]["package"], record.get("app", {}).get("version", "—"),
                record["goal"], record["outcome"], row["file"], row["line"],
                " — %.0f%%, %s" % (row["confidence"], ",".join(row["identity_matches"]))
                if args.v2 else ""))
        print("  Kết quả chỉ là tham chiếu; vẫn cần semantic-plan + preflight.")
        return 0
    if args.hanh_dong == "suggest-plan":
        from .smali_sem import build_app_model_v2
        model = build_app_model_v2(args.cay_apk)
        plan = suggest_plan_v2(args.db, model, goal=args.goal, limit=args.top)
        if not plan:
            print("[knowledge] Không có ứng viên verified tương tự cho APK này.")
            return 2
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(plan, fh, ensure_ascii=False, indent=2)
        print("[knowledge] Đã sinh semantic-plan/V2 tham chiếu: %s (%d target)" % (
            args.o, len(plan["targets"])))
        print("  Chi la ung vien tu kho tri thuc; hay chay `patchx semantic-plan` "
              "tren APK nay va nguoi dung duyet trước preflight.")
        return 0
    print("[knowledge] %d bản ghi" % len(load_store(args.db)))
    return 0


def cmd_plan_compile(args):
    from .semantic_plan import load_plan
    from .smali_sem import build_app_model_v2
    from .plan_compile import compile_plan_v2
    plan = load_plan(args.ke_hoach)
    if plan.get("schema") != "patchx.semantic-plan/v2":
        raise ValueError("plan-compile chỉ nhận patchx.semantic-plan/v2")
    model = build_app_model_v2(args.cay_apk)
    draft = compile_plan_v2(plan, model, args.cay_apk)
    os.makedirs(os.path.dirname(os.path.abspath(args.o)), exist_ok=True)
    with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(draft, fh, ensure_ascii=False, indent=2)
    print("[patchx] Transaction nháp: %s (%d target, hash evidence đã khóa)" %
          (args.o, len(draft["selected_targets"])))
    print("  Không áp APK. Bước sau: người dùng duyệt → preflight.")
    return 0


def cmd_plan_preflight(args):
    from .plan_compile import revalidate_draft
    with open(args.draft, encoding="utf-8") as fh:
        draft = json.load(fh)
    report = revalidate_draft(draft, args.cay_apk)
    suffix = " — đã đánh giá lại plan" if report.get("recompiled") else ""
    print("[patchx] Draft evidence: %s — %s%s" % (
        report["status"], report["reason"], suffix))
    if report.get("recompiled") and getattr(args, "o", None):
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report["draft"], fh, ensure_ascii=False, indent=2)
        print("Đã ghi draft mới:", args.o)
    if report["status"] == "BLOCKED":
        if report.get("verdict"):
            print("  Verdict plan trên cây mới: %s" % report["verdict"])
        from .failure_db import classify_failure
        failure = classify_failure(report["reason"], stage="PREFLIGHT")
        if failure:
            print("  Phân loại lỗi: %s — %s" % (
                failure["error_id"], failure["fix"]))
    return 0 if report["status"] == "READY_FOR_APPROVAL" else 2


def cmd_remote_map(args):
    if args.dataflow:
        from .remote_map import build_data_flow, dataflow_summary_text
        flow = build_data_flow(args.cay_apk)
        print("[patchx] Bản đồ data-flow: %s" % args.cay_apk)
        print(dataflow_summary_text(flow))
        if args.o:
            with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(flow, fh, ensure_ascii=False, indent=2)
            print("Đã ghi:", args.o)
        return 0
    if args.flow:
        from .remote_map import build_decision_flow, flow_summary_text
        flow = build_decision_flow(args.cay_apk)
        print("[patchx] Bản đồ luồng quyết định/dữ liệu: %s" % args.cay_apk)
        print(flow_summary_text(flow))
        if args.o:
            with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(flow, fh, ensure_ascii=False, indent=2)
            print("Đã ghi:", args.o)
        return 0
    from .remote_map import build_remote_map, summary_text
    data = build_remote_map(args.cay_apk, with_atomic=not args.no_atomic)
    print("[patchx] Bản đồ flag điều khiển từ xa: %s" % args.cay_apk)
    print(summary_text(data))
    flags = data["flags"]
    n_show = args.top or 15
    rows = sorted(
        ((len(f["reads"]) + len(f["writes"]), fkey, f)
         for fkey, f in flags.items()), reverse=True)
    for score, fkey, f in rows[:n_show]:
        print("  %-45s %s  đọc=%d ghi=%d" % (
            fkey, "atomic" if f["atomic"] else "bool ",
            len(f["reads"]), len(f["writes"])))
    if args.o:
        with open(args.o, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        print("Đã ghi:", args.o)
    return 0


def cmd_remote_patch(args):
    from .remote_map import build_force_patch
    with open(args.remote_map, "r", encoding="utf-8") as fh:
        rmap = json.load(fh)
    overrides = {}
    if args.force:
        with open(args.force, "r", encoding="utf-8") as fh:
            overrides = json.load(fh)
    for spec in args.set or []:
        if "=" not in spec:
            print("[patchx] bỏ qua spec thiếu '=': %r" % spec)
            continue
        fld, _, val = spec.partition("=")
        overrides[fld.strip()] = val.strip().lower() in ("true", "1", "0x1")
    if not overrides:
        print("[patchx] Chua co override nao. Dung --set "
              "'Lcls;->fld:Z = true' hoac --force overrides.json")
        return 2
    try:
        text = build_force_patch(rmap, overrides, args.o)
    except ValueError as e:
        print("[patchx] Lỗi: %s" % e)
        return 2
    print("[patchx] Đã sinh patch: %s" % args.o)
    print(text)
    return 0


def _parse_remote_rule(spec):
    """Phan tich quy tac dieu khien tu chuoi CLI.

    Dang: match=vip_check,false;command=set_vip_status;value=true
    """
    rule = {}
    for part in spec.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError("quy tac phai co dang key=value: %s" % part)
        key, _, value = part.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "match":
            rule["match"] = [item.strip() for item in value.split(",") if item.strip()]
        elif key == "command":
            rule["command"] = value.strip()
        elif key == "value":
            rule["value"] = value.lower() in ("true", "1", "yes", "on")
        else:
            raise ValueError("khong ho tro khoa quy tac: %s" % key)
    if not rule.get("match"):
        raise ValueError("quy tac thieu match")
    if not rule.get("command"):
        raise ValueError("quy tac thieu command")
    return rule


def cmd_remote_observe(args):
    from .behavior.remote_controller import DynamicRemoteController

    hook_path = args.hook
    if not os.path.isfile(hook_path):
        print("[patchx] Khong thay hook script: %s" % hook_path)
        return 2

    log_file = args.log or os.path.join(
        os.path.dirname(os.path.abspath(hook_path)),
        "remote_observation.jsonl",
    )

    try:
        ctrl = DynamicRemoteController(args.package, args.device)
        ctrl.start_observation(log_file)
        ctrl.connect_and_inject(hook_path, mode=args.mode)
    except Exception as exc:
        print("[patchx] Khong the khoi dong remote observe: %s" % exc)
        return 1

    for spec in args.rule or []:
        try:
            rule = _parse_remote_rule(spec)
        except ValueError as exc:
            print("[patchx] Bo qua quy tac loi: %s (%s)" % (spec, exc))
            continue
        ctrl.add_condition_rule(rule)
        print("[patchx] Da them dieu kien: %s" % rule)

    print("[patchx] Dang quan sat package: %s" % args.package)
    print("[patchx] Log: %s" % log_file)

    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    if args.save:
        ctrl.save_observation(args.save)
    elif args.duration:
        ctrl.save_observation(log_file.replace(".jsonl", ".json"))

    return 0


def cmd_rodata_find(args):
    """Tìm RVA (Relative Offset) của chuỗi trong .rodata/.data của file .so."""
    from .behavior.rodata_patcher import ElfReader, find_string_offsets
    try:
        if args.string:
            hits = find_string_offsets(args.so, args.string, all_hits=args.all)
            if not hits:
                print("[patchx] Không tìm thấy chuỗi %r trong %s"
                      % (args.string, args.so))
                return 1
            print("[patchx] Tìm chuỗi %r trong %s — %d vị trí:"
                  % (args.string, args.so, len(hits)))
            for h in hits:
                print("  rva=0x%x | file=0x%x | %-16s | size=%d | %r"
                      % (h.rva, h.file_offset, h.section, h.size, h.value))
        else:
            reader = ElfReader(args.so)
            secs = reader.list_alloc_sections()
            hits = []
            print("[patchx] Section ALLOC (chứa hằng chuỗi) trong %s:"
                  % args.so)
            for s in secs:
                print("  %-20s addr=0x%x | file=0x%x | size=0x%x"
                      % (s["name"], s["addr"], s["offset"], s["size"]))
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi: %s" % exc)
        return 2

    print("[patchx] Gợi ý patch: python3 patchx rodata-patch %s "
          "--string %r --new \"<chuỗi mới>\" --mode inline|pointer|both"
          % (args.so, args.string or "<chuỗi>"))
    if args.o:
        from pathlib import Path
        out = Path(args.o)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "so": args.so,
            "needle": args.string,
            "hits": [h.to_dict() for h in hits],
        }
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print("[patchx] Đã ghi:", out)
    return 0


def cmd_rodata_patch(args):
    """Sinh script Frida patch chuỗi trong .rodata trên RAM."""
    from .behavior.rodata_patcher import write_rodata_script
    from pathlib import Path

    patches = []
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as exc:
            print("[patchx] Không đọc được config: %s" % exc)
            return 2
        if isinstance(cfg, list):
            patches = cfg
        elif isinstance(cfg, dict) and isinstance(cfg.get("patches"), list):
            patches = cfg["patches"]
            default_module = cfg.get("module") or os.path.basename(args.so)
            for p in patches:
                p.setdefault("module", default_module)
        else:
            print("[patchx] Config phải là list patch hoặc "
                  '{"patches": [...], "module": "..."}')
            return 2
        if not patches:
            print("[patchx] Config không có patch nào")
            return 2
    else:
        if not args.new_string:
            print("[patchx] Cần --new (chuỗi mới) hoặc --config")
            return 2
        patch = {
            "new_string": args.new_string,
            "mode": args.mode,
            "module": args.module or os.path.basename(args.so),
        }
        if args.string:
            patch["old_string"] = args.string
        if args.offset is not None:
            try:
                patch["rva"] = int(args.offset, 0)
            except ValueError:
                print("[patchx] --offset không hợp lệ: %r" % args.offset)
                return 2
        if args.ptr_offset is not None:
            try:
                patch["ptr_rva"] = int(args.ptr_offset, 0)
            except ValueError:
                print("[patchx] --ptr-offset không hợp lệ: %r" % args.ptr_offset)
                return 2
        if args.runtime_scan:
            patch["runtime_scan"] = True
        patches = [patch]

    from .behavior.rodata_patcher import normalize_rodata_patches
    try:
        normalized = normalize_rodata_patches(patches, so_path=args.so)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi: %s" % exc)
        return 2
    for p in normalized:
        mode = p.get("mode")
        if (mode in ("inline", "both") and not p.get("runtime_scan")
                and p.get("old_len") and p["new_len"] > p["old_len"] + 1):
            print("[patchx] Cảnh báo: chuỗi mới (%dB) dài hơn chuỗi cũ (%dB) — "
                  "inline sẽ bỏ qua lúc runtime trừ khi --allow-overflow; "
                  "nên dùng --mode pointer (--ptr-offset) để đổi con trỏ, "
                  "chuỗi mới độ dài vô hạn và không đụng dữ liệu kế bên."
                  % (p["new_len"] - 1, p["old_len"]))

    out = Path(args.o or os.path.join(
        BASE_DIR, "outputs", "behavior", "rodata_patch.js"))
    try:
        out = write_rodata_script(
            patches, out,
            restore=not args.no_restore,
            allow_overflow=args.allow_overflow,
            so_path=args.so)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi: %s" % exc)
        return 2

    print("[patchx] Đã sinh script Frida ro.data: %s" % out)
    print("[patchx] Chạy: frida -U -f <package> -l %s "
          "(hoặc nạp qua gadget-pipeline / remote-observe)" % out)
    return 0


def cmd_rodata_apply(args):
    """Chèn chuỗi mới TRỰC TIẾP vào file .so (patch file, không cần Frida)."""
    from .behavior.rodata_patcher import normalize_rodata_patches, patch_so_file
    from pathlib import Path

    patches = []
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as exc:
            print("[patchx] Không đọc được config: %s" % exc)
            return 2
        if isinstance(cfg, list):
            patches = cfg
        elif isinstance(cfg, dict) and isinstance(cfg.get("patches"), list):
            patches = cfg["patches"]
        else:
            print("[patchx] Config phải là list patch hoặc "
                  '{"patches": [...]}')
            return 2
        if not patches:
            print("[patchx] Config không có patch nào")
            return 2
    else:
        if not args.new_string:
            print("[patchx] Cần --new (chuỗi mới) hoặc --config")
            return 2
        patch = {"new_string": args.new_string, "mode": "inline"}
        if args.string:
            patch["old_string"] = args.string
        if args.offset is not None:
            try:
                patch["rva"] = int(args.offset, 0)
            except ValueError:
                print("[patchx] --offset không hợp lệ: %r" % args.offset)
                return 2
        patches = [patch]

    try:
        normalized = normalize_rodata_patches(patches, so_path=args.so)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi: %s" % exc)
        return 2
    for p in normalized:
        if p.get("mode") != "inline":
            print("[patchx] rodata-apply chỉ hỗ trợ inline; bỏ qua %r"
                  % (p.get("label") or p.get("new_string")))
        if (p.get("old_len") and p["new_len"] > p["old_len"] + 1):
            print("[patchx] Cảnh báo: chuỗi mới (%dB) dài hơn chuỗi cũ (%dB) — "
                  "patch file sẽ lỗi trừ khi --allow-overflow."
                  % (p["new_len"] - 1, p["old_len"]))

    try:
        report = patch_so_file(
            args.so, patches,
            out_path=args.out,
            allow_overflow=args.allow_overflow,
            backup=not args.no_backup,
            backup_dir=args.backup_dir)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi: %s" % exc)
        return 2

    print("[patchx] Đã patch file: %s" % report["out"])
    if report.get("backup"):
        print("[patchx] Backup: %s" % report["backup"])
    for p in report["patched"]:
        print("  rva=0x%x | offset=0x%x | %s | %r -> %r%s" % (
            p["rva"], p["file_offset"], p["section"],
            p["old_value"], p["new_value"],
            " (TRÀN)" if p["overflow"] else ""))
    return 0


def cmd_smart_scan(args):
    """Quét chuỗi .rodata/.data thông minh (4 trụ cột + Confidence Score)."""
    from .behavior.smart_scanner import scan_so, render_markdown
    if args.behaviors:
        from .behavior.smart_ontology import render_behavior_catalog
        print(render_behavior_catalog())
        return 0
    if args.benchmark:
        return cmd_neon_bench_args(args.benchmark, args.o)
    try:
        report = scan_so(args.so, min_len=args.min_len,
                         min_risk=args.min_risk, show_noise=args.show_noise,
                         scan_refs=args.scan_refs, native=args.native)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi smart-scan: %s" % exc)
        return 2

    s = report["summary"]
    print("[patchx] Quét thông minh: %s" % report["repro"]["file"])
    print("  SHA-256: %s..." % report["repro"]["file_sha256"][:16])
    engine = "NEON native" if s.get("native_engine") == "neon" else "Python thuần"
    print("  Động cơ quét chuỗi: %s" % engine)
    print("  Chuỗi: %d | Giữ: %d | Lọc nhiễu: %d | FP loại: %d"
          % (s["total_strings"], s["kept"], s["noise_dropped"],
             s["false_positive_removed"]))
    print("  Tham chiếu: %d (JNI: %d) | Cao: %d | TB: %d | Thấp: %d | "
          "TB confidence: %.1f%%"
          % (s["refs_found"], s["jni_refs"], s["flagged_high"],
             s["flagged_medium"], s["flagged_low"], s["confidence_avg"]))

    for f in report["findings"][:15]:
        print("  [%3d%%] rva=0x%-6x %-10s %-12s %r"
              % (f["confidence"], f["rva"], f["category"].upper(),
                 f["section"], f["value"][:60]))
    if len(report["findings"]) > 15:
        print("  ... còn %d finding — xem JSON/Markdown đầy đủ"
              % (len(report["findings"]) - 15))

    from pathlib import Path
    if getattr(args, "jni", False):
        from .behavior.rodata_patcher import ElfReader
        from .behavior.smart_scanner import (scan_register_natives,
                                             render_frida_for_natives)
        try:
            reader = ElfReader(args.so)
            jni_rep = scan_register_natives(reader)
        except (ValueError, OSError) as exc:
            print("[patchx] Lỗi phân tích bảng RegisterNatives: %s" % exc)
            jni_rep = None
        if jni_rep is not None:
            report["jni_natives"] = jni_rep
            print("[patchx] Bảng RegisterNatives: symbol=%s · %s-bit · mục=%d"
                  % (jni_rep["has_register_natives_symbol"],
                     jni_rep["arch"], jni_rep["count"]))
            for e in jni_rep["entries"][:20]:
                print("  - %-28s %-16s fn=0x%x (bảng @ 0x%x)"
                      % (e["name"], e["signature"], e["fn_rva"],
                         e["table_offset"]))
            if getattr(args, "jni_frida", None):
                script = render_frida_for_natives(
                    jni_rep, module_name=Path(args.so).name)
                p = Path(args.jni_frida)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(script, encoding="utf-8")
                print("[patchx] Đã ghi Frida hook:", p)

    base = Path(args.o) if args.o else None
    md_path = Path(args.md) if args.md else None
    if base is None:
        out_dir = Path(BASE_DIR) / "outputs" / "behavior" / "smart_scan"
        out_dir.mkdir(parents=True, exist_ok=True)
        import time as _t
        stamp = _t.strftime("%Y%m%d-%H%M%S")
        stem = Path(args.so).name
        base = out_dir / ("%s_%s.json" % (stem, stamp))
        md_path = md_path or out_dir / ("%s_%s.md" % (stem, stamp))
    base = Path(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    print("[patchx] Đã ghi JSON:", base)
    if md_path is not None:
        md_path = Path(md_path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(report), encoding="utf-8")
        print("[patchx] Đã ghi Markdown:", md_path)
    _learn_behavior(report, args.so)
    return 0


def cmd_neon_bench_args(size_mb: int, out_json) -> int:
    """Chạy phép đo NEON vs Python từ cờ --benchmark của smart-scan."""
    from .neon_scan import benchmark as neon_benchmark, native_status, compile_native
    st = native_status()
    print("[patchx] Đo tốc độ NEON (biên dịch clang -O3 tại chỗ)")
    if not compile_native():
        print("  %sLỗi biên dịch:%s %s" % (C.RED, C.RST, st.get("error")))
        return 2
    res = neon_benchmark(size_mb=size_mb, iterations=3)
    print("  Python thuần: %.2f GB/s | NEON native: %.2f GB/s | nhanh hơn %sx"
          % (res["python_gbps"], res["native_gbps"], res.get("speedup")))
    print("  Kết quả khớp nhau: dải byte=%s · mẫu chính xác=%s"
          % (res.get("same_runs"), res.get("same_find")))
    if out_json:
        from pathlib import Path
        p = Path(out_json)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(res, ensure_ascii=False, indent=2),
                     encoding="utf-8")
        print("[patchx] Đã ghi JSON:", p)
    return 0


def cmd_neon_bench(args):
    """Lệnh riêng: đo tốc độ GB/s thật của đường quét NEON ARM64."""
    from .neon_scan import benchmark as neon_benchmark, native_status, compile_native
    st = native_status()
    print(f"{C.BLD}{C.CYN}Đo tốc độ quét NEON ARM64 (không tự nhận số ảo){C.RST}")
    if not compile_native():
        print(f"  {C.RED}Lỗi biên dịch:{C.RST} {st.get('error')}")
        return 2
    res = neon_benchmark(size_mb=args.size_mb, needle=args.needle.encode("utf-8", "replace"),
                         iterations=max(1, args.iterations))
    if not res.get("native_available"):
        print(f"  {C.RED}Không dùng được đường native:{C.RST} {res.get('error')}")
        return 2
    print("  Python thuần: %.2f GB/s" % res["python_gbps"])
    print("  NEON native : %.2f GB/s" % res["native_gbps"])
    print("  Tỉ lệ tăng tốc: %sx" % res.get("speedup"))
    print("  Kết quả khớp nhau: dải byte=%s · mẫu chính xác=%s"
          % (res.get("same_runs"), res.get("same_find")))
    if args.o:
        from pathlib import Path
        p = Path(args.o)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[patchx] Đã ghi JSON:", p)
    return 0


def cmd_start_scan(args):
    """start-scan — xử lý THƯ VIỆN lib .so (APK/thư mục/file) -> báo cáo tổng hợp.
    Tách biệt: start-scan = native .so; behavior = smali."""
    from .behavior.smart_scanner import (start_scan,
                                         render_start_scan_markdown)
    try:
        report = start_scan(args.target, abi=args.abi, min_len=args.min_len,
                            min_risk=args.min_risk, show_noise=args.show_noise,
                            keep_extract=args.keep_so, native=args.native)
    except (ValueError, OSError) as exc:
        print("[patchx] Lỗi start-scan: %s" % exc)
        return 2

    s = report["summary"]
    print("[patchx] start-scan: %s" % report["repro"]["target"])
    print("  Lib: %d (OK %d · lỗi %d) | Chuỗi: %d | Finding: %d | Nhiễu: %d"
          % (s["libs_scanned"], s["libs_ok"], s["libs_errored"],
             s["total_strings"], s["total_findings"], s["total_noise"]))
    print("  Động cơ quét: %d lib NEON native · %d lib Python thuần"
          % (s.get("neon_libs", 0), s.get("python_libs", 0)))
    print("  Tham chiếu: %d (JNI: %d) | Cao: %d | TB: %d | Thấp: %d | "
          "TB confidence: %.1f%%"
          % (s["refs_found"], s["jni_refs"], s["flagged_high"],
             s["flagged_medium"], s["flagged_low"], s["confidence_avg"]))

    # phân chia hiển thị: CAO / TRUNG BÌNH / THẤP, trong nhóm theo Confidence
    groups = {"CAO (≥75)": [], "TRUNG BÌNH (50-74)": [], "THẤP (<50)": []}
    for f in report["top_findings"]:
        if f["confidence"] >= 75:
            groups["CAO (≥75)"].append(f)
        elif f["confidence"] >= 50:
            groups["TRUNG BÌNH (50-74)"].append(f)
        else:
            groups["THẤP (<50)"].append(f)
    for gname, items in groups.items():
        if not items:
            continue
        print("\n  == %s ==" % gname)
        for f in items[:8]:
            print("  [%3d%%] %-28s %-9s %r"
                  % (f["confidence"], f["lib_name"], f["category"].upper(),
                     f["value"][:50]))
        if len(items) > 8:
            print("  ... còn %d finding — xem JSON/Markdown đầy đủ"
                  % (len(items) - 8))

    from pathlib import Path
    base = Path(args.o) if args.o else None
    md_path = Path(args.md) if args.md else None
    if base is None:
        out_dir = Path(BASE_DIR) / "outputs" / "behavior" / "smart_scan"
        out_dir.mkdir(parents=True, exist_ok=True)
        import time as _t
        stamp = _t.strftime("%Y%m%d-%H%M%S")
        stem = Path(args.target).name
        base = out_dir / ("start_scan_%s_%s.json" % (stem, stamp))
        md_path = md_path or out_dir / ("start_scan_%s_%s.md" % (stem, stamp))
    base = Path(base)
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    print("[patchx] Đã ghi JSON:", base)
    if md_path is not None:
        md_path = Path(md_path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_start_scan_markdown(report),
                           encoding="utf-8")
        print("[patchx] Đã ghi Markdown:", md_path)
    _learn_behavior(report, args.target)
    return 0


def _learn_behavior(report, source):
    """Tự động ghi nhận hành vi MỚI phát hiện sau mỗi lần quét."""
    try:
        from .behavior.behavior_learner import learn_from_report
        new = learn_from_report(report, source=str(source))
        if new:
            print("[patchx] Hành vi mới phát hiện (%d): %s"
                  % (len(new), ", ".join(sorted(new))))
            print("[patchx]   -> %s"
                  % os.path.join("outputs", "behavior", "discovered",
                                 "behaviors.json"))
    except Exception as exc:
        print("[patchx] Cảnh báo learner: %s" % exc)


def cmd_menu(args):
    """Danh sách chức năng để lựa chọn pipeline (menu)."""
    from .feature_menu import main as feature_menu_main
    argv = []
    if args.list:
        argv.append("--list")
    if args.goal:
        argv += ["--goal", args.goal]
    if args.run:
        argv += ["--run", args.run]
    for kv in args.set or []:
        argv += ["--set", kv]
    if args.no_confirm:
        argv.append("--no-confirm")
    return feature_menu_main(argv)


def cmd_diff_apk(args):
    from .diffapk import (build_patch, prepare_tree, verify_rebuild,
                          write_patch_zip)
    goc, goc_decoded, goc_tmp = prepare_tree(args.goc, args.keep_trees)
    mod, mod_decoded, mod_tmp = prepare_tree(args.da_mod, args.keep_trees)
    try:
        patch_text, assets, stats = build_patch(goc, mod, args.name)
        out = args.o or os.path.join(
            os.getcwd(), "diff_apk_%s.zip"
            % time.strftime("%Y%m%d-%H%M%S"))
        if out.lower().endswith(".zip"):
            write_patch_zip(out, patch_text, assets)
        else:
            with open(out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(patch_text)
            adir = os.path.join(os.path.dirname(out), "assets")
            for name, data in assets.items():
                full = os.path.join(adir, name[len("assets/"):])
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "wb") as fh:
                    fh.write(data)
        print("[patchx] diff-apk: thêm %d, sửa %d, xóa %d (binary đổi %d bỏ qua)"
              % (len(stats["added"]), len(stats["changed"]),
                 len(stats["removed"]), len(stats["binary_changed"])))
        print("  Đã ghi: %s" % out)
        if args.semantic_plan:
            from .smali_sem import build_app_model
            from .semantic_plan import plan_from_model_diff
            semantic = plan_from_model_diff(
                build_app_model(goc), build_app_model(mod),
                goal="Thay đổi rút ra từ %s" % args.name)
            os.makedirs(os.path.dirname(os.path.abspath(args.semantic_plan)),
                        exist_ok=True)
            with open(args.semantic_plan, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(semantic, fh, ensure_ascii=False, indent=2)
            print("  Kế hoạch ngữ nghĩa tham chiếu: %s (%d target)" % (
                args.semantic_plan, len(semantic["targets"])))
        if args.version_map or args.semantic_plan_v2:
            from .smali_sem import build_app_model_v2
            from .diffapk import match_app_models_v2
            from .semantic_plan import plan_v2_from_version_map
            original_v2 = build_app_model_v2(goc)
            modified_v2 = build_app_model_v2(mod)
            version_map = match_app_models_v2(original_v2, modified_v2)
            if args.semantic_plan_v2:
                semantic_v2 = plan_v2_from_version_map(
                    version_map, original_v2, modified_v2,
                    goal="Thay đổi tham chiếu từ %s" % args.name)
                os.makedirs(os.path.dirname(os.path.abspath(args.semantic_plan_v2)),
                            exist_ok=True)
                with open(args.semantic_plan_v2, "w", encoding="utf-8", newline="\n") as fh:
                    json.dump(semantic_v2, fh, ensure_ascii=False, indent=2)
                print("  Kế hoạch ngữ nghĩa V2 (chỉ tham chiếu): %s (%d target)" % (
                    args.semantic_plan_v2, len(semantic_v2["targets"])))
            if args.version_map:
                os.makedirs(os.path.dirname(os.path.abspath(args.version_map)), exist_ok=True)
                with open(args.version_map, "w", encoding="utf-8", newline="\n") as fh:
                    json.dump(version_map, fh, ensure_ascii=False, indent=2)
                s = version_map["summary"]
                print("  Bản đồ phiên bản: exact=%d, structural=%d, semantic=%d, unknown=%d" % (
                    s["exact"], s["structural"], s["semantic"], s["unknown"]))
        for k in stats["added"][:5]:
            print("  + %s" % k)
        for k in stats["changed"][:5]:
            print("  ~ %s" % k)
        if not args.no_verify:
            v = verify_rebuild(goc, mod, out)
            print("[patchx] Vòng khép kín: tái sinh %s (khớp %d/%d tệp text)"
                  % (v["tỷ_lệ"], v["khớp"], v["tổng"]))
            if v["tỷ_lệ"] >= 90:
                print("  NGHIỆM THU ĐẠT (≥ 90%)")
            else:
                print("  Chưa đạt mốc 90%% — xem các tệp lệch.")
        return 0
    finally:
        import shutil
        if goc_tmp and args.keep_trees is None:
            shutil.rmtree(goc_tmp, ignore_errors=True)
        if mod_tmp and args.keep_trees is None:
            shutil.rmtree(mod_tmp, ignore_errors=True)


def cmd_suggest_apk(args):
    from .learn import suggest_plan
    from .optimizer import CAP_LABELS
    plan = suggest_plan(args.cay_apk, args.thu_muc, top=args.top)
    print("[patchx] Danh mục: %s | package: %s" % (
        plan["danh_mục"], plan["package"] or "(chưa rõ)"))
    if not plan["khớp"]:
        print("  Không có patch khớp APK này.")
    for s in plan["khớp"]:
        print("  %-36s %4.0f%%  %s" % (
            s["patch"], s["tỷ_lệ"] * 100,
            ",".join(CAP_LABELS.get(c, c) for c in s["năng_lực"])))
    print("  " + plan["gợi_ý"])
    if plan["combo_đã_thành_công"]:
        print("  Combo đã thành công cùng danh mục:")
        for e in plan["combo_đã_thành_công"]:
            print("    - %s (lúc %s)" % (e.get("combo"), e.get("ts")))
    if args.o:
        os.makedirs(args.o, exist_ok=True)
        with open(os.path.join(args.o, "suggest_apk.json"), "w",
                  encoding="utf-8", newline="\n") as fh:
            json.dump(plan, fh, ensure_ascii=False, indent=2)
        print("Đã ghi:", os.path.join(args.o, "suggest_apk.json"))
    return 0


def cmd_suggest_llm(args):
    from .learn import suggest_by_intent, build_skeleton
    from .session import load_patch_map
    from .optimizer import CAP_LABELS
    patches = load_patch_map(args.thu_muc)
    scored, caps = suggest_by_intent(" ".join(args.y_dinh), patches)
    print("[patchx] Ý định → năng lực: %s" % ", ".join(
        CAP_LABELS.get(c, c) for c in caps))
    if not scored:
        print("  Không tìm thấy patch phù hợp — thử từ khóa khác.")
        return 0
    for s in scored[:args.top]:
        print("  %-36s %s" % (s["patch"], ",".join(
            CAP_LABELS.get(c, c) for c in s["năng_lực"])))
    selected = [s["patch"] for s in scored[:args.top]]
    print("Khung combo đề xuất (%d patch): %s" % (
        len(selected), ", ".join(selected)))
    if not args.approve:
        print("Chạy lại với --approve để ghi khung combo (người dùng duyệt).")
        return 0
    merged, conflicts = build_skeleton(patches, selected,
                                       "suggest_llm_%s" % time.strftime("%Y%m%d-%H%M%S"))
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "combos", "combos_llm")
    os.makedirs(out_dir, exist_ok=True)
    fname = os.path.join(out_dir, merged.name + ".zip")
    from .combo import render_patch_text
    import zipfile
    with zipfile.ZipFile(fname, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("patch.txt", render_patch_text(
            merged, header="Gợi ý LLM cục bộ (%s) — đã duyệt"
                           % " ".join(args.y_dinh)))
        for sec in merged.sections:
            if sec.type in ("ADD_FILES", "HOOK_SCRIPT", "REPLACE_FILES"):
                src = sec.get("SOURCE") or ""
                for name, data in (getattr(merged, "assets", {}) or {}).items():
                    if name == src:
                        zf.writestr(name, data)
    print("Đã ghi khung combo (đã duyệt): %s (%d xung đột tách)"
          % (fname, conflicts))
    return 0


def cmd_roadmap(args):
    from .advisor import build_roadmap, render_roadmap
    items = build_roadmap(args.thu_muc, args.cay_apk)
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "roadmap")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "roadmap.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "items": items}, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "roadmap.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_roadmap(items))
    print("[patchx] Đã sinh roadmap.md + roadmap.json cho %d patch" % len(items))
    for it in items[:8]:
        print("  %-32s %5.0f%%  %d khớp" % (it["patch"], it["tỷ_lệ"] * 100, it["lần_khớp"]))
    return 0


def cmd_simulate(args):
    from .simulate import run_simulation, render_simulation
    summary = run_simulation(args.thu_muc, quick=args.quick,
                             dex_runner=args.dex_runner,
                             dex_timeout=args.dex_timeout,
                             apk_tree=args.apk)
    out_dir = args.o or os.path.join(BASE_DIR, "outputs", "simulate")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "simulation.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "simulation_report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_simulation(summary))
    print("[patchx] Mô phỏng %d patch: ĐẠT %d | THẤT-BẠI %d | BỎ-QUA %d | LỖI %d"
          % (summary["tổng_patch"], summary["đạt"], summary["thất_bại"], summary["bỏ_qua"], summary["lỗi"]))
    v2 = summary.get("status_v2", {})
    if v2:
        print("[patchx] V2 — PASS %d | EXPECTED_SKIP %d | UNSUPPORTED %d | BAD_PATCH %d | ENGINE_LIMIT %d | cache %d" % (
            v2.get("PASS", 0), v2.get("EXPECTED_SKIP", 0), v2.get("UNSUPPORTED", 0),
            v2.get("BAD_PATCH", 0), v2.get("ENGINE_LIMIT", 0), summary.get("cache_hits", 0)))
    print("[patchx] Tỷ lệ đạt %s%% — tổng %s ms, trung bình %s ms/patch" % (
        summary["tỷ_lệ_đạt"], summary["tổng_thời_gian_ms"], summary["trung_bình_ms_patch"]))
    print("Đã ghi:", os.path.join(out_dir, "simulation_report.md"))
    return 0


def cmd_selfcheck(args):
    import importlib
    root = args.thu_muc
    if not root:
        suite_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for cand in (os.path.join(suite_root, "upgraded"), suite_root, os.path.dirname(suite_root)):
            if glob.glob(os.path.join(cand, "*.zip")):
                root = cand
                break
        root = root or suite_root
    elif not glob.glob(os.path.join(root, "*.zip")):
        print("[patchx] CẢNH BÁO: không thấy tệp .zip trong %s" % root)
    args.thu_muc = root
    ok_mods = []
    for m in ("model", "parser", "engine", "audit", "optimizer", "advisor", "indexer", "simulate"):
        try:
            importlib.import_module("patchx_core." + m)
            ok_mods.append(m)
        except Exception as e:
            print("[patchx] LỖI import patchx_core.%s: %s" % (m, e))
    from .parser import parse_patch_file
    from .audit import parse_nested_zip
    total = bad = 0
    for z in sorted(glob.glob(os.path.join(args.thu_muc, "*.zip"))):
        try:
            p = parse_patch_file(z)
            total += 1
            for msg in p.issues:
                if msg.startswith("[ZIP]"):
                    print("[patchx] CẢNH BÁO %s: %s" % (os.path.basename(z), msg))
        except ValueError:
            nested = parse_nested_zip(z)
            total += len(nested)
        except Exception as e:
            bad += 1
            print("[patchx] LỖI phân tích %s: %s" % (os.path.basename(z), e))
    print("[patchx] Tự kiểm tra: %d/%d module OK, %d patch đọc được, %d lỗi" % (len(ok_mods), 8, total, bad))
    if args.full:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__)))))
        import importlib.util
        tests = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "run_tests.py")
        spec = importlib.util.spec_from_file_location("run_tests", tests)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.main()
    return 0 if (len(ok_mods) == 8 and bad == 0) else 1


def cmd_combo(args):
    from .combo import collect_patches, build_combos, render_combo_report
    patches = collect_patches(args.thu_muc, recursive=args.recursive)
    if getattr(args, "apk", None):
        from .advisor import coverage_patch
        keep = []
        for p in patches:
            try:
                cov = coverage_patch(p, args.apk)
            except Exception:
                cov = None
            if cov and cov["quy_tắc_khớp"] > 0:
                keep.append(p)
        print("[patchx] combo --apk: giữ %d/%d patch khớp APK %s" % (len(keep), len(patches), args.apk))
        patches = keep
    if args.auto:
        from .complement import discover_combos, render_auto_report
        combos, isolated = discover_combos(patches)
        suite_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out_dir = args.o or os.path.join(suite_root, "combos_auto")
        os.makedirs(out_dir, exist_ok=True)
        summary = {"patches": len(patches), "combos": [], "isolated": isolated}
        for cb in combos:
            fpath = os.path.join(out_dir, cb["file"])
            header = "Combo tự phát hiện: %s (%d patch)" % (cb["label"], len(cb["patches"]))
            with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(render_patch_text(cb["merged"], header=header))
            summary["combos"].append({
                "label": cb["label"], "file": cb["file"],
                "patches": cb["patches"], "sections": cb["sections"],
                "conflicts": cb.get("conflicts", 0)})
            print("[patchx] Combo tự %s -> %s (%d khối từ %d patch%s)" % (
                cb["label"], cb["file"], cb["sections"], len(cb["patches"]),
                ", %d xung đột tách" % cb.get("conflicts", 0) if cb.get("conflicts", 0) else ""))
        with open(os.path.join(out_dir, "_auto_combos.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(summary, fh, ensure_ascii=False, indent=2)
        with open(os.path.join(out_dir, "auto_combos_report.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_auto_report(combos, isolated, len(patches)))
        print("[patchx] Tự phát hiện %d combo từ %d patch (%d patch cô lập) vào %s" % (
            len(combos), len(patches), len(isolated), out_dir))
        return 0
    only = [c.strip() for c in args.only.split(",")] if args.only else None
    combos = build_combos(patches, only=only)
    suite_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = args.o or os.path.join(suite_root, "combos")
    os.makedirs(out_dir, exist_ok=True)
    summary = {"patches": len(patches), "combos": []}
    for cb in combos:
        fpath = os.path.join(out_dir, cb["file"])
        header = "Combo: %s (%d patch)" % (cb["label"], len(cb["patches"]))
        with open(fpath, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_patch_text(cb["merged"], header=header))
        summary["combos"].append({
            "label": cb["label"], "file": cb["file"],
            "patches": cb["patches"], "sections": cb["sections"],
            "conflicts": cb["conflicts"]})
        print("[patchx] Combo %s -> %s (%d khối từ %d patch%s)" % (
            cb["label"], cb["file"], cb["sections"], len(cb["patches"]),
            ", %d xung đột tách" % cb["conflicts"] if cb["conflicts"] else ""))
    with open(os.path.join(out_dir, "_combos.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "combos_report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_combo_report(combos, len(patches)))
    print("[patchx] Đã tạo %d combo từ %d patch vào %s" % (len(combos), len(patches), out_dir))
    return 0


def cmd_ui(args):
    from .terminal_ui import run_terminal_ui
    return run_terminal_ui(BASE_DIR, demo=args.demo)


def cmd_behavior(args):
    from .behavior.detector import BehaviorDetector
    root = args.thu_muc
    print("[patchx] Phân tích hành vi:")
    print("  Cây APK: %s" % root)
    detector = BehaviorDetector(root)
    behaviors = detector.scan()
    if not behaviors:
        print("  Không phát hiện hành vi.")
        return 0
    print()
    for behavior in sorted(behaviors, key=lambda x: x.confidence, reverse=True):
        meta = BEHAVIORS.get(behavior.name, {})
        label = meta.get("label", behavior.name)
        flow_alias = flow_alias_for_behavior(behavior.name)
        print("  %-32s %-28s %.1f%%" % (label, flow_alias, behavior.confidence * 100))
        for ev in behavior.evidence[:5]:
            print("      [%s] %s" % (ev.kind, ev.value))
    return 0


def cmd_targets(args):
    from .behavior.detector import BehaviorDetector
    from .behavior.target import TargetAnalyzer
    root = args.thu_muc
    print("[patchx] Xác định mục tiêu sửa đổi:")
    print("  Cây APK: %s" % root)
    detector = BehaviorDetector(root)
    behaviors = detector.scan()
    analyzer = TargetAnalyzer(root)
    targets = analyzer.analyze(behaviors)
    if not targets:
        print("\n  Khong tim thay mức tieu.")
        return 0
    print("\n  Phat hien %d mức tieu:\n" % len(targets))
    for number, target in enumerate(targets, 1):
        print("  [%d] %-24s %.1f%%" % (number, target.category, target.confidence * 100))
        if target.source:
            print("      Tệp        : %s" % target.source)
        if target.class_name:
            print("      Lớp        : %s" % target.class_name)
        if target.method:
            print("      Phương thức : %s" % target.method)
        if target.line is not None:
            print("      Dòng        : %s" % target.line)
        print("      Lý do       : %s" % target.reason)
        for ev in target.evidence[:3]:
            print("      Bằng chứng  : [%s] %s" % (ev.get("kind", ""), ev.get("value", "")))
        print()
    return 0


def cmd_fused_targets(args):
    """targets-fused — Xác định và phân hạng mục tiêu hợp nhất đa nguồn (Behavior + Security Gates)."""
    from .fused_target_engine import (
        fuse_analysis_targets,
        apply_fused_targets,
        generate_fused_frida_script,
        render_fused_targets_markdown,
    )
    tree = args.thu_muc
    if not os.path.isdir(tree):
        print("[patchx] ❌ Lỗi: Thư mục cây Smali không tồn tại: %s" % tree)
        return 1

    out_dir = args.out_dir or os.path.join(BASE_DIR, "outputs", "targets_fused")
    os.makedirs(out_dir, exist_ok=True)

    print("[patchx] 🎯 Đang phân tích mục tiêu hợp nhất (Target-Driven Engine)...")
    print("  Cây Smali: %s" % tree)
    res = fuse_analysis_targets(
        tree,
        min_behavior_score=args.min_score,
        min_gate_confidence=args.min_confidence,
    )
    summary = res.get("summary", {})
    targets = res.get("targets", [])

    print("\n[patchx] Đã tìm thấy %d mục tiêu:" % summary.get("total_fused", 0))
    print("  • Hạng 1 (DUAL_CONFIRMED) : %d (Xác thực kép 100%%)" % summary.get("dual_confirmed", 0))
    print("  • Hạng 2 (SECURITY_GATE)  : %d (Cổng rẽ nhánh Zero-Workkey)" % summary.get("security_gates", 0))
    print("  • Hạng 3 (BEHAVIOR_TARGET): %d (Mục tiêu nghiệp vụ)" % summary.get("behavior_targets", 0))

    for idx, t in enumerate(targets[:15], 1):
        tier_color = C.RED if t["tier"] == "DUAL_CONFIRMED" else (C.YEL if t["tier"] == "SECURITY_GATE" else C.CYN)
        print("  [%d] %s[%s]%s %s -> %s (%.1f%%)" % (
            idx, tier_color, t["tier"], C.RST, t.get("class_clean", ""), t.get("method", ""), round(t.get("confidence", 0.0)*100, 1)
        ))
        if t.get("decision_branch"):
            print("      Nhánh rẽ: %s" % t.get("decision_branch"))
        if t.get("suggested_patch"):
            print("      Gợi ý vá : %s" % t.get("suggested_patch"))

    json_path = os.path.join(out_dir, "fused_targets.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)

    md_path = os.path.join(out_dir, "fused_targets.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_fused_targets_markdown(res))

    if getattr(args, "frida_hook", None):
        frida_file = args.frida_hook if isinstance(args.frida_hook, str) and args.frida_hook.endswith(".js") else os.path.join(out_dir, "fused_hook.js")
        generate_fused_frida_script(res, frida_file)
        print("\n[patchx] 💉 Đã sinh Frida hook: %s" % frida_file)

    if getattr(args, "apply", False):
        print("\n[patchx] ⚙️ Đang can thiệp tự động theo Target (Zero-Editor)...")
        min_conf = args.min_confidence / 100.0 if args.min_confidence > 1.0 else args.min_confidence
        patch_res = apply_fused_targets(tree, res, min_confidence=min_conf)
        print("  • Đã can thiệp thành công: %d cổng logic" % patch_res.get("static_gates_applied", 0))
        print("  • Tổng số mục tiêu nhắm tới: %d" % patch_res.get("applied_targets_count", 0))

    print("\n[patchx] Báo cáo đã lưu tại: %s" % out_dir)
    return 0


def cmd_smart_patch(args):
    """smart-patch — bản patch thông minh smali, tái dùng detector behavior."""
    from .behavior.smart_patch import apply_smart_patch
    out_dir = args.out_dir or os.path.join(
        BASE_DIR, "outputs", "behavior", "smart_patch")
    print("[patchx] Chay smart-patch (smali, chong R8/D8):")
    print("  detector behavior -> target -> rank -> [--apply] backup + patch")
    print("  Cây APK: %s" % args.thu_muc)
    try:
        report = apply_smart_patch(
            args.thu_muc,
            out_dir=out_dir,
            min_score=args.min_score,
            apply=args.apply,
        )
    except Exception as exc:
        print("[patchx] LỖI smart-patch: %s" % exc)
        return 1
    stats = report["plan"]["stats"]
    print("[patchx] Hanh vi: %d | Target: %d (R8/D8: %d)" % (
        stats["behaviors"], stats["targets_ranked"],
        stats["r8_d8_targets"]))
    patched = report.get("patched")
    if patched:
        print("[patchx] Da patch: %d thanh cong, %d loi" % (
            patched["success"], patched["failed"]))
        print("[patchx] Backup: %s" % patched["backup_dir"])
    else:
        print("[patchx] Chi lap ke hoach (dung --apply de ghi smali, "
              "backup tu dong)")
    print("[patchx] Bao cao: %s" % out_dir)
    return 0


def cmd_pairip_bypass(args):
    """pairip-bypass — vô hiệu hóa PairIP (license check) trên cây APK."""
    from .behavior.pairip_bypass import apply_pairip_bypass
    out_dir = args.out_dir or os.path.join(
        BASE_DIR, "outputs", "behavior", "pairip_bypass")
    print("[patchx] Chay pairip-bypass:")
    print("  detect -> plan -> [--apply] backup + patch (idempotent)")
    print("  Cây APK: %s" % args.thu_muc)
    try:
        report = apply_pairip_bypass(
            args.thu_muc,
            out_dir=out_dir,
            apply=args.apply,
            backup=not args.no_backup,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        print("[patchx] LỖI pairip-bypass: %s" % exc)
        return 1
    det = report["detected"]
    if not det["found"]:
        print("[patchx] KHONG phat hien PairIP (com.pairip.*) trong cay APK.")
        print("[patchx] Bao cao: %s" % out_dir)
        return 0
    stats = report["plan"]["stats"]
    print("[patchx] PairIP: co | Manifest khớp: %d | Lib native: %d" % (
        len(det["manifest_hits"]), len(det["native_libs"])))
    print("[patchx] Plan: %d muc | Can va: %d | Da va san: %d | "
          "Thieu file/method: %d" % (
              stats["total"], stats["patchable"],
              stats["already_patched"],
              stats["not_found"] + stats["method_missing"]))
    patched = report.get("patched")
    if patched:
        print("[patchx] Da patch: %d thanh cong, %d loi (da va san: %d)" % (
            patched["success"], patched["failed"], patched.get("already", 0)))
        print("[patchx] Backup: %s" % patched.get("backup_dir") or "—")
    else:
        print("[patchx] Chi lap ke hoach (dung --apply de ghi smali, "
              "backup tu dong)")
    print("[patchx] Bao cao: %s" % out_dir)
    return 0


def cmd_behavior_pipeline(args):
    from .behavior.pipeline import run_frida_pipeline

    flow_key = normalize_flow_name(getattr(args, "flow", "all"))
    flow_def = get_flow_definition(flow_key)
    allowed = set(flow_def.get("behaviors", [])) if flow_def else set()

    print("[patchx] Chay luong behavior pipeline:")
    print("  detector -> cfg -> target -> hook.json -> frida -> loader -> APK")
    print("  Luong: %s (%s)" % (flow_key, flow_def.get("title", "tat ca")))
    print("  Cây APK: %s" % args.thu_muc)
    print("  Thu mức ra: %s" % args.out_dir)

    try:
        report = run_frida_pipeline(
            args.thu_muc,
            out_dir=args.out_dir,
            auto_patch=args.auto_patch,
            build_apk=args.build_apk,
            min_score=args.min_score,
            interactive=args.interactive,
            behavior_filter=allowed or None,
        )
    except Exception as exc:
        print("[patchx] LỖI pipeline: %s" % exc)
        return 1

    print("[patchx] Da phat hien %d behavior, %d cfg artifact, %d target." % (
        len(report.get("behaviors", [])),
        len(report.get("cfg_artifacts", [])),
        len(report.get("targets", [])),
    ))
    for key, value in report.get("artifacts", {}).items():
        print("  %s: %s" % (key, value))

    build_result = report.get("build_result")
    if build_result and build_result.get("ok"):
        print("[patchx] Da build APK: %s" % build_result.get("apk"))
    elif build_result:
        print("[patchx] CẢNH BÁO build APK: %s" % build_result.get("error"))

    return 0 if report.get("ok") else 1


def cmd_gadget_pipeline(args):
    from .behavior.gadget_pipeline import run_gadget_pipeline
    try:
        report = run_gadget_pipeline(
            args.input,
            out_dir=args.out_dir,
            config_path=args.config,
            gadget_url=args.gadget_url,
            gadget_path=args.gadget_path,
            gadget_mode=args.gadget_mode,
            sign=not args.no_sign,
            keystore=args.keystore,
            ks_pass=args.ks_pass,
            auto_confirm=args.yes,
            keep_tree=args.keep_tree,
        )
    except Exception as exc:
        print("[gadget] LỖI pipeline: %s" % exc)
        return 1
    print("[gadget] APK:", report.get("build", {}).get("apk"))
    print("[gadget] Loader:", report.get("loader"))
    print("[gadget] Manifest extractNativeLibs:", report.get("manifest_ok"))
    print("[gadget] Resource fixes:", report.get("resource_fix", {}).get("changes", 0))
    return 0 if report.get("ok") else 1

def cmd_frida(args):
    from patchx_core.behavior.frida_generator import main as frida_main
    return frida_main(args.input, args.output)


def cmd_stats(args):
    patches = _load_patches(args.thu_muc, recursive=args.recursive)
    if not patches:
        print("[patchx] Không tìm thấy patch nào trong:", args.thu_muc)
        return 0
    total_sections = sum(len(p.sections) for p in patches)
    authors = {}
    engines = {}
    for p in patches:
        for s in p.sections:
            if s.type == "AUTHOR":
                auth = s.get("AUTHOR") or "Không rõ"
                authors[auth] = authors.get(auth, 0) + 1
            elif s.type == "MIN_ENGINE_VER":
                eng = s.get("MIN_ENGINE_VER") or "Không rõ"
                engines[eng] = engines.get(eng, 0) + 1
    print("=== THỐNG KÊ KHO PATCH ===")
    print("Tổng số patch        : %d" % len(patches))
    print("Tổng số khối (rules) : %d" % total_sections)
    print("Trung bình khối/patch: %.1f" % (total_sections / len(patches) if patches else 0))
    if authors:
        top_auth = sorted(authors.items(), key=lambda x: x[1], reverse=True)[:5]
        print("Tác giả hàng đầu     : %s" % ", ".join("%s (%d)" % (k, v) for k, v in top_auth))
    if engines:
        top_eng = sorted(engines.items(), key=lambda x: x[1], reverse=True)[:5]
        print("Phiên bản Engine     : %s" % ", ".join("%s (%d)" % (k, v) for k, v in top_eng))
    return 0


def cmd_clean(args):
    import shutil
    target_dirs = ["combos_auto", "combos_llm", "outputs/tu-sinh"]
    removed = 0
    for d in target_dirs:
        p = os.path.join(args.thu_muc, d)
        if os.path.exists(p):
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p)
                    os.makedirs(p, exist_ok=True)
                else:
                    os.remove(p)
                print("[patchx] Đã dọn sạch tệp tự sinh/tạm:", p)
                removed += 1
            except Exception as e:
                print("[patchx] Không thể xóa %s: %s" % (p, e))
    print("[patchx] Đã dọn dẹp %d thư mục/tệp tự sinh tạm thời." % removed)
    return 0


def cmd_precompile(args):
    """Tiền biên dịch toàn bộ mã nguồn Python thành mã máy bytecode (.pyc) trên 8 nhân CPU."""
    from tools.precompile import precompile_toolkit
    workers = getattr(args, "workers", None)
    opt = getattr(args, "optimize", 1)
    success, _ = precompile_toolkit(workers=workers, opt_level=opt)
    return 0 if success else 1


COMMAND_GROUPS = [
    ("1. TIẾP NHẬN & KIỂM TRA HỆ THỐNG", [
        ("intake", "Tiếp nhận tệp ứng dụng và trích xuất thông tin ban đầu không cần giải nén"),
        ("capabilities", "Kiểm tra đầy đủ năng lực và các công cụ hỗ trợ trên hệ máy"),
        ("signature-cert", "Trích xuất chứng chỉ gốc và dấu vân tay bảo mật của ứng dụng"),
        ("selfcheck", "Tự kiểm tra toàn diện hoạt động của các bộ phận và kho dữ liệu"),
        ("precompile", "Tiền biên dịch toàn bộ mã nguồn hệ thống sang bytecode tối ưu trên 8 nhân CPU"),
    ]),
    ("2. PHÂN TÍCH MÃ NGUỒN & TÌM CỔNG KIỂM TRA TỰ ĐỘNG", [
        ("analyze", "Phân tích cấu trúc mã nguồn, phát hiện lớp vỏ bọc và cổng kiểm tra bảo vệ"),
        ("model", "Dựng sơ đồ cấu trúc ứng dụng và các điểm quyết định rẽ nhánh logic"),
        ("semantic-plan", "Lập kế hoạch xử lý rẽ nhánh theo mục tiêu và điều kiện cần đạt"),
        ("plan-compile", "Tạo bản nháp các bước chỉnh sửa chuẩn xác từ kế hoạch"),
        ("plan-preflight", "Thẩm định lại bản nháp các bước trước khi ghi đè vào ứng dụng"),
        ("behavior", "Phân tích hành vi hoạt động của ứng dụng dựa trên dấu vết thực tế"),
        ("targets", "Xác định danh sách các vị trí then chốt cần chỉnh sửa trong mã nguồn"),
        ("targets-fused", "Hợp nhất các vị trí cần sửa từ nhiều nguồn phân tích để tránh nhầm lẫn"),
        ("discover", "Khám phá toàn diện: Quét tài nguyên nhạy cảm và dò tìm từ khóa ẩn"),
        ("unflatten", "Gỡ phẳng luồng mã bị làm rối kiểu switch-case và cắt tỉa khối chết"),
    ]),
    ("3. ĐIỀU PHỐI QUY TRÌNH HỢP NHẤT & TỰ ĐỘNG HÓA", [
        ("dag", "Quản lý sơ đồ điều phối thứ tự công việc và sổ bộ quy trình mẫu"),
        ("pipeline", "Chạy quy trình xử lý trọn gói đa tầng từ kiểm tra đến đóng gói"),
        ("behavior-pipeline", "Quy trình khép kín: tìm dấu vết -> lập sơ đồ -> chọn mục tiêu -> tạo lệnh can thiệp"),
        ("gadget-pipeline", "Gắn công cụ can thiệp tạm thời vào ứng dụng (dùng tốt trên máy không có quyền quản trị)"),
        ("smart-combo", "Tự động tạo bộ gói chỉnh sửa tối ưu dựa trên bài học thành công trước đó"),
        ("autopilot", "Điều phối tự hành một chạm toàn trình: vá toàn vẹn, mạng, mã máy, kiểm chứng và đóng gói"),
        ("subtitle-tts", "Đọc phụ đề thời gian thực bằng giọng nói tiếng Việt dễ nghe"),
        ("auto-refresh", "Tự động bật lại dịch phụ đề và chia sẻ màn hình sau mỗi 160 giây"),
    ]),
    ("4. SỬA ĐỔI TRỰC TIẾP SIÊU TỐC KHÔNG CẦN RÃ TỆP (<0.5 GIÂY)", [
        ("fast-patch", "Vá trực tiếp ruột tệp và đóng gói ứng dụng siêu tốc chỉ mất nửa giây"),
        ("dex-patch", "Sửa trực tiếp chuỗi chữ và mã lệnh trong tệp thực thi, không cần tháo tệp"),
        ("axml-patch", "Sửa tệp cấu hình chính để vượt cổng chứng chỉ mạng và cấp quyền"),
        ("arsc-patch", "Tìm và thay thế các dòng chữ trong bảng tài nguyên ngôn ngữ"),
        ("apk-repack-fast", "Đóng gói lại ứng dụng siêu nhanh chỉ với những phần đã sửa đổi"),
        ("macro-list", "Xem danh sách các đoạn mã mẫu an toàn và số thanh ghi cần chuẩn bị"),
    ]),
    ("5. XỬ LÝ MÃ MÁY & CAN THIỆP BỘ NHỚ TẠM THỜI", [
        ("native-sig-bypass", "Tự động quét và xử lý kiểm tra dấu vân tay chứng chỉ trong tệp mã máy"),
        ("start-scan", "Quét toàn bộ các tệp mã máy trong ứng dụng và lập bảng tổng hợp"),
        ("rodata-find", "Tìm địa chỉ chính xác của dòng chữ trong vùng nhớ tệp mã máy"),
        ("rodata-apply", "Ghi đè trực tiếp dòng chữ thay thế vào tệp mã máy trên đĩa"),
        ("rodata-patch", "Tạo lệnh can thiệp tạm thời vào dòng chữ trong bộ nhớ khi ứng dụng đang chạy"),
        ("smart-scan", "Dò tìm dòng chữ thông minh kèm điểm đánh giá độ chính xác"),
        ("neon-bench", "Đo tốc độ GB/s thật của đường quét NEON ARM64 so với Python thuần"),
        ("remote-observe", "Quan sát và theo dõi cờ trạng thái từ xa khi ứng dụng chạy"),
        ("remote-patch", "Tạo lệnh ép đặt giá trị cờ trạng thái từ xa theo ý muốn"),
        ("remote-map", "Lập bản đồ các vị trí cờ trạng thái có thể điều khiển từ xa"),
        ("frida", "Tạo kịch bản can thiệp bộ nhớ tự động từ kết quả phân tích hành vi"),
    ]),
    ("6. QUẢN LÝ GÓI SỬA ĐỔI & GHÉP BỘ TỰ ĐỘNG", [
        ("combo", "Ghép các gói chỉnh sửa nhỏ thành bộ gói lớn có độ tương thích cao"),
        ("diff-apk", "Tạo gói sửa đổi từ sự khác biệt giữa ứng dụng gốc và bản đã sửa"),
        ("suggest-apk", "Gợi ý các bước sửa đổi phù hợp dựa trên cấu trúc ứng dụng thực tế"),
        ("suggest-llm", "Gợi ý phương án sửa đổi theo yêu cầu bằng ngôn ngữ tự nhiên"),
        ("roadmap", "Lập lộ trình từng bước sửa đổi theo thứ tự ưu tiên hợp lý"),
        ("simulate", "Thử nghiệm áp dụng sửa đổi ảo trong bộ nhớ, không làm hỏng tệp gốc"),
        ("smart-patch", "Bản sửa đổi thông minh tự động thích ứng với mã nguồn bị làm rối"),
        ("pairip-bypass", "Vô hiệu hóa cổng kiểm tra bản quyền PairIP trên ứng dụng"),
    ]),
    ("7. KIỂM TRA CHẤT LƯỢNG & BẢNG ĐIỀU KHIỂN", [
        ("scan", "Quét thư mục chứa các gói sửa đổi và in thông số tổng quan"),
        ("index", "Lập danh mục chỉ mục và báo cáo tổng hợp chi tiết"),
        ("report", "Xuất báo cáo trang trực quan sinh động cho kho gói sửa đổi"),
        ("dupes", "Phát hiện và phân loại các gói sửa đổi bị trùng lặp nội dung"),
        ("manifest", "Tạo tệp kê khai dấu vân tay toàn bộ thư mục để kiểm tra sai lệch"),
        ("verify-manifest", "Đối chiếu và xác minh kho tệp theo tệp kê khai dấu vân tay"),
        ("audit", "Kiểm tra cấu trúc và chuẩn mực kỹ thuật của từng gói sửa đổi"),
        ("upgrade", "Nâng cấp gói sửa đổi cũ lên chuẩn định dạng mới an toàn hơn"),
        ("optimize", "Gom nhóm và sắp xếp lại các bước sửa đổi cho tối ưu tốc độ"),
        ("apply", "Áp dụng các gói sửa đổi trực tiếp lên cây mã nguồn thực tế"),
        ("ci", "Quy trình tự động kiểm tra chất lượng liên tục từ đầu đến cuối"),
        ("golden", "Cửa kiểm định chất lượng nghiêm ngặt trước khi cho phép xuất xưởng"),
        ("validate", "Xác thực tính nguyên vẹn và cú pháp của toàn bộ cây mã nguồn"),
        ("integrity-gate", "Một cổng kiểm tra toàn vẹn xuyên tầng G1..G5 cho smali/DEX/ELF/APK/cây"),
        ("apk-prepare", "Tháo rã toàn bộ ứng dụng bằng công cụ giải mã tiêu chuẩn"),
        ("test", "Chạy bộ kiểm tra tự động nội bộ để phát hiện sai sót"),
        ("dex-budget", "Tính toán số lượng tham chiếu mã nguồn để chống tràn giới hạn hệ thống"),
        ("preflight", "Kiểm tra điều kiện môi trường trước khi thực hiện công việc lớn"),
        ("fuzz", "Kiểm tra độ bền của hệ thống bằng dữ liệu thử thách bất thường"),
        ("failure", "Sổ ghi chép các sự cố đã gặp và cách thức khắc phục thành công"),
        ("baseline", "Lưu lại mốc đo tốc độ chuẩn để đối chiếu độ mượt mà về sau"),
        ("coverage", "Đo lường mức độ bao phủ của các điểm chỉnh sửa trên mã nguồn"),
        ("suggest", "Tự động đề xuất cách cải tiến và hoàn thiện nội dung chỉnh sửa"),
        ("acceptance", "Đối chiếu theo bộ tiêu chuẩn nghiệm thu chất lượng chính thức"),
        ("knowledge", "Quản lý kho tri thức kinh nghiệm tích lũy qua các phiên làm việc"),
        ("menu", "Bảng điều khiển tương tác chọn quy trình làm việc theo mục tiêu"),
        ("ui", "Giao diện dòng lệnh hiển thị bảng biểu màu sắc dễ nhìn"),
        ("stats", "Thống kê tổng thể về số lượng gói, dung lượng và kết quả thành công"),
        ("clean", "Dọn dẹp sạch sẽ các tệp nháp và thư mục tạm để nhẹ máy"),
    ]),
]


def cmd_packet(args):
    """Điều phối nhóm công cụ an ninh mạng gói tin cho Toolkit."""
    from .packet_security.cli import main as packet_security_main
    return packet_security_main([args.tool] + list(args.tool_args))


def command_at_position(position):
    """Trả tên lệnh theo vị trí hiển thị 1-based; ``None`` nếu không hợp lệ."""
    if not isinstance(position, int) or position < 1:
        return None
    commands = [name for _, group in COMMAND_GROUPS for name, _ in group]
    return commands[position - 1] if position <= len(commands) else None


GROUP_COLORS = {
    "1. TIẾP NHẬN & KIỂM TRA HỆ THỐNG": (C.CYN, "🔍"),
    "2. PHÂN TÍCH MÃ NGUỒN & TÌM CỔNG KIỂM TRA TỰ ĐỘNG": (C.MAG, "🧠"),
    "3. ĐIỀU PHỐI QUY TRÌNH HỢP NHẤT & TỰ ĐỘNG HÓA": (C.GRN, "⚡"),
    "4. SỬA ĐỔI TRỰC TIẾP SIÊU TỐC KHÔNG CẦN RÃ TỆP (<0.5 GIÂY)": (C.YEL, "🚀"),
    "5. XỬ LÝ MÃ MÁY & CAN THIỆP BỘ NHỚ TẠM THỜI": (C.RED, "🛡️"),
    "6. QUẢN LÝ GÓI SỬA ĐỔI & GHÉP BỘ TỰ ĐỘNG": (C.BLU, "📦"),
    "7. KIỂM TRA CHẤT LƯỢNG & BẢNG ĐIỀU KHIỂN": (C.WHT, "🛠️"),
}


class GroupedArgumentParser(argparse.ArgumentParser):
    """Trình hiển thị trợ giúp phân nhóm pipeline & lệnh cho PatchX với màu sắc trực quan."""

    def __init__(self, *args, **kwargs):
        if "prog" not in kwargs:
            kwargs["prog"] = "patchx"
        super().__init__(*args, **kwargs)

    def format_help(self):
        if self.prog != "patchx":
            return super().format_help()
        w = 78
        lines = [
            f"{C.BLD}{C.CYN}╔{'═' * (w - 2)}╗{C.RST}",
            f"{C.BLD}{C.CYN}║{C.RST} {C.BLD}{C.WHT}PATCHX — BỘ ĐIỀU PHỐI PIPELINE & PHÂN TÍCH NGỮ NGHĨA APK{C.RST}{' ' * (w - 60)}{C.BLD}{C.CYN}║{C.RST}",
            f"{C.BLD}{C.CYN}║{C.RST} {C.DIM}Cú pháp: patchx [--version] [-h] LỆNH [tham số...]{C.RST}{' ' * (w - 53)}{C.BLD}{C.CYN}║{C.RST}",
            f"{C.BLD}{C.CYN}╚{'═' * (w - 2)}╝{C.RST}",
            "",
            f"{C.BLD}DANH MỤC LỆNH & PIPELINE PHÂN THEO NHÓM CHỨC NĂNG (GỘP CHUỖI TỐI ƯU):{C.RST}",
            f"{C.DIM}{'─' * w}{C.RST}",
            f"{C.DIM}Số 01–{sum(len(cmds) for _, cmds in COMMAND_GROUPS):02d} là vị trí lệnh thật. Dùng {C.RST}{C.BLD}{C.CYN}python3 pushx <SỐ> [tham số...]{C.RST}",
            f"{C.DIM}Tên lệnh hiển thị màu trắng; phần mô tả hiển thị màu xám để dễ phân biệt.{C.RST}",
        ]
        position = 1
        for g_name, cmds in COMMAND_GROUPS:
            col, icon = GROUP_COLORS.get(g_name, (C.CYN, "📁"))
            lines.append(f"\n{C.BLD}{col}{icon} [{g_name}]{C.RST}")
            for c_name, c_help in cmds:
                lines.append(
                    f"  {col}{position:02d}.{C.RST} "
                    f"{C.BLD}{C.WHT}{c_name:<19}{C.RST} "
                    f"{C.DIM}│ {c_help}{C.RST}"
                )
                position += 1

        lines.append(f"\n{C.DIM}{'─' * w}{C.RST}")
        lines.append(f"{C.BLD}{C.GRN}💡 Mẹo:{C.RST} Gõ {C.BLD}patchx LỆNH -h{C.RST} để xem chi tiết đối số từng lệnh.")
        lines.append(f"{C.BLD}{C.YEL}⚡ Gợi ý chạy nhanh:{C.RST} {C.DIM}patchx pipeline <file.apk> --mode auto{C.RST}\n")
        return "\n".join(lines)


def cmd_integrity_decouple(args):
    """Điều phối AIDM: triệt tiêu 4 tầng kiểm soát toàn vẹn."""
    from .integrity_decoupler import decouple_integrity

    raw = getattr(args, "spearheads", "all")
    if raw in ("", "all", "ALL", "tat-ca"):
        spearheads = (1, 2, 3, 4)
    else:
        try:
            spearheads = tuple(int(x.strip()) for x in raw.split(",") if x.strip())
        except ValueError:
            print(f"{C.RED}Lỗi:{C.RST} --spearheads phải là 'all' hoặc danh sách 1-4 cách nhau dấu phẩy.")
            return 1
        spearheads = tuple(x for x in spearheads if 1 <= x <= 4)

    report = decouple_integrity(
        target=args.target,
        orig_apk=getattr(args, "orig_apk", None),
        new_apk=getattr(args, "new_apk", None),
        so_dir=getattr(args, "so_dir", None),
        out_dir=args.output_dir,
        spearheads=spearheads,
        dry_run=args.dry_run,
    )

    print(f"{C.BLD}{C.CYN}Kết quả triệt tiêu toàn vẹn (AIDM){C.RST}")
    print(f"  Mục tiêu: {report['target']}")
    print(f"  Chế độ: {'phân tích (dry-run)' if report['dry_run'] else 'ghi thật (có sao lưu)'}")
    print(f"  Tệp smali quét: {report['files_scanned']} · tệp đổi: {report['files_patched']}")
    print(f"  Phương thức đổi: {report['methods_patched']}")
    print(f"  Installer đã thay: {report['installer_decoupled']} · ép chữ ký: {report['signing_forced']}")
    print(f"  Thoát đã vô hiệu: {report['exits_neutralized']} · nhánh đã đảo: {report['branches_inverted']}")
    if report.get("native"):
        print(f"  Native .so đã vá: {len(report['native'].get('native_patches', []))}")
    if report.get("play_integrity"):
        print(f"  Hook Play Integrity: {report['play_integrity']['hook']}")
    if report.get("warnings"):
        print(f"{C.YEL}  Cảnh báo:{C.RST}")
        for w in report["warnings"]:
            print(f"    - {w}")
    print(f"  Báo cáo: {report.get('report_path')}")
    return 0


def cmd_autopilot(args):
    """Điều phối tự hành toàn trình: toàn vẹn -> cổng -> mạng -> native."""
    import json
    import os
    from pathlib import Path
    from .orchestrator import AutopilotOrchestrator

    target = args.target
    out_dir = args.output_dir or os.path.join(BASE_DIR, "outputs", "autopilot")
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    raw = getattr(args, "spearheads", "all")
    if raw in ("", "all", "ALL", "tat-ca"):
        spearheads = (1, 2, 3, 4)
    else:
        try:
            spearheads = tuple(int(x.strip()) for x in raw.split(",") if x.strip())
        except ValueError:
            print(f"{C.RED}Lỗi:{C.RST} --spearheads phải là 'all' hoặc danh sách 1-4 cách nhau dấu phẩy.")
            return 1
        spearheads = tuple(x for x in spearheads if 1 <= x <= 4)

    orch = AutopilotOrchestrator(
        target=target,
        out_dir=out_dir,
        spearheads=spearheads,
        dry_run=getattr(args, "dry_run", False),
        so_dir=getattr(args, "so_dir", None),
        orig_apk=getattr(args, "orig_apk", None),
        new_apk=getattr(args, "new_apk", None),
        network=getattr(args, "network", False),
        native_patch=getattr(args, "native_patch", False),
        unflatten=getattr(args, "unflatten", False),
        unflatten_limit=getattr(args, "unflatten_limit", 0),
        decompile=getattr(args, "decompile", False),
        package=getattr(args, "package", True),
    )
    report = orch.run_full_pipeline()
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    print(f"{C.BLD}{C.CYN}Autopilot toàn trình{C.RST} — chế độ: {report['mode']}")
    print(f"  Mục tiêu: {target}")
    for s in report["steps"]:
        if s.get("skipped"):
            print(f"  - {s['name']}: BỎ QUA")
        elif s.get("ok"):
            print(f"  - {s['name']}: OK ({s.get('elapsed_ms', 0)}ms)")
        else:
            print(f"{C.RED}  - {s['name']}: LỖI{C.RST} {s.get('error', '')}")
    print(f"  Tổng: {report['elapsed_seconds']}s · báo cáo: {report_path}")
    return 0


def cmd_unflatten(args):
    """Gỡ phẳng luồng mã switch-case và cắt tỉa khối chết (có sao lưu)."""
    import os
    from .cfg_unflatten import unflatten_file, unflatten_tree
    target = args.target
    if os.path.isdir(target):
        rep = unflatten_tree(
            target, apply=args.apply, limit=args.limit,
            min_cases=args.min_cases, backup_root=args.backup_root)
        print(f"{C.BLD}{C.CYN}Gỡ phẳng luồng mã — cây:{C.RST} {target}")
        print(f"  Tệp quét: {rep['files_scanned']} · tệp có mã làm phẳng: "
              f"{rep['files_unflattened']} · tệp đã ghi: {rep['files_applied']}")
        print(f"  Phương thức: {rep['methods_total']} · đã gỡ phẳng: "
              f"{rep['methods_unflattened']}")
    else:
        rep = unflatten_file(
            target, apply=args.apply, backup=True,
            min_cases=args.min_cases, backup_root=args.backup_root)
        print(f"{C.BLD}{C.CYN}Gỡ phẳng luồng mã — tệp:{C.RST} {target}")
        print(f"  Phương thức: {rep['methods_total']} · đã gỡ phẳng: "
              f"{rep['methods_unflattened']} · đã ghi: "
              f"{'có' if rep['applied'] else 'chưa (chỉ phân tích)'}")
        if rep.get("backup"):
            print(f"  Sao lưu: {rep['backup']}")
        for d in rep.get("details", [])[:20]:
            print(f"  - {d['method'][:80]} | case={d['case_count']} "
                  f"hoàn_chỉnh={d['complete']} khối_chết={len(d['dead_blocks_removed'])}")
    if args.o:
        from pathlib import Path
        p = Path(args.o)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[patchx] Đã ghi JSON:", p)
    return 0


def cmd_integrity_gate(args):
    """Một cổng kiểm tra toàn vẹn xuyên tầng: G1..G5."""
    import os
    from .integrity_gate import gate_target, gate_tree, gate_apk
    target = args.target
    if os.path.isdir(target):
        rep = gate_tree(target)
    elif target.lower().endswith(".apk"):
        rep = gate_apk(target)
    else:
        exp = getattr(args, "g3_expected", True)
        if isinstance(exp, str):
            exp = exp.strip().lower() not in ("0", "false", "none", "no")
        rep = gate_target(
            target, layer=args.layer,
            g3_method=getattr(args, "g3_method", None),
            g3_expected=exp,
            g4_expected=getattr(args, "g4_expected", None))
    print(f"{C.BLD}{C.CYN}Cổng toàn vẹn (G1..G5){C.RST} — {target}")
    print(f"  Kết luận: {C.GRN if rep['verdict'] == 'PASS' else C.RED}"
          f"{rep['verdict']}{C.RST}")
    if "layers" in rep:
        for name, chk in rep["layers"].items():
            mark = C.GRN + "ĐẠT" if chk["ok"] else C.RED + "LỖI"
            print(f"  - {name}: {mark}{C.RST}"
                  + ("" if chk["ok"] else " · %s" % chk.get("reason", "")))
    else:
        print(f"  Tệp kiểm: {rep.get('files_checked', 0)} · đạt: {rep.get('passed', 0)}")
        for f in rep.get("failed", [])[:10]:
            print(f"  - {C.RED}LỖI{C.RST} {f.get('layer')} · {f.get('reason')}")
    if args.o:
        from pathlib import Path
        p = Path(args.o)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[patchx] Đã ghi JSON:", p)
    return 0 if rep["verdict"] == "PASS" else 1


def cmd_ast_dsl(args):
    """Vá ngữ nghĩa bằng ngôn ngữ quy tắc trên cây AST Smali (T1)."""
    from .ast_dsl import apply_patch_dsl, load_rules
    rules = load_rules(args.rules)
    rep = apply_patch_dsl(
        args.target, rules, dry_run=not args.apply,
        output_dir=args.output_dir if not args.apply else None)
    print(f"{C.BLD}{C.CYN}AST DSL — vá ngữ nghĩa theo quy tắc{C.RST} — {args.target}")
    print(f"  Quy tắc: {rep['tong_quy_tac']} · tệp quét: {rep['tep_quet']} · "
          f"tệp đổi: {rep['tep_doi']} · phương thức đổi: {rep['phuong_thuc_doi']}")
    for d in rep.get("chi_tiet", [])[:20]:
        canh_bao = (" · " + d["canh_bao"]) if d.get("canh_bao") else ""
        print(f"  - {d['tep']} :: {d['phuong_thuc']} :: {d['quy_tac']}{canh_bao}")
    if args.o:
        from pathlib import Path
        p = Path(args.o)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[patchx] Đã ghi JSON:", p)
    return 0


def cmd_dex_method(args):
    """Trình sửa DEX ở mức phương thức (T2): xem bản đồ hoặc vá opcode cùng độ dài."""
    from pathlib import Path
    from .dex_inplace import (apply_dex_method_patch,
                              map_methods_report)
    dex = args.dex
    if args.map:
        rep = map_methods_report(Path(dex).read_bytes(), filter_regex=args.method)
        print(f"{C.BLD}{C.CYN}DEX method map{C.RST} — {dex}")
        print(f"  magic={rep['header']['magic']} · method_ids="
              f"{rep['header']['method_ids']} · class_defs={rep['header']['class_defs']}")
        for m in rep["methods"][:40]:
            code = (f"off={m.get('insns_off')} · insns={m.get('insns_size')}"
                    if m.get("has_code") else "không mã")
            print(f"  - {m['class_name']}->{m['name']} : {code}")
        if args.o:
            p = Path(args.o)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                         encoding="utf-8")
            print("[patchx] Đã ghi JSON:", p)
        return 0
    rep = apply_dex_method_patch(
        dex, args.method or ".", args.swap.split("=", 1)[0],
        args.swap.split("=", 1)[1], backup_dir=args.backup,
        dry_run=not args.apply)
    if rep.get("changed"):
        print(f"{C.GRN}Đã tìm {rep['hits']} vị trí khớp{C.RST} · "
              f"dry_run={rep['dry_run']}")
        for m in rep.get("matches", []):
            print(f"  - {m['class']}->{m['method']} @ offset {m['offset']}")
    else:
        print(f"{C.YEL}{rep.get('reason', 'không thay đổi')}{C.RST}")
    if args.o:
        p = Path(args.o)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(rep, ensure_ascii=False, indent=2),
                     encoding="utf-8")
    return 0 if rep.get("changed") else 1


def main(argv=None):
    parser = GroupedArgumentParser(
        prog="patchx",
        description="Bộ script nâng cấp cho bộ sưu tập patch APK Editor.")
    parser.add_argument("--version", action="version", version="patchx %s" % __version__)
    sub = parser.add_subparsers(dest="lenh", metavar="LENH")

    p = sub.add_parser("axml-patch", help="Patch chuỗi nhị phân AXML/ARSC có backup")
    p.add_argument("binary", help="AndroidManifest.xml hoặc resources.arsc")
    p.add_argument("old", nargs="?", default=None, help="Chuỗi cũ")
    p.add_argument("new", nargs="?", default=None, help="Chuỗi mới không dài hơn chuỗi cũ")
    p.add_argument("--inspect-security", action="store_true", help="Báo cáo thuộc tính bảo mật Manifest")
    p.add_argument("--bypass-nsc", action="store_true", help="Vô hiệu hóa Network Security Config (bỏ SSL pinning)")
    p.add_argument("--replace-perm", metavar="OLD=NEW", help="Đổi permission nhị phân in-place")
    p.add_argument("--backup", default=None, help="Tệp backup")
    p.add_argument("--dry-run", action="store_true", help="Chỉ inspect chunk, không ghi")
    p.set_defaults(func=cmd_axml_patch)

    p = sub.add_parser("signature-cert", help="Trích DER cert gốc và SHA-256, không ký APK")
    p.add_argument("apk", help="APK gốc")
    p.add_argument("-o", "--output", default=None, help="JSON context đầu ra")
    p.set_defaults(func=cmd_signature_cert)

    p = sub.add_parser("intake", help="Tiếp nhận APK/APKS/XAPK/AAB và tạo evidence report chỉ đọc")
    p.add_argument("artifact", help="Tệp APK, APKS, XAPK hoặc AAB")
    p.add_argument("-o", "--output-dir", default=None, help="Thư mục output (mặc định: outputs/intake)")
    p.add_argument("--no-tool-probe", action="store_true", help="Không probe version công cụ ngoài")
    p.set_defaults(func=cmd_intake)

    p = sub.add_parser("capabilities", help="Ghi tool_capabilities.json cho môi trường hiện tại")
    p.add_argument("-o", "--output-dir", default=None, help="Thư mục output (mặc định: outputs/intake)")
    p.set_defaults(func=cmd_capabilities)

    p = sub.add_parser("pipeline", help="Khởi chạy Pipeline Thống Nhất (auto|intake|semantic|fast|behavior|native|combo|gadget)")
    p.add_argument("artifact", help="Tệp APK, APKS, XAPK hoặc AAB")
    p.add_argument("--mode", default="auto", choices=["auto", "intake", "semantic", "fast", "behavior", "native", "combo", "gadget"], help="Chế độ pipeline")
    p.add_argument("-o", "--out", default=None, help="Đường dẫn APK đầu ra (nếu có)")
    p.add_argument("--output-dir", default=None, help="Thư mục xuất báo cáo (mặc định: outputs/pipeline)")
    p.add_argument("--dex-str", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trong ruột tệp mã máy DEX trực tiếp")
    p.add_argument("--dex-hex", action="append", default=[], metavar="HEX1=HEX2", help="Thay mã lệnh nhị phân DEX trực tiếp")
    p.add_argument("--axml", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trong tệp khai báo XML nhị phân trực tiếp")
    p.add_argument("--arsc", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trong bảng tài nguyên nhị phân trực tiếp")
    p.add_argument("--dry-run", action="store_true", help="Chạy thử không ghi tệp ứng dụng")
    p.add_argument("--auto-patch", action="store_true", help="Tự động sửa mã trung gian cho chặng phân tích hành vi")
    p.add_argument("--build-apk", action="store_true", help="Đóng gói ứng dụng sau khi sửa")
    p.set_defaults(func=cmd_pipeline)

    p = sub.add_parser("dag", help="Quản lý sơ đồ điều phối thứ tự công việc và sổ bộ quy trình mẫu")
    p.add_argument("--list", action="store_true", help="Liệt kê danh sách quy trình mẫu và các bước trong sổ bộ")
    p.add_argument("--inspect", metavar="NAME", help="Xem chi tiết cấu trúc sơ đồ và các tầng thực hiện độc lập của quy trình")
    p.add_argument("--mermaid", metavar="NAME", help="Xuất mã sơ đồ hình ảnh Mermaid Markdown của quy trình")
    p.add_argument("--run", metavar="NAME", help="Khởi chạy quy trình được chỉ định")
    p.add_argument("artifact", nargs="?", default=None, help="Tệp ứng dụng APK/AAB khi chạy --run")
    p.add_argument("-o", "--output-dir", default=None, help="Thư mục xuất kết quả")
    p.add_argument("--dry-run", action="store_true", help="Chạy thử mô phỏng không biến đổi dữ liệu")
    p.add_argument("--export-all", nargs="?", const="outputs/pipeline/dag", metavar="DIR", help="Xuất toàn bộ tài liệu sơ đồ và quy trình ra thư mục")
    p.add_argument("--export", nargs="?", const="outputs/pipeline/dag", metavar="DIR", help="Xuất toàn bộ tài liệu sơ đồ và quy trình")
    p.set_defaults(func=cmd_dag)

    p = sub.add_parser("macro-list", help="Liệt kê danh sách macro mã trung gian và yêu cầu thanh ghi")
    p.add_argument("--registers", type=int, default=2, help="Số thanh ghi dự kiến")
    p.set_defaults(func=cmd_macro_list)

    p = sub.add_parser("dex-patch", help="Sửa trực tiếp chuỗi và mã lệnh DEX, không qua công cụ rã tệp cồng kềnh")
    p.add_argument("dex", help="Tệp classes*.dex")
    p.add_argument("--replace", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trực tiếp; có thể lặp lại")
    p.add_argument("--replace-hex", action="append", default=[], metavar="TARGET=REPL", help="Thay mã lệnh nhị phân trực tiếp (ví dụ: 12000f00=12100f00)")
    p.add_argument("--backup", default=None, help="Thư mục sao lưu an toàn")
    p.add_argument("--dry-run", action="store_true", help="Chỉ kiểm tra vị trí tìm thấy, không ghi đè tệp")
    p.set_defaults(func=cmd_dex_patch)

    p = sub.add_parser("apk-repack-fast", help="Đóng gói APK siêu tốc chỉ với các thành phần có thay đổi")
    p.add_argument("apk", help="Tệp APK gốc")
    p.add_argument("-o", "--output", required=True, help="Tệp APK xuất xưởng mới")
    p.add_argument("--update", action="append", default=[], metavar="ENTRY=FILE", help="Entry APK và file thay thế")
    p.add_argument("--dry-run", action="store_true", help="Chỉ kiểm tra tham số, không tạo APK")
    p.set_defaults(func=cmd_apk_repack_fast)

    p = sub.add_parser("fast-patch", help="Quy trình 1-Click vá DEX/AXML/ARSC in-place và repack APK siêu tốc")
    p.add_argument("apk", help="APK gốc")
    p.add_argument("-o", "--output", required=True, help="APK đầu ra đã patch")
    p.add_argument("--dex-str", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi UTF-8 trong classes*.dex")
    p.add_argument("--dex-hex", action="append", default=[], metavar="TARGET=REPL", help="Thay opcode/bytecode hex trong classes*.dex")
    p.add_argument("--axml", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trong AndroidManifest.xml (auto UTF-8/UTF-16)")
    p.add_argument("--arsc", action="append", default=[], metavar="OLD=NEW", help="Thay chuỗi trong resources.arsc (auto UTF-8/UTF-16)")
    p.add_argument("--no-strip", action="store_true", help="Không tự động gỡ file chữ ký cũ trong META-INF")
    p.add_argument("--dag", action="store_true", help="Chạy quy trình vá siêu tốc qua động cơ điều phối DAG")
    p.set_defaults(func=cmd_fast_patch)

    p = sub.add_parser("arsc-patch", help="Phân tích và thay thế chuỗi trong bảng tài nguyên resources.arsc")
    p.add_argument("arsc", help="File resources.arsc")
    p.add_argument("old", nargs="?", default=None, help="Chuỗi gốc cần tìm")
    p.add_argument("new", nargs="?", default=None, help="Chuỗi mới thay thế")
    p.add_argument("--replace", action="append", default=[], metavar="OLD=NEW", help="Mẫu thay thế dạng OLD=NEW")
    p.add_argument("--inspect", action="store_true", help="Kiểm tra thông tin chi tiết bảng tài nguyên và package")
    p.add_argument("--backup", default=None, help="Đường dẫn file sao lưu (.bak)")
    p.add_argument("--dry-run", action="store_true", help="Chỉ kiểm tra hit, không ghi tệp")
    p.set_defaults(func=cmd_arsc_patch)

    p = sub.add_parser("native-sig-bypass", help="Tự động quét và bypass SHA-256 cert hash trong thư viện native .so")
    p.add_argument("apk", help="APK đích cần bypass chữ ký native")
    p.add_argument("--orig-apk", default=None, help="APK gốc chứa chứng chỉ chuẩn (nếu khác APK đích)")
    p.add_argument("-o", "--output", default=None, help="Đường dẫn APK đầu ra sau khi vá .so")
    p.add_argument("--frida-out", default=None, help="Đường dẫn file kịch bản Frida hook đa tầng")
    p.add_argument("--dry-run", action="store_true", help="Chỉ quét tìm hit hash trong .so, không vá APK")
    p.set_defaults(func=cmd_native_sig_bypass)

    p = sub.add_parser("smart-combo", help="Tự động sinh combo tối ưu từ Active Learning (AST Smali + combos_success.json)")
    p.add_argument("cay", help="Cây APK đã giải mã hoặc thư mục APK")
    p.add_argument("--intent", default=None, help="Ý định mod (bypass-license, integrity, purchase, root-hide, ads...)")
    p.add_argument("--collection", default="upgraded", help="Kho patch nguồn (mặc định: upgraded)")
    p.add_argument("--max-patches", type=int, default=4, help="Số patch tối đa ghép vào combo (mặc định: 4)")
    p.add_argument("--name", default=None, help="Tên combo tùy chỉnh")
    p.add_argument("-o", "--output-dir", default=None, help="Thư mục xuất combo (mặc định: combos/)")
    p.add_argument("--apply", action="store_true", help="Tự động áp combo vào cây sau khi sinh")
    p.add_argument("--dry-run", action="store_true", help="Chỉ phân tích, không ghi tệp")
    p.set_defaults(func=cmd_smart_combo)

    p = sub.add_parser("behavior", help="Phân tích hành vi APK dựa trên bằng chứng")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.set_defaults(func=cmd_behavior)

    p = sub.add_parser("targets", help="Xác định mục tiêu cần xem xét sửa đổi")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("targets-fused", aliases=["fused-targets"], help="Xác định và phân hạng mục tiêu hợp nhất đa nguồn (Behavior + Security Gates)")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.add_argument("--min-score", type=float, default=0.50, help="Điểm tối thiểu cho Behavior Targets (0.0-1.0)")
    p.add_argument("--min-confidence", type=float, default=70.0, help="Độ tin cậy tối thiểu cho Security Gates (%%)")
    p.add_argument("-o", "--out-dir", help="Thư mục xuất báo cáo JSON và MD")
    p.add_argument("--frida-hook", nargs="?", const="default", help="Sinh kịch bản Frida hook đa tầng")
    p.add_argument("--apply", action="store_true", help="Tự động can thiệp vào mã Smali (Target-Driven thay thế Editor)")
    p.set_defaults(func=cmd_fused_targets)

    p = sub.add_parser("discover", aliases=["universal-discovery", "deep-scan"], help="Phân tích toàn diện: Quét tệp nhạy cảm (assets/cert/db) & Khai phá từ điển động không giới hạn")
    p.add_argument("target", help="Tệp APK hoặc cây giải mã Smali")
    p.add_argument("-o", "--output", default=None, help="Thư mục xuất báo cáo (mặc định: outputs/discovery)")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("subtitle-tts", aliases=["subtitle-reader", "realtime-subtitles"], help="Động cơ & công cụ đọc phụ đề thời gian thực bằng giọng nói TTS")
    p.add_argument("target", nargs="?", default=None, help="Đường dẫn cây APK hoặc thư mục Smali cần kiểm tra/vá")
    p.set_defaults(func=cmd_subtitle_tts)

    p = sub.add_parser("auto-refresh", aliases=["auto-session", "auto-reset-translation"], help="Tự động reset và bật lại dịch phụ đề + chia sẻ toàn màn hình sau 2m40s (160s)")
    p.add_argument("--interval", "-i", type=int, default=160, help="Khoảng thời gian chu kỳ tính bằng giây (mặc định: 160 = 2 phút 40 giây)")
    p.add_argument("--package", "-p", type=str, default="com.sota.aitranslatex", help="Gói ứng dụng mục tiêu (mặc định: com.sota.aitranslatex)")
    p.add_argument("--device", "-d", type=str, default=None, help="Địa chỉ thiết bị ADB (ví dụ: 100.64.170.99:5555)")
    p.add_argument("--root", action="store_true", help="Sử dụng quyền root su trên thiết bị")
    p.add_argument("--once", action="store_true", help="Chỉ chạy 1 chu kỳ làm mới duy nhất rồi dừng")
    p.add_argument("--no-tts", action="store_true", help="Không phát âm thông báo qua TTS")
    p.set_defaults(func=cmd_auto_refresh)

    p = sub.add_parser("gadget-pipeline", help="Nhung Frida Gadget vao APK/cay APK (khong root)")
    p.add_argument("input", help="File .apk hoac thu mục cây APK da giai ma")
    p.add_argument("-o", "--out-dir",
                default=os.path.join(BASE_DIR, "outputs", "behavior", "gadget"),
                help="Thu mục xuat APK va artifact")
    p.add_argument("--config", help="Path/URL file cau hinh Frida hoac gadget")
    p.add_argument("--gadget-url", help="URL gadget .so.xz neu muon dung ban khac")
    p.add_argument("--gadget-path", help="Path gadget .so local neu da tai san")
    p.add_argument("--gadget-mode", choices=["script", "listen"], default="script", help="script=tu nap hook; listen=cho remote-observe attach")
    p.add_argument("--yes", action="store_true", help="Tu dong xac nhan config dau tien tim thay")
    p.add_argument("--keep-tree", action="store_true", help="Giu cây APK da giai ma")
    p.add_argument("--no-sign", action="store_true", help="Khong ky APK")
    p.add_argument("--keystore", help="Keystore dung de ky APK")
    p.add_argument("--ks-pass", default="android", help="Mat khau keystore")
    p.set_defaults(func=cmd_gadget_pipeline)

    p = sub.add_parser("behavior-pipeline", help="Chay luong detector -> cfg -> target -> hook -> frida -> loader -> APK")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.add_argument("-o", "--out-dir",
                default=os.path.join(BASE_DIR, "outputs", "behavior"),
                help="Thu mức xuat artifact")
    p.add_argument("--flow", default="all", choices=available_flows(), help="Chon luong hanh vi de phan tich")
    p.add_argument("--auto-patch", action="store_true", help="Sua Smali truc tiep trước khi build")
    p.add_argument("--build-apk", action="store_true", help="Build APK sau khi sua (can apktool)")
    p.add_argument("--interactive", action="store_true", help="Hien goi y va cho nguoi dung chon target")
    p.add_argument("--min-score", type=float, default=0.65, help="Nguong diem bypass toi thieu cho target")
    p.set_defaults(func=cmd_behavior_pipeline)

    p = sub.add_parser("smart-patch",
                       help="Bản patch thông minh smali: tái dùng detector "
                            "behavior (kể cả nhánh obfuscated-*), chống R8/D8")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.add_argument("-o", "--out-dir", default=None,
                   help="Thư mục đầu ra (mặc định outputs/behavior/smart_patch)")
    p.add_argument("--min-score", type=float, default=0.65,
                   help="Ngưỡng điểm bypass cho target (mặc định 0.65)")
    p.add_argument("--apply", action="store_true",
                   help="Ghi đè smali (backup tự động); mặc định chỉ lập kế hoạch")
    p.set_defaults(func=cmd_smart_patch)

    p = sub.add_parser("pairip-bypass",
                       help="Vo hieu hoa PairIP (license check) tren cay APK")
    p.add_argument("thu_muc", help="Cây APK đã giải mã")
    p.add_argument("-o", "--out-dir", default=None,
                   help="Thư mục đầu ra "
                        "(mặc định outputs/behavior/pairip_bypass)")
    p.add_argument("--apply", action="store_true",
                   help="Ghi đè smali (backup tự động); "
                        "mặc định chỉ lập kế hoạch")
    p.add_argument("--dry-run", action="store_true",
                   help="Chỉ lập kế hoạch, không ghi (ưu tiên hơn --apply)")
    p.add_argument("--no-backup", action="store_true",
                   help="Không sao lưu trước khi ghi")
    p.set_defaults(func=cmd_pairip_bypass)

    p = sub.add_parser("scan", help="Quét thư mục patch và in tóm tắt")
    p.add_argument("thu_muc", help="Thư mục chứa các tệp .zip")
    p.add_argument("-o", help="Ghi kết quả JSON")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("index", help="Tạo index.json + report.md")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.add_argument("--ten", default="patchx", help="Tiền tố tên tệp")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.set_defaults(func=cmd_index)

    p = sub.add_parser("dupes", help="Phát hiện patch trùng nội dung")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.set_defaults(func=cmd_dupes)

    p = sub.add_parser("manifest", help="Tạo MANIFEST.json cho toàn bộ cây")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Đường dẫn tệp đầu ra")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("verify-manifest", help="Xác minh kho theo MANIFEST.json")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("--manifest", default=None, help="Đường dẫn MANIFEST.json")
    p.set_defaults(func=cmd_verify_manifest)

    p = sub.add_parser("report", help="Tạo báo cáo HTML")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Đường dẫn tệp HTML")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.add_argument("--apk", default=None, help="Cây APK đã giải mã")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("ci", help="Dây chuyền CI tự động")
    p.add_argument("thu_muc", help="Thư mục kho patch gốc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.add_argument("--quick", action="store_true", help="Mô phỏng nhanh")
    p.add_argument("--golden", action="store_true", help="Chay cong Golden Build")
    p.set_defaults(func=cmd_ci)

    p = sub.add_parser("golden", help="Cổng Golden Build")
    p.add_argument("-o", default=None, help="Thư mục ghi golden_gate.json")
    p.add_argument("--fw", action="store_true", help="Bật build framework-res")
    p.set_defaults(func=cmd_golden)

    p = sub.add_parser("validate", help="Xác thực cây APK (smali/XML/DEX)")
    p.add_argument("cay", help="Cây APK đã giải mã")
    p.add_argument("--level", default="NORMAL", choices=["FAST", "NORMAL", "FULL", "RELEASE"])
    p.add_argument("--changed-only", action="store_true", help="Chỉ kiểm tra tệp đổi")
    p.add_argument("--files", nargs="*", default=None, help="Chỉ kiểm tra tệp này")
    p.add_argument("--limit", type=int, default=50, help="Số lỗi in tối đa")
    p.add_argument("--max-files", type=int, default=None, help="Giới hạn tệp quét DEX")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("apk-prepare", help="Giải mã APK bằng apktool")
    p.add_argument("apk", help="Tệp .apk")
    p.add_argument("-o", default=None, help="Thư mục giải mã")
    p.add_argument("--timeout", type=int, default=600, help="Giới hạn giây")
    p.set_defaults(func=cmd_apk_prepare)

    p = sub.add_parser("audit", help="Kiểm tra kiến trúc từng patch")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("upgrade", help="Nâng cấp patch an toàn")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.add_argument("--dry-run", action="store_true", help="Xem trước, không ghi")
    p.set_defaults(func=cmd_upgrade)

    p = sub.add_parser("optimize", help="Gộp patch tối ưu")
    p.add_argument("thu_muc")
    p.add_argument("-o", default=None, help="Thư mục đầu ra")
    p.set_defaults(func=cmd_optimize)

    p = sub.add_parser("apply", help="Áp patch lên cây APK")
    p.add_argument("patch", nargs="+", help="Các patch (.zip/.txt)")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("--dry-run", action="store_true", help="Xem trước")
    p.add_argument("--no-backup", action="store_true", help="Không sao lưu")
    p.add_argument("--force", action="store_true", help="Ép áp lại")
    p.add_argument("--dex-runner", default=None, help="Lệnh chạy EXECUTE_DEX")
    p.add_argument("--dex-allow", action="append", default=[], help="Cho phép EXECUTE_DEX")
    p.add_argument("--strict", action="store_true", help="Dừng nếu lỗi nhẹ")
    p.add_argument("--quiet", action="store_true", help="In ít thông tin")
    p.add_argument("--reset-state", action="store_true", help="Xóa trạng thái áp trước đó")
    p.add_argument("--dag", action="store_true", help="Ủy quyền điều phối tự động qua DAG")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("test", help="Chạy bộ kiểm tra nội bộ")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("dex-budget", help="Ước lượng giới hạn DEX refs")
    p.add_argument("cay", help="Thư mục APK đã giải mã")
    p.add_argument("--patch", help="Tệp patch kiểm tra")
    p.add_argument("--max", type=int, help="Giới hạn refs")
    p.add_argument("--max-files", type=int, help="Giới hạn tệp smali")
    p.add_argument("--workers", type=int, default=1, help="Số luồng xử lý")
    p.set_defaults(func=cmd_dex_budget)

    p = sub.add_parser("preflight", help="Kiểm tra trước khi áp patch")
    p.add_argument("patch", help="Tệp patch (.zip/.txt)")
    p.add_argument("cay", help="Thư mục APK đã giải mã")
    p.add_argument("--max-files", type=int, help="Giới hạn tệp")
    p.set_defaults(func=cmd_preflight)

    p = sub.add_parser("fuzz", help="Tấn công fuzz/chaos parser & engine")
    p.add_argument("--iter", type=int, default=100, help="Số lượt fuzz")
    p.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên")
    p.add_argument("--workdir", help="Thư mục làm việc")
    p.set_defaults(func=cmd_fuzz)

    p = sub.add_parser("failure", help="Cơ sở dữ liệu Failure Intelligence")
    p.add_argument("hanh_dong", choices=["list", "report", "lookup", "add", "gen-regression"])
    p.add_argument("--db", default="failure_db.json", help="Đường dẫn DB")
    p.add_argument("--message", help="Thông điệp lỗi")
    p.add_argument("--stage", help="Giai đoạn lỗi")
    p.add_argument("--error-id", help="Mã lỗi")
    p.add_argument("--pattern", help="Mẫu nhận diện")
    p.add_argument("--cause", help="Nguyên nhân")
    p.add_argument("--fix", help="Phương án sửa")
    p.add_argument("--regression", help="Mã regression test")
    p.add_argument("--test-name", help="Tên test")
    p.add_argument("-o", "--out", help="Tệp xuất ra")
    p.set_defaults(func=cmd_failure)

    p = sub.add_parser("baseline", help="Chụp và so sánh baseline performance/metrics")
    p.add_argument("hanh_dong", choices=["capture", "show", "compare"])
    p.add_argument("--dir", help="Thư mục lưu baseline")
    p.add_argument("--full", action="store_true", help="Chụp toàn bộ môi trường")
    p.add_argument("--set", action="append", help="Thiết lập key=val")
    p.add_argument("--metrics-mới", help="Tệp metrics mới")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("coverage", help="Đo độ bao phủ của patch")
    p.add_argument("patch", help="Tệp patch")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("--mode", default="FAST", choices=["FAST", "NORMAL", "FULL", "RELEASE"])
    p.add_argument("-o", default=None, help="Ghi JSON")
    p.add_argument("--method", action="store_true", help="Chi tiết theo method")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("suggest", help="Tự đề xuất cải tiến cho patch")
    p.add_argument("patch", help="Tệp patch")
    p.add_argument("cay_apk", nargs="?", default=None, help="Thư mục APK đã giải mã")
    p.add_argument("-o", default=None, help="Ghi JSON")
    p.set_defaults(func=cmd_suggest)

    p = sub.add_parser("analyze", help="Phân tích ngữ nghĩa cây APK")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("-o", default=None, help="Ghi JSON")
    p.add_argument("--top", type=int, default=15, help="Số class top call-graph")
    p.add_argument("--dag", action="store_true", help="Chạy phân tích sâu tự động qua DAG")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("model", help="Tạo mô hình trung gian app_model.json")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("-o", default=None, help="Tệp JSON đầu ra")
    p.add_argument("--with-bodies", action="store_true", help="Kèm thân method")
    p.add_argument("--v2", action="store_true", help="Sinh app-model/v2")
    p.add_argument("--bench", action="store_true", help="Đo thời gian chạy")
    p.set_defaults(func=cmd_model)

    p = sub.add_parser("semantic-plan", help="Đánh giá kế hoạch ngữ nghĩa")
    p.add_argument("ke_hoach", help="Tệp plan JSON")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("--model", help="Tệp app_model.json")
    p.add_argument("-v", "--verbose", action="store_true", help="In chi tiết")
    p.add_argument("-o", help="Ghi JSON kết quả")
    p.set_defaults(func=cmd_semantic_plan)

    p = sub.add_parser("acceptance", help="Chạy tiêu chí nghiệm thu V2")
    p.add_argument("fixture", help="Thư mục fixture")
    p.add_argument("-o", help="Ghi JSON kết quả")
    p.set_defaults(func=cmd_acceptance)

    p = sub.add_parser("knowledge", help="Quản lý kho tri thức nghiệm thu")
    p.add_argument("hanh_dong", choices=["record", "query", "suggest-plan"])
    p.add_argument("--db", default="knowledge_db.json", help="Tệp DB")
    p.add_argument("--record", help="Tệp record JSON")
    p.add_argument("cay_apk", nargs="?", help="Thư mục APK")
    p.add_argument("--goal", help="Mục tiêu tìm kiếm")
    p.add_argument("--top", type=int, default=5, help="Số lượng kết quả")
    p.add_argument("--v2", action="store_true", help="Dùng model V2")
    p.add_argument("-o", help="Ghi JSON kết quả")
    p.set_defaults(func=cmd_knowledge)

    p = sub.add_parser("plan-compile", help="Tạo transaction nháp từ plan V2")
    p.add_argument("ke_hoach", help="Tệp plan V2 JSON")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("-o", required=True, help="Tệp draft JSON đầu ra")
    p.set_defaults(func=cmd_plan_compile)

    p = sub.add_parser("plan-preflight", help="Đánh giá lại draft transaction")
    p.add_argument("draft", help="Tệp draft JSON")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("-o", help="Cập nhật tệp draft")
    p.set_defaults(func=cmd_plan_preflight)

    p = sub.add_parser("remote-map", help="Tạo bản đồ flag điều khiển từ xa")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("--flow", action="store_true", help="Luồng quyết định")
    p.add_argument("--dataflow", action="store_true", help="Luồng dữ liệu")
    p.add_argument("--no-atomic", action="store_true", help="Bỏ qua AtomicBoolean")
    p.add_argument("--top", type=int, default=15, help="Top flag")
    p.add_argument("-o", help="Ghi JSON kết quả")
    p.set_defaults(func=cmd_remote_map)

    p = sub.add_parser("remote-patch", help="Sinh patch ép flag")
    p.add_argument("remote_map", help="Tệp remote map JSON")
    p.add_argument("--set", action="append", help="Thiết lập flag (Lcls;->fld:Z=true)")
    p.add_argument("--force", help="Tệp overrides JSON")
    p.add_argument("-o", default="remote_force.patch", help="Tệp patch xuất ra")
    p.set_defaults(func=cmd_remote_patch)

    p = sub.add_parser("remote-observe", help="Quan sat va dieu khien hanh vi tu xa qua Frida")
    p.add_argument("package", help="Package name cua APK")
    p.add_argument("--hook",
                default=os.path.join(BASE_DIR, "outputs", "behavior", "generated_hook.js"),
                help="Duong dan generated_hook.js")
    p.add_argument("--device", default=None, help="Frida device id (mac dinh USB)")
    p.add_argument("--mode", choices=["spawn", "attach"], default="spawn", help="spawn=frida-server; attach=Gadget listen")
    p.add_argument("--log", default=None, help="File log quan sat JSONL")
    p.add_argument("--save", default=None, help="Luu toan bo su kien JSON khi ket thuc")
    p.add_argument("--rule", action="append", default=[], help="Quy tac dieu khien: match=a,b;command=set_vip_status;value=true")
    p.add_argument("--duration", type=float, default=None, help="So giay quan sat truoc khi tu dong dung")
    p.set_defaults(func=cmd_remote_observe)


    p = sub.add_parser("rodata-find", help="Tìm vị trí tương đối (địa chỉ bộ nhớ) của chuỗi trong tệp mã máy .so")
    p.add_argument("so", help="Tệp thư viện mã máy .so/.elf cần quét")
    p.add_argument("--string", default=None, help="Chuỗi cần tìm (để trống để liệt kê toàn bộ vùng nhớ được cấp phát)")
    p.add_argument("--all", action="store_true", help="Bao gồm cả các vị trí nằm ngoài vùng nhớ ánh xạ")
    p.add_argument("-o", default=None, help="Ghi kết quả ra tệp dữ liệu JSON")
    p.set_defaults(func=cmd_rodata_find)

    p = sub.add_parser("rodata-patch", help="Tạo tập lệnh can thiệp tạm thời để thay đổi chuỗi trong bộ nhớ RAM khi ứng dụng chạy")
    p.add_argument("so", help="Tệp thư viện mã máy gốc (dùng để tự động tính toán vị trí chuỗi)")
    p.add_argument("--string", default=None, help="Chuỗi gốc cần thay thế (tự động dò tìm vị trí; nhiều vị trí thì dùng --offset)")
    p.add_argument("--new", dest="new_string", default=None, help="Chuỗi mới (độ dài tùy ý)")
    p.add_argument("--offset", default=None, help="Địa chỉ bộ nhớ tương đối của chuỗi gốc (ví dụ: 0x1A2B3) — bỏ qua bước tìm kiếm")
    p.add_argument("--ptr-offset", dest="ptr_offset", default=None, help="Địa chỉ ô nhớ đang giữ con trỏ trỏ tới chuỗi (chế độ pointer)")
    p.add_argument("--module", default=None, help="Tên tệp thư viện khi nạp vào bộ nhớ (mặc định lấy theo tên tệp)")
    p.add_argument("--mode", choices=["inline", "pointer", "both"], default="both",
                   help="inline=ghi đè tại chỗ; pointer=đổi con trỏ (an toàn, độ dài tùy ý)")
    p.add_argument("--runtime-scan", dest="runtime_scan", action="store_true",
                   help="Quét bộ nhớ khi ứng dụng đang chạy để tìm chuỗi cũ rồi sửa tại chỗ (không cần địa chỉ tĩnh)")
    p.add_argument("--allow-overflow", dest="allow_overflow", action="store_true",
                   help="Cho phép ghi đè chuỗi dài hơn chuỗi cũ (có rủi ro đè dữ liệu liền kề)")
    p.add_argument("--no-restore", dest="no_restore", action="store_true",
                   help="Không phục hồi quyền bộ nhớ sau khi ghi")
    p.add_argument("--config", default=None, help="Tệp cấu hình JSON chứa nhiều mục cần sửa đổi cùng lúc")
    p.add_argument("-o", default=None, help="Tệp tập lệnh can thiệp xuất ra (mặc định outputs/behavior/rodata_patch.js)")
    p.set_defaults(func=cmd_rodata_patch)


    p = sub.add_parser("rodata-apply", help="Ghi đè chuỗi trực tiếp vào tệp mã máy trên đĩa (sửa tệp vĩnh viễn, có tự động sao lưu)")
    p.add_argument("so", help="Tệp thư viện mã máy .so/.elf cần sửa (tự động sao lưu an toàn trước khi ghi)")
    p.add_argument("--string", default=None, help="Chuỗi gốc cần thay thế (tự động dò tìm vị trí; nhiều vị trí thì dùng --offset)")
    p.add_argument("--new", dest="new_string", default=None, help="Chuỗi mới — KHÔNG được dài hơn chuỗi cũ để bảo đảm an toàn tệp")
    p.add_argument("--offset", default=None, help="Địa chỉ bộ nhớ tương đối của chuỗi gốc (ví dụ: 0x1A2B3) — bỏ qua bước tìm kiếm")
    p.add_argument("--allow-overflow", dest="allow_overflow", action="store_true",
                   help="Cho phép ghi dài hơn độ dài cũ (có rủi ro làm hỏng cấu trúc tệp)")
    p.add_argument("--no-backup", dest="no_backup", action="store_true",
                   help="Không tạo bản sao lưu dự phòng")
    p.add_argument("--backup-dir", dest="backup_dir", default=None,
                   help="Thư mục lưu bản sao lưu (mặc định outputs/backup/rodata_apply/)")
    p.add_argument("--config", default=None, help="Tệp cấu hình JSON chứa nhiều mục cần sửa đổi cùng lúc")
    p.add_argument("--out", default=None,
                   help="Xuất ra tệp mã máy mới thay vì ghi đè trực tiếp lên tệp gốc")
    p.set_defaults(func=cmd_rodata_apply)


    p = sub.add_parser("smart-scan",
                       help="Quét chuỗi nhị phân thông minh: lọc rác + dò luồng dữ liệu + kiểm tra chéo + tính điểm tin cậy 0-100")
    p.add_argument("so", nargs="?", help="Tệp thư viện mã máy .so/.elf cần quét (bỏ trống khi dùng --behaviors)")
    p.add_argument("--min-len", type=int, default=6,
                   help="Độ dài tối thiểu của chuỗi cần lấy (mặc định 6)")
    p.add_argument("--min-risk", type=int, default=0,
                   help="Chỉ giữ lại các chuỗi có mức độ rủi ro lớn hơn hoặc bằng giá trị này (mặc định 0)")
    p.add_argument("--show-noise", action="store_true",
                   help="Kèm danh sách các chuỗi rác đã bị lọc bỏ vào báo cáo")
    p.add_argument("--no-refs", dest="scan_refs", action="store_false",
                   help="Tắt tính năng truy vết tham chiếu dòng lệnh tới chuỗi")
    p.add_argument("-o", default=None,
                   help="Tệp JSON báo cáo kết quả (mặc định outputs/behavior/smart_scan/)")
    p.add_argument("--md", default=None, help="Tệp Markdown báo cáo kết quả (mặc định kèm theo JSON)")
    p.add_argument("--behaviors", action="store_true",
                   help="In bảng từ điển phân loại hành vi rồi thoát")
    p.add_argument("--native", dest="native", action="store_true", default=None,
                   help="Bắt buộc dùng đường quét NEON native (mặc định: tự dùng nếu biên dịch được)")
    p.add_argument("--no-native", dest="native", action="store_false",
                   help="Tắt đường NEON, quét bằng Python thuần")
    p.add_argument("--benchmark", type=int, nargs="?", const=32, metavar="MB",
                   help="Chạy đo tốc độ GB/s thật NEON vs Python trên khối dữ liệu cỡ này rồi thoát")
    p.add_argument("--jni", action="store_true",
                   help="Phân tích thêm bảng RegisterNatives (JNINativeMethod) trong .so: tên, chữ ký, con trỏ hàm")
    p.add_argument("--jni-frida", default=None, metavar="FILE",
                   help="Ghi kịch bản Frida hook theo RVA của các hàm JNI phát hiện được")
    p.set_defaults(func=cmd_smart_scan)


    p = sub.add_parser(
        "start-scan", aliases=["start_scan"],
        help="Quét toàn bộ thư viện mã máy trong APK/thư mục và lập báo cáo tổng hợp")
    p.add_argument("target", help="Tệp APK, thư mục chứa thư viện, hoặc tệp .so đơn lẻ")
    p.add_argument("--abi", default=None,
                   help="Chỉ quét kiến trúc CPU chỉ định (ví dụ: arm64-v8a, armeabi-v7a) khi đầu vào là APK")
    p.add_argument("--min-len", type=int, default=6,
                   help="Độ dài tối thiểu của chuỗi cần lấy (mặc định 6)")
    p.add_argument("--min-risk", type=int, default=60,
                   help="Chỉ giữ lại các chuỗi có mức độ rủi ro lớn hơn hoặc bằng giá trị này (mặc định 60)")
    p.add_argument("--show-noise", action="store_true",
                   help="Kèm danh sách các chuỗi rác đã bị lọc bỏ vào báo cáo")
    p.add_argument("--keep-so", dest="keep_so", action="store_true",
                   help="Giữ lại các tệp thư viện đã trích xuất tại outputs/behavior/smart_scan/so_extract/")
    p.add_argument("--native", dest="native", action="store_true", default=None,
                   help="Bắt buộc dùng đường quét NEON native (mặc định: tự dùng nếu biên dịch được)")
    p.add_argument("--no-native", dest="native", action="store_false",
                   help="Tắt đường NEON, quét bằng Python thuần")
    p.add_argument("-o", default=None,
                   help="Tệp JSON báo cáo kết quả (mặc định outputs/behavior/smart_scan/)")
    p.add_argument("--md", default=None, help="Tệp Markdown báo cáo kết quả (mặc định kèm theo JSON)")
    p.set_defaults(func=cmd_start_scan)


    p = sub.add_parser("neon-bench",
                       help="Đo tốc độ GB/s thật của đường quét NEON ARM64 so với Python thuần")
    p.add_argument("--size-mb", type=int, default=64,
                   help="Cỡ khối dữ liệu thử (MB, mặc định 64)")
    p.add_argument("--needle", default="/system/bin/su",
                   help="Mẫu byte cần tìm trong phép đo mẫu chính xác")
    p.add_argument("--iterations", type=int, default=3,
                   help="Số vòng lặp đo để lấy trung bình")
    p.add_argument("-o", default=None, help="Tệp JSON ghi kết quả đo")
    p.set_defaults(func=cmd_neon_bench)


    p = sub.add_parser("integrity-decouple", help="Triệt tiêu 4 tầng kiểm soát toàn vẹn (Smali AST + DEX digest + Native + Play Integrity)")
    p.add_argument("target", help="Cây Smali / tệp .smali / APK cần phân tích")
    p.add_argument("--orig-apk", default=None, help="APK gốc để trích chữ ký (bắt buộc cho tầng Native)")
    p.add_argument("--new-apk", default=None, help="APK đã can thiệp để đồng bộ mã băm chữ ký Native")
    p.add_argument("--so-dir", default=None, help="Thư mục chứa lib .so đã giải nén")
    p.add_argument("--spearheads", default="all", help="Danh sách mũi nhọn 1-4 cách nhau dấu phẩy (mặc định all)")
    p.add_argument("--dry-run", action="store_true", help="Chỉ phân tích, không ghi tệp")
    p.add_argument("-o", "--output-dir", default="outputs/integrity_decoupler", help="Thư mục xuất báo cáo và hook")
    p.set_defaults(func=cmd_integrity_decouple)


    p = sub.add_parser("autopilot", help="Điều phối tự hành 1-chạm: triage -> xác minh toàn vẹn -> báo cáo")
    p.add_argument("target", help="APK hoặc cây APK đã giải mã")
    p.add_argument("--orig-apk", default=None, help="APK gốc để trích chữ ký (tầng Native)")
    p.add_argument("--new-apk", default=None, help="APK đã can thiệp để đồng bộ hash Native")
    p.add_argument("--so-dir", default=None, help="Thư mục lib .so")
    p.add_argument("--spearheads", default="all", help="Danh sách mũi nhọn 1-4 cách nhau dấu phẩy (mặc định all)")
    p.add_argument("--dry-run", action="store_true", help="Chỉ phân tích, không ghi tệp")
    p.add_argument("--network", action="store_true", help="Bật bước vô hiệu hóa NSC/SSL pinning (tầng mạng)")
    p.add_argument("--native-patch", action="store_true", help="Bật bước đột biến zero-drift trên .so (tầng native)")
    p.add_argument("--decompile", action="store_true",
                   help="Giải mã APK bằng apktool để chạy đủ các bước sửa mã trung gian")
    p.add_argument("--unflatten", action="store_true",
                   help="Bật bước gỡ phẳng luồng mã và cắt tỉa khối chết trên cây đã giải mã")
    p.add_argument("--unflatten-limit", type=int, default=0,
                   help="Giới hạn số phương thức gỡ phẳng (0 = không giới hạn)")
    p.add_argument("--no-package", dest="package", action="store_false",
                   help="Bỏ bước đóng gói và ký số (chỉ phân tích và vá)")
    p.add_argument("--package", dest="package", action="store_true", default=True,
                   help="Bật bước đóng gói và ký số sau khi vá (mặc định bật)")
    p.add_argument("-o", "--output-dir", default=None, help="Thư mục xuất báo cáo")
    p.set_defaults(func=cmd_autopilot)


    p = sub.add_parser("unflatten",
                       help="Gỡ phẳng luồng mã bị làm rối kiểu switch-case và cắt tỉa khối chết (có sao lưu)")
    p.add_argument("target", help="Tệp .smali hoặc cây smali")
    p.add_argument("--apply", action="store_true",
                   help="Ghi thật vào tệp (tự sao lưu .bak vào outputs/backup/unflatten/); mặc định chỉ phân tích")
    p.add_argument("--limit", type=int, default=0,
                   help="Giới hạn số phương thức xử lý khi quét cây (0 = không giới hạn)")
    p.add_argument("--min-cases", type=int, default=2,
                   help="Số nhánh case tối thiểu để coi là bị làm phẳng (mặc định 2)")
    p.add_argument("--backup-root", default=None,
                   help="Thư mục gốc chứa bản sao lưu (mặc định outputs/backup/unflatten/)")
    p.add_argument("-o", default=None, help="Tệp JSON báo cáo")
    p.set_defaults(func=cmd_unflatten)


    p = sub.add_parser("integrity-gate",
                       help="Một cổng kiểm tra toàn vẹn xuyên tầng (G1 vân tay, G2 cấu trúc, G3 ngữ nghĩa, G4 hành vi, G5 chống đạt giả)")
    p.add_argument("target", help="Tệp .smali/.dex/.so/APK hoặc cây APK đã giải mã")
    p.add_argument("--layer", default=None, help="Tầng kiểm (tự nhận diện nếu bỏ trống)")
    p.add_argument("--g3-method", dest="g3_method", default=None,
                   help="Thân phương thức smali để kiểm chứng ngữ nghĩa (G3)")
    p.add_argument("--g3-expected", dest="g3_expected", default="true",
                   help="Giá trị trả về kỳ vọng (true/false)")
    p.add_argument("-o", default=None, help="Tệp JSON kết quả")
    p.set_defaults(func=cmd_integrity_gate)


    p = sub.add_parser("ast-dsl",
                       help="Vá ngữ nghĩa bằng ngôn ngữ quy tắc trên cây AST Smali (tìm mẫu -> ràng buộc -> biến đổi -> in lại smali hợp lệ)")
    p.add_argument("target", help="Tệp .smali hoặc cây smali")
    p.add_argument("--rules", required=True,
                   help="Tệp JSON danh sách quy tắc (mảng hoặc đối tượng có khóa 'quy_tac')")
    p.add_argument("--apply", action="store_true",
                   help="Ghi thật vào tệp (tự sao lưu .bak); mặc định chỉ phân tích")
    p.add_argument("--output-dir", default=None,
                   help="Khi chỉ phân tích: ghi bản dự kiến ra thư mục này (không sửa cây gốc)")
    p.add_argument("-o", default=None, help="Tệp JSON báo cáo")
    p.set_defaults(func=cmd_ast_dsl)


    p = sub.add_parser("dex-method",
                       help="Trình sửa DEX ở mức phương thức: xem bản đồ tên->lệnh hoặc vá opcode cùng độ dài (tự tính lại chữ ký)")
    p.add_argument("dex", help="Tệp classes*.dex")
    p.add_argument("--map", action="store_true", help="In bản đồ phương thức (không sửa)")
    p.add_argument("--method", default=None, help="Lọc phương thức theo regex tên")
    p.add_argument("--swap", default=None, metavar="HEX_CU=HEX_MOI",
                   help="Thay mẫu lệnh hex cùng độ dài byte trong phương thức khớp")
    p.add_argument("--apply", action="store_true", help="Ghi thật (có sao lưu); mặc định chỉ phân tích")
    p.add_argument("--backup", default="outputs/backup/dex-method", help="Thư mục sao lưu khi --apply")
    p.add_argument("-o", default=None, help="Tệp JSON báo cáo")
    p.set_defaults(func=cmd_dex_method)


    p = sub.add_parser("menu", help="Danh sách chức năng chọn pipeline (menu có nhóm + sắp xếp)")
    p.add_argument("--list", action="store_true", help="In toàn bộ danh sách chức năng")
    p.add_argument("--goal", default=None, help="Tìm theo mục tiêu (tính điểm khớp, xếp hạng)")
    p.add_argument("--run", default=None, help="Chạy pipeline theo ID (vd rodata-static)")
    p.add_argument("--set", action="append", default=[], help="Giá trị placeholder KEY=VALUE")
    p.add_argument("--no-confirm", dest="no_confirm", action="store_true", help="Chạy pipeline không hỏi xác nhận")
    p.set_defaults(func=cmd_menu)

    p = sub.add_parser("diff-apk", help="Sinh patch từ khác biệt hai APK/cây")
    p.add_argument("goc", help="APK/thư mục gốc")
    p.add_argument("da_mod", help="APK/thư mục đã sửa")
    p.add_argument("--name", default="diff_apk", help="Tên patch")
    p.add_argument("-o", help="Tệp zip/patch đầu ra")
    p.add_argument("--keep-trees", help="Giữ lại cây giải mã")
    p.add_argument("--semantic-plan", help="Sinh semantic plan V1")
    p.add_argument("--semantic-plan-v2", help="Sinh semantic plan V2")
    p.add_argument("--version-map", help="Ghi version map JSON")
    p.add_argument("--no-verify", action="store_true", help="Bỏ qua xác minh")
    p.set_defaults(func=cmd_diff_apk)

    p = sub.add_parser("suggest-apk", help="Gợi ý patch theo APK thật")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("--top", type=int, default=10, help="Số gợi ý")
    p.add_argument("-o", help="Thư mục ghi kết quả")
    p.set_defaults(func=cmd_suggest_apk)

    p = sub.add_parser("suggest-llm", help="Gợi ý patch theo ý định")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("y_dinh", nargs="+", help="Chuỗi mô tả ý định")
    p.add_argument("--top", type=int, default=5, help="Số gợi ý")
    p.add_argument("--approve", action="store_true", help="Tự động duyệt và ghi combo")
    p.add_argument("-o", help="Thư mục ghi combo")
    p.set_defaults(func=cmd_suggest_llm)

    p = sub.add_parser("roadmap", help="Sinh roadmap thực thi patch")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("cay_apk", help="Thư mục APK đã giải mã")
    p.add_argument("-o", help="Thư mục ghi kết quả")
    p.set_defaults(func=cmd_roadmap)

    p = sub.add_parser("simulate", help="Mô phỏng áp patch trên cây APK")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("--apk", help="Thư mục APK đã giải mã")
    p.add_argument("--quick", action="store_true", help="Mô phỏng nhanh")
    p.add_argument("--dex-runner", help="Lệnh dex runner")
    p.add_argument("--dex-timeout", type=int, default=60, help="Timeout dex")
    p.add_argument("-o", help="Thư mục ghi báo cáo")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("selfcheck", help="Tự kiểm tra module và kho patch")
    p.add_argument("thu_muc", nargs="?", default=None, help="Thư mục kho patch")
    p.add_argument("--full", action="store_true", help="Chạy full test suite")
    p.set_defaults(func=cmd_selfcheck)

    p = sub.add_parser("combo", help="Tạo các bộ gộp patch (combos)")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("-o", help="Thư mục ghi combo")
    p.add_argument("--auto", action="store_true", help="Tự động phát hiện combo")
    p.add_argument("--only", help="Chỉ gộp các nhóm chỉ định")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.add_argument("--apk", help="Thư mục APK lọc độ phủ")
    p.set_defaults(func=cmd_combo)

    p = sub.add_parser("ui", help="Giao diện dòng lệnh TUI")
    p.add_argument("--demo", action="store_true", help="Chế độ demo")
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("frida", help="Sinh Frida script từ tệp phân tích")
    p.add_argument("-i", "--input", required=True, help="Tệp đầu vào")
    p.add_argument("-o", "--output", default="generated_hook.js", help="Tệp xuất ra")
    p.set_defaults(func=cmd_frida)

    p = sub.add_parser("stats", help="Thống kê tổng quan kho patch")
    p.add_argument("thu_muc", help="Thư mục kho patch")
    p.add_argument("--recursive", action="store_true", help="Quét thư mục con")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("clean", help="Dọn dẹp tệp/thư mục tạm")
    p.add_argument("thu_muc", help="Thư mục gốc")
    p.set_defaults(func=cmd_clean)

    p = sub.add_parser("precompile", help="Tiền biên dịch bytecode Python tối ưu trên 8 nhân CPU")
    p.add_argument("-j", "--workers", type=int, default=None, help="Số nhân CPU thực thi song song")
    p.add_argument("-O", "--optimize", type=int, default=1, choices=[0, 1, 2], help="Mức tối ưu hóa bytecode (0, 1, 2)")
    p.set_defaults(func=cmd_precompile)

    p = sub.add_parser("packet", help="Bộ công cụ an ninh mạng gói tin: guard | forge | arena | middleware")
    p.add_argument("tool", choices=["guard", "forge", "arena", "middleware"], help="Công cụ cần chạy")
    p.add_argument("tool_args", nargs=argparse.REMAINDER, help="Tham số phụ của công cụ đã chọn")
    p.set_defaults(func=cmd_packet)

    p = sub.add_parser("auto-gate", help="Tự động can thiệp các cổng an ninh bằng Smali AST Mutator và Micro-DEX Emulator")
    p.add_argument("tree", help="Thư mục cây APK đã giải mã")
    p.add_argument("--min-confidence", type=float, default=75.0, help="Ngưỡng tin cậy tối thiểu (mặc định: 75.0%%)")
    p.add_argument("--max-gates", type=int, default=50, help="Số lượng cổng tối đa cần quét (mặc định: 50)")
    p.add_argument("--no-backup", action="store_true", help="Không tạo tệp sao lưu .bak")
    p.set_defaults(func=cmd_auto_gate)

    p = sub.add_parser("network-bypass", help="Đột phá tầng mạng: mở khóa NSC, Cleartext và sinh tập lệnh vô hiệu hóa SSL Pinning đa tầng")
    p.add_argument("target", help="Đường dẫn APK hoặc thư mục cây APK")
    p.add_argument("-o", "--output-dir", default="outputs/network_bypass", help="Thư mục xuất báo cáo và tập lệnh")
    p.add_argument("--no-cleartext", action="store_true", help="Không can thiệp NSC và Cleartext traffic")
    p.add_argument("--no-ssl-script", action="store_true", help="Không sinh tập lệnh Frida SSL Pinning Nullifier")
    p.set_defaults(func=cmd_network_bypass)

    p = sub.add_parser("native-auto-patch", help="Đột phá tầng thư viện: quét và đột biến nhị phân zero-drift vô hiệu hóa chốt chặn Native C/C++")
    p.add_argument("target", help="Đường dẫn tệp .so hoặc thư mục/cây chứa .so")
    p.add_argument("-o", "--output-dir", default="outputs/native_mutator", help="Thư mục xuất kết quả")
    p.add_argument("--dry-run", action="store_true", help="Chỉ quét và sinh tập lệnh Frida, không sửa trực tiếp file .so")
    p.set_defaults(func=cmd_native_auto_patch)

    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
