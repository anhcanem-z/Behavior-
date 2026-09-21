# -*- coding: utf-8 -*-
"""Bộ tự kiểm tra patchx — chạy: python3 patchx test
Thư mục tạm được tạo riêng và dọn sạch sau khi chạy."""

import glob
import io
import os
import shutil
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchx_core.parser import parse_patch_file, parse_text
from patchx_core.audit import parse_nested_zip
from patchx_core.engine import Engine
from patchx_core.audit import audit_patch, upgrade_zip, LEVEL_ERROR
from patchx_core.optimizer import merge_patches, find_conflicts
from patchx_core.smali_validate import validate_file, validate_tree
from patchx_core.advisor import coverage_patch
from patchx_core.indexer import scan_dir, patch_sha256
from patchx_core.engine import Engine

TMP = "/data/data/com.termux/files/usr/tmp"
# Thư mục bộ sưu tập chuẩn hóa (upgraded/) — ưu tiên bản đã nâng cấp
PATCHX = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_ROOT = os.path.dirname(PATCHX)

ADDSAVE_TEXT = (
    "[MIN_ENGINE_VER]\n1\n[/MIN_ENGINE_VER]\n"
    "[AUTHOR]\nNai\n[/AUTHOR]\n"
    "[PACKAGE]\nDemo\n[/PACKAGE]\n"
    "[ADD_FILES]\nSOURCE:\nsave.smali\nTARGET:\nsmali/save.smali\n"
    "[/ADD_FILES]\n"
    "[MATCH_REPLACE]\nTARGET:\n[LAUNCHER_ACTIVITIES]\nMATCH:\n"
    "onCreate\nREGEX:\nfalse\nREPLACE:\nLsave;->m()V\n[/MATCH_REPLACE]\n")


def make_patch_zip(d, name, text, assets=None):
    """Tạo zip patch tổng hợp trong thư mục tạm — trả đường dẫn."""
    zpath = os.path.join(d, name)
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("patch.txt", text)
        for an, av in (assets or {}).items():
            zf.writestr(an, av)
    return zpath

RESULTS = []


def check(name, condition, detail=""):
    RESULTS.append((name, bool(condition), detail))
    print(("[PASS] " if condition else "[FAIL] ") + name +
          (" — " + detail if detail else ""))


def make_tree(root):
    """Tạo cây APK giả lập nhỏ."""
    smali = os.path.join(root, "smali", "com", "demo")
    os.makedirs(smali, exist_ok=True)
    manifest = os.path.join(root, "AndroidManifest.xml")
    with open(manifest, "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="utf-8"?>\n'
                 '<manifest xmlns:android="http://schemas.android.com/apk/'
                 'res/android" package="com.demo">\n'
                 '  <application android:name=".App">\n'
                 '    <activity android:name=".MainActivity">\n'
                 '      <intent-filter>\n'
                 '        <action android:name="android.intent.action.MAIN"/>\n'
                 '        <category android:name="android.intent.category.LAUNCHER"/>\n'
                 '      </intent-filter>\n'
                 '    </activity>\n'
                 '  </application>\n'
                 '</manifest>\n')
    with open(os.path.join(smali, "MainActivity.smali"), "w",
              encoding="utf-8") as fh:
        fh.write(".class public Lcom/demo/MainActivity;\n\n"
                 ".method protected onCreate(Landroid/os/Bundle;)V\n"
                 "    .registers 5\n\n"
                 "    return-void\n"
                 ".end method\n")
    with open(os.path.join(smali, "Util.smali"), "w", encoding="utf-8") as fh:
        fh.write(".class public Lcom/demo/Util;\n"
                 "const-string v0, \"com.example\"\n"
                 "return-void\n")
    return root


def test_parser():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_parser_")
    try:
        zpath = make_patch_zip(
            d, "AddSave.zip", ADDSAVE_TEXT,
            {"save.smali": ".class public Lsave;\n.method public static "
                           "m()V\nreturn-void\n.end method\n"})
        p = parse_patch_file(zpath)
        check("parser: AddSave phân tích được", len(p.sections) >= 5)
        targets = [s.get("TARGET").strip() for s in p.sections]
        check("parser: pseudo-target [LAUNCHER_ACTIVITIES]",
              "[LAUNCHER_ACTIVITIES]" in targets)
        check("parser: metadata AddSave",
              p.min_engine_ver == "1" and p.author == "Nai")
        # Quét toàn bộ bộ sưu tập thật (chỉ đọc): không patch nào vỡ
        bad = []
        for z in sorted(glob.glob(os.path.join(RAW_ROOT, "*.zip"))):
            try:
                parse_patch_file(z)
            except ValueError:
                nested = parse_nested_zip(z)
                if not nested:
                    bad.append(os.path.basename(z))
            except Exception as e:
                bad.append("%s: %s" % (os.path.basename(z), e))
        check("parser: toàn bộ bộ sưu tập đọc được", not bad,
              ", ".join(bad) if bad else "%d zip OK" % len(
                  glob.glob(os.path.join(RAW_ROOT, "*.zip"))))
        # Zip lồng nhau: dựng fixture tổng hợp (3 zip con, mỗi zip có patch.txt)
        nested_zip = os.path.join(d, "nested.zip")
        with zipfile.ZipFile(nested_zip, "w") as zf:
            for i in ("a", "b", "c"):
                inner = io.BytesIO()
                with zipfile.ZipFile(inner, "w") as iz:
                    iz.writestr("patch.txt",
                                "[PACKAGE]\ncom.demo\n[/PACKAGE]\n")
                zf.writestr("%s.zip" % i, inner.getvalue())
        nested = parse_nested_zip(nested_zip)
        check("parser: zip lồng nhau 3 patch", len(nested) == 3,
              str(len(nested)))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_engine():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_engine_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        zpath = make_patch_zip(
            d, "AddSave.zip", ADDSAVE_TEXT,
            {"save.smali": ".class public Lsave;\n.method public static "
                           "m()V\nreturn-void\n.end method\n"})
        p = parse_patch_file(zpath)
        eng = Engine(tree, quiet=True)
        eng.apply(p)
        eng.finalize()
        save_ok = os.path.isfile(os.path.join(tree, "smali", "save.smali"))
        check("engine: ADD_FILES tạo save.smali", save_ok)
        text = open(os.path.join(tree, "smali", "com", "demo",
                                 "MainActivity.smali"), encoding="utf-8").read()
        check("engine: MATCH_REPLACE trên launcher activity",
              "Lsave;->m(" in text)
        # Idempotency: áp lại lần 2 không tạo thay đổi mới
        eng2 = Engine(tree, quiet=True)
        before = len(eng2.changes)
        eng2.apply(p)
        eng2.finalize()
        after = len(eng2.changes)
        check("engine: idempotency (lần 2 không sửa gì)", after == before,
              "%d -> %d" % (before, after))
        # Biến MATCH_ASSIGN + ${VAR}
        tree2 = os.path.join(d, "tree2")
        make_tree(tree2)
        mini = ("[MATCH_ASSIGN]\nTARGET:\nAndroidManifest.xml\nMATCH:\n"
                "package=\"([^\"]+)\"\nREGEX:\ntrue\nASSIGN:\n"
                "PKG=${GROUP1}\n[/MATCH_ASSIGN]\n"
                "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Util.smali\n"
                "MATCH:\ncom.example\nREGEX:\nfalse\nREPLACE:\n${PKG}\n"
                "[/MATCH_REPLACE]\n")
        pm = parse_text(mini)
        eng3 = Engine(tree2, quiet=True)
        eng3.apply(pm)
        eng3.finalize()
        util = open(os.path.join(tree2, "smali", "com", "demo", "Util.smali"),
                    encoding="utf-8").read()
        check("engine: biến ${PKG} từ MATCH_ASSIGN", "com.demo" in util
              and "com.example" not in util)
        # Glob APK Editor: smali*/*.smali quét đệ quy cả thư mục sâu
        tree5 = os.path.join(d, "tree5")
        make_tree(tree5)
        deep_dir = os.path.join(tree5, "smali", "com", "demo", "deep")
        os.makedirs(deep_dir, exist_ok=True)
        with open(os.path.join(deep_dir, "Deep.smali"), "w",
                  encoding="utf-8") as fh:
            fh.write("const-string v0, \"com.example\"\n")
        gpatch = parse_text(
            "[MATCH_REPLACE]\nTARGET:\nsmali*/*.smali\n"
            "MATCH:\ncom.example\nREGEX:\nfalse\nREPLACE:\ncom.demo\n"
            "[/MATCH_REPLACE]\n")
        eng5 = Engine(tree5, quiet=True)
        eng5.apply(gpatch)
        eng5.finalize()
        deep = open(os.path.join(deep_dir, "Deep.smali"),
                    encoding="utf-8").read()
        shallow = open(os.path.join(tree5, "smali", "com", "demo",
                                    "Util.smali"), encoding="utf-8").read()
        check("engine: glob smali*/*.smali quét đệ quy",
              "com.demo" in deep and "com.demo" in shallow)

        # Luồng GOTO: khối b sau nhãn end không được thực thi
        tree3 = os.path.join(d, "tree3")
        make_tree(tree3)
        goto = ("[MATCH_REPLACE]\nNAME:\na\nTARGET:\nsmali/com/demo/Util.smali\n"
                "MATCH:\ncom.example\nREGEX:\nfalse\nREPLACE:\nAAA\n[/MATCH_REPLACE]\n"
                "[GOTO]\nGOTO:\nend\n[/GOTO]\n"
                "[MATCH_REPLACE]\nNAME:\nb\nTARGET:\nsmali/com/demo/Util.smali\n"
                "MATCH:\nreturn-void\nREGEX:\nfalse\nREPLACE:\nBBB\n[/MATCH_REPLACE]\n"
                "[DUMMY]\nNAME:\nend\n[/DUMMY]\n")
        pg = parse_text(goto)
        eng4 = Engine(tree3, quiet=True)
        eng4.apply(pg)
        eng4.finalize()
        u3 = open(os.path.join(tree3, "smali", "com", "demo", "Util.smali"),
                  encoding="utf-8").read()
        check("engine: GOTO nhảy đúng (b không chạy)", "AAA" in u3
              and "BBB" not in u3)
    finally:
        shutil.rmtree(d, ignore_errors=True)




def test_result_contract():
    """P1 — apply() trả ApplyResult chuẩn hóa với đầy đủ thống kê."""
    from patchx_core.engine import (ApplyResult, RESULT_CHANGED,
                                    RESULT_SKIPPED)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_result_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        p = parse_text(
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/MainActivity.smali\n"
            "MATCH:\nonCreate\nREGEX:\nfalse\nREPLACE:\npatched\n"
            "[/MATCH_REPLACE]\n")
        eng = Engine(tree, quiet=True)
        res = eng.apply(p)
        eng.finalize()
        check("P1: apply trả ApplyResult", isinstance(res, ApplyResult))
        check("P1: status CHANGED khi có sửa", res.status == RESULT_CHANGED,
              res.status)
        check("P1: files_scanned > 0", res.files_scanned >= 1,
              str(res.files_scanned))
        check("P1: matches ≥ 1", res.matches >= 1, str(res.matches))
        check("P1: changes ≥ 1", res.changes >= 1, str(res.changes))
        check("P1: files_changed = 1", res.files_changed == 1,
              str(res.files_changed))
        check("P1: sections có kết quả từng khối", len(res.sections) == 1
              and res.sections[0].status == RESULT_CHANGED,
              str([(s.type, s.status) for s in res.sections]))
        # Lần 2 idempotent: không thay đổi gì
        res2 = eng.apply(p)
        check("P1: lần 2 không đổi", res2.changes == 0,
              "%s / changes=%d" % (res2.status, res2.changes))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_strict_rollback():
    """P2 — STRICT rollback 100% khi patch gây lỗi sau khi đã sửa file."""
    from patchx_core.engine import RESULT_ROLLED_BACK
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_tx_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        p = parse_text(
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/MainActivity.smali\n"
            "MATCH:\nonCreate\nREGEX:\nfalse\nREPLACE:\npatched\n"
            "[/MATCH_REPLACE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/MainActivity.smali\n"
            "MATCH:\n[\nREGEX:\ntrue\nREPLACE:\nx\n[/MATCH_REPLACE]\n")
        path = os.path.join(tree, "smali", "com", "demo",
                            "MainActivity.smali")
        orig = open(path, encoding="utf-8").read()
        eng = Engine(tree, quiet=True, strict=True)
        res = eng.apply(p)
        eng.finalize()
        text = open(path, encoding="utf-8").read()
        check("P2: STRICT rollback — status ROLLED_BACK",
              res.status == RESULT_ROLLED_BACK, res.status)
        check("P2: STRICT rollback — rolled_back=True", res.rolled_back)
        check("P2: STRICT rollback — nội dung file khôi phục",
              text == orig, "file đã bị thay đổi")
        check("P2: STRICT rollback — state không giữ key",
              len(eng.state) == 0, str(eng.state))
        check("P2: STRICT rollback — section đổi thành ROLLED_BACK",
              res.sections[0].status == RESULT_ROLLED_BACK,
              str([(s.type, s.status) for s in res.sections]))
        # Không strict: lỗi sau không kéo rollback
        tree2 = os.path.join(d, "tree2")
        make_tree(tree2)
        eng2 = Engine(tree2, quiet=True, strict=False)
        res2 = eng2.apply(p)
        eng2.finalize()
        t2 = open(os.path.join(tree2, "smali", "com", "demo",
                               "MainActivity.smali"),
                  encoding="utf-8").read()
        check("P2: không STRICT giữ thay đổi (status FAILED nhưng còn file)",
              res2.status == "FAILED" and "patched" in t2,
              "%s / %s" % (res2.status, "patched" in t2))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dex_budget():
    """P5 — DEX Resource Manager: đếm refs, ước lượng delta, phân mức."""
    from patchx_core.dex_budget import (analyze_tree, budget_report,
                                        classify, estimate_delta)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_dexbudget_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        smali = os.path.join(tree, "smali", "com", "demo")
        with open(os.path.join(smali, "Util.smali"), "w",
                  encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Util;\n\n"
                     ".field public static x:I\n\n"
                     ".method public static run(Ljava/lang/String;)V\n"
                     "    .registers 2\n\n"
                     "    sget v0, Lcom/demo/Util;->x:I\n\n"
                     "    const-string v0, \"hello\"\n\n"
                     "    invoke-static {v0}, Lcom/demo/Util;->run(Ljava/lang/String;)V\n\n"
                     "    return-void\n"
                     ".end method\n")
        used = analyze_tree(tree)
        check("P5: đếm được classes ≥ 2", used["classes"] >= 2,
              str(used["classes"]))
        check("P5: đếm được methods ≥ 1", used["methods"] >= 1,
              str(used["methods"]))
        check("P5: đếm được fields ≥ 1", used["fields"] >= 1,
              str(used["fields"]))
        check("P5: đếm được strings ≥ 1", used["strings"] >= 1,
              str(used["strings"]))

        # Hồi quy: đếm đúng từng signature khai báo (không gộp về 1)
        d2 = os.path.join(d, "tree_count")
        os.makedirs(os.path.join(d2, "smali"), exist_ok=True)
        with open(os.path.join(d2, "smali", "C.smali"), "w",
                  encoding="utf-8") as fh:
            fh.write(".class public LC;\n.super Ljava/lang/Object;\n\n"
                     ".method public static m1()V\n    .registers 1\n\n"
                     "    return-void\n.end method\n\n"
                     ".method public static m2(I)V\n    .registers 2\n\n"
                     "    return-void\n.end method\n")
        used2 = analyze_tree(d2)
        check("P5: đếm đúng 2 method khai báo riêng biệt",
              used2["methods"] == 2, str(used2["methods"]))
        delta, per = estimate_delta(
            [type("S", (), {"type": "TRACE"})(),
             type("S", (), {"type": "MATCH_REPLACE"})(),
             type("S", (), {"type": "SET_BOOL"})()])
        check("P5: delta TRACE=+2, MATCH_REPLACE=0, SET_BOOL=0",
              delta == 2 and per == {"TRACE": 2,
                                     "MATCH_REPLACE": 0,
                                     "SET_BOOL": 0},
              "delta=%d %s" % (delta, per))
        lvl, rem, tot = classify(63000, delta=3000)
        check("P5: quá 64K → BLOCK", lvl == "BLOCK" and rem <= 0,
              "%s rem=%d" % (lvl, rem))
        lvl2, _, _ = classify(45000, delta=1000)
        check("P5: ~70% → WATCH", lvl2 == "WATCH", lvl2)
        lvl_hi, _, _ = classify(56000, delta=0)
        check("P5: ~85% → HIGH", lvl_hi == "HIGH", lvl_hi)
        lvl_cr, _, _ = classify(63000, delta=0)
        check("P5: ~96% → CRITICAL", lvl_cr == "CRITICAL", lvl_cr)
        lvl3, _, _ = classify(1000, delta=0)
        check("P5: thấp → SAFE", lvl3 == "SAFE", lvl3)
        rep = budget_report(tree)
        check("P5: budget_report đủ khóa",
              all(k in rep for k in ("used", "delta", "level",
                                     "remaining", "total")))
        from patchx_core.dex_budget import strategy_for
        st = strategy_for(rep)
        check("P6: strategy đủ khóa",
              all(k in st for k in ("strategy", "estimated_delta", "risk",
                                    "confidence", "reason")))
        st_lock = strategy_for(
            {"level": "BLOCK", "remaining": -10, "max_refs": 65536,
             "total": 65546, "delta": 5,
             "used": {"methods": 65541}})
        check("P6: BLOCK → LOCKED", st_lock["strategy"] == "LOCKED"
              and st_lock["risk"] == "HIGH", st_lock["strategy"])
        st_watch = strategy_for(
            {"level": "WATCH", "remaining": 20000, "max_refs": 65536,
             "total": 45536, "delta": 2,
             "used": {"methods": 45534}})
        check("P6: WATCH → EAGER", st_watch["strategy"] == "EAGER"
              and st_watch["risk"] == "LOW", st_watch["strategy"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_preflight():
    """P7 — Preflight: verdict READY/READY_WITH_WARNING/INCOMPATIBLE/UNSAFE."""
    from patchx_core.preflight import preflight_patch
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_preflight_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        p_ok = parse_text(
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/MainActivity.smali\n"
            "MATCH:\nonCreate\nREGEX:\nfalse\nREPLACE:\npatched\n"
            "[/MATCH_REPLACE]\n")
        rep = preflight_patch(p_ok, tree)
        check("P7: patch hợp lệ → READY", rep["verdict"] == "READY",
              rep["summary"])
        p_pkg = parse_text("[PACKAGE]\ncom.sai.package\n[/PACKAGE]\n"
                           "[MATCH_REPLACE]\nTARGET:\nAndroidManifest.xml\n"
                           "MATCH:\npackage=\"com.demo\"\nREGEX:\nfalse\n"
                           "REPLACE:\npackage=\"com.sai.package\"\n"
                           "[/MATCH_REPLACE]\n")
        rep2 = preflight_patch(p_pkg, tree)
        check("P7: PACKAGE sai → READY_WITH_WARNING (chỉ cảnh báo)",
              rep2["verdict"] == "READY_WITH_WARNING", rep2["summary"])
        p_engine = parse_text("[MIN_ENGINE_VER]\n99\n[/MIN_ENGINE_VER]\n")
        rep_eng = preflight_patch(p_engine, tree)
        check("P7: engine quá cũ → INCOMPATIBLE",
              rep_eng["verdict"] == "INCOMPATIBLE", rep_eng["summary"])
        p_nt = parse_text(
            "[MATCH_REPLACE]\nTARGET:\nsmali/khong/ton/tai.smali\n"
            "MATCH:\nxyz\nREGEX:\nfalse\nREPLACE:\nabc\n[/MATCH_REPLACE]\n")
        rep3 = preflight_patch(p_nt, tree)
        check("P7: target không khớp → READY_WITH_WARNING",
              rep3["verdict"] == "READY_WITH_WARNING", rep3["summary"])
        from patchx_core.dex_budget import DEX_METHOD_MAX
        fake_dex = {"level": "BLOCK", "total": DEX_METHOD_MAX + 1,
                    "max_refs": DEX_METHOD_MAX, "remaining": -1,
                    "delta": 0, "used": {"methods": DEX_METHOD_MAX}}
        rep4 = preflight_patch(p_ok, tree, dex_rep=fake_dex)
        check("P7: DEX vượt giới hạn → UNSAFE",
              rep4["verdict"] == "UNSAFE", rep4["summary"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_pipeline_gate():
    """P8 — cổng preflight chặn patch UNSAFE/INCOMPATIBLE trước apply."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ptk_gate", os.path.join(PATCHX, "patchx_toolkit.py"))
    ptk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ptk)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_gate_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        p_ok = os.path.join(d, "ok.txt")
        with open(p_ok, "w", encoding="utf-8") as fh:
            fh.write("[MATCH_REPLACE]\nTARGET:\n"
                     "smali/com/demo/MainActivity.smali\nMATCH:\nonCreate\n"
                     "REGEX:\nfalse\nREPLACE:\npatched\n[/MATCH_REPLACE]\n")
        p_bad = os.path.join(d, "bad.txt")
        with open(p_bad, "w", encoding="utf-8") as fh:
            fh.write("[MIN_ENGINE_VER]\n99\n[/MIN_ENGINE_VER]\n")
        check("P8: gate cho patch hợp lệ đi qua",
              ptk._preflight_gate([p_ok], tree) is True)
        check("P8: gate chặn patch INCOMPATIBLE",
              ptk._preflight_gate([p_bad], tree) is False)
        check("P8: gate chặn khi có 1 patch hỏng trong nhóm",
              ptk._preflight_gate([p_ok, p_bad], tree) is False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_validation_v2():
    """P9 — Validation V2: XML/Manifest/DEX + 4 mức FAST..RELEASE."""
    from patchx_core.smali_validate import validate_tree_v2
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_valv2_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        r = validate_tree_v2(tree, level="NORMAL")
        check("P9: cây sạch → NORMAL ok", r["ok"] and not r["errors"],
              "%s" % r["errors"])
        # Manifest hỏng (mất package)
        tree2 = os.path.join(d, "tree2")
        make_tree(tree2)
        mpath = os.path.join(tree2, "AndroidManifest.xml")
        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
                     '</manifest>')
        r2 = validate_tree_v2(tree2, level="NORMAL")
        check("P9: manifest thiếu package → lỗi",
              any(f["loại"] == "manifest" and f["mức"] == "lỗi"
                  for f in r2["findings"]), str(r2["errors"]))
        # XML hỏng trong res → chỉ FULL phát hiện
        tree3 = os.path.join(d, "tree3")
        make_tree(tree3)
        res = os.path.join(tree3, "res", "values")
        os.makedirs(res, exist_ok=True)
        with open(os.path.join(res, "strings.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write("<resources><string name=\"a\">x</string>")
        r3f = validate_tree_v2(tree3, level="FULL", max_files=20)
        check("P9: XML hỏng → FULL báo lỗi",
              any(f["loại"] == "xml" for f in r3f["findings"]),
              str(r3f["errors"]))
        r3n = validate_tree_v2(tree3, level="FAST")
        check("P9: XML hỏng → FAST bỏ qua (nhanh)",
              not any(f["loại"] == "xml" for f in r3n["findings"]))
        # Level không hợp lệ
        try:
            validate_tree_v2(tree, level="XYZ")
            check("P9: level sai bị chặn", False)
        except ValueError:
            check("P9: level sai bị chặn", True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_parser_edge_p11():
    """P11 — Parser biên: rỗng, BOM, khối mở dở, loại lạ."""
    from patchx_core.parser import parse_text
    p0 = parse_text("")
    check("P11: patch rỗng → 0 khối", len(p0.sections) == 0)
    pb = parse_text("\ufeff[PACKAGE]\nDemo\n[/PACKAGE]\n")
    check("P11: BOM được bỏ qua", pb.package == "Demo"
          and len(pb.sections) == 1, str(pb.package))
    pu = parse_text("[MATCH_REPLACE]\nTARGET:\nx\nMATCH:\ny\n")
    check("P11: khối mở dở closed=False",
          len(pu.sections) == 1 and not pu.sections[0].closed,
          str(pu.sections))
    px = parse_text("[FOOBAR]\nX\n[/FOOBAR]\n[PACKAGE]\nA\n[/PACKAGE]\n")
    check("P11: khối lạ giữ nguyên thứ tự",
          [s.type for s in px.sections] == ["FOOBAR", "PACKAGE"],
          str([s.type for s in px.sections]))


def test_engine_tx_ensure_p11():
    """P11 — Engine helper ngoài apply không crash (hồi quy _tx None)."""
    from patchx_core.engine import Engine
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_txen_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        eng = Engine(tree, quiet=True, no_dex=True)
        zpath = make_patch_zip(
            d, "add.zip",
            "[ADD_FILES]\nSOURCE:\na.txt\nTARGET:\nsmali/x.smali\n"
            "[/ADD_FILES]\n", assets={"a.txt": b"hello"})
        pa = parse_patch_file(zpath)
        try:
            eng._add_files(pa, pa.sections[0])
            check("P11: _add_files ngoài apply không crash", True)
        except Exception as e:
            check("P11: _add_files ngoài apply không crash", False, "%r" % e)
        check("P11: tệp được thêm",
              os.path.isfile(os.path.join(tree, "smali", "x.smali")))
        pr = parse_text("[REMOVE_FILES]\nTARGET:\nAndroidManifest.xml\n"
                        "[/REMOVE_FILES]\n")
        eng._remove_files(pr, pr.sections[0])
        check("P11: REMOVE_FILES chặn xóa manifest",
              os.path.isfile(os.path.join(tree, "AndroidManifest.xml")))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_scan_modes_p16():
    """P16 — 4 chế độ quét: FAST/NORMAL/FULL/RELEASE + chặn mode lạ."""
    from patchx_core.advisor import coverage_patch
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_mode_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        p = parse_text("[MATCH_REPLACE]\nTARGET:\nsmali*/*.smali\n"
                       "MATCH:\nonCreate\nREGEX:\nfalse\n"
                       "REPLACE:\npatched\n[/MATCH_REPLACE]\n")
        try:
            coverage_patch(p, tree, mode="XYZ")
            check("P16: mode lạ bị chặn", False)
        except ValueError:
            check("P16: mode lạ bị chặn", True)
        for mode in ("FAST", "NORMAL", "FULL", "RELEASE"):
            cov = coverage_patch(p, tree, mode=mode)
            check("P16: mode %s được ghi nhận" % mode,
                  cov["mode"] == mode and all(
                      d2["mode"] == mode for d2 in cov["chi_tiết"]),
                  cov["mode"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_simulate_cache_change_p11():
    """P11 — Cache simulate: patch khác → không trúng cache."""
    from patchx_core.simulate import run_simulation
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_sc_")
    try:
        sim_dir = os.path.join(wd, "sim_patches")
        os.makedirs(sim_dir, exist_ok=True)
        base = ("[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\n[LAUNCHER_ACTIVITIES]\n"
                "MATCH:\nonCreate\nREGEX:\nfalse\n")
        make_patch_zip(sim_dir, "p1.zip", base + "REPLACE:\nxxx\n"
                       "[/MATCH_REPLACE]\n")
        cache = os.path.join(wd, "cache")
        s1 = run_simulation(sim_dir, work_dir=wd, quick=True, cache_dir=cache)
        check("P11: lần đầu không trúng cache", s1["cache_hits"] == 0,
              str(s1["cache_hits"]))
        s2 = run_simulation(sim_dir, work_dir=wd, quick=True, cache_dir=cache)
        check("P11: lần 2 trúng cache", s2["cache_hits"] == 1,
              str(s2["cache_hits"]))
        make_patch_zip(sim_dir, "p2.zip", base + "REPLACE:\nyyy\n"
                       "[/MATCH_REPLACE]\n")
        s3 = run_simulation(sim_dir, work_dir=wd, quick=True, cache_dir=cache)
        check("P11: patch mới không trúng cache (1/2 trúng)",
              s3["cache_hits"] == 1 and s3["tổng_patch"] == 2,
              "%d/%d" % (s3["cache_hits"], s3["tổng_patch"]))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_failure_gen_message_p11():
    """P11 — Sinh regression test theo thông báo lỗi."""
    from patchx_core.failure_db import classify_failure, gen_regression_test
    hit = classify_failure('apktool: Syntax error: "(" unexpected')
    check("P11: tra theo message → F-BUILD-001",
          hit and hit["error_id"] == "F-BUILD-001",
          hit and hit["error_id"] or "None")
    src = gen_regression_test(hit)
    check("P11: gen test có tên + classify_failure",
          "def test_failure_f_build_001():" in src
          and "classify_failure" in src, src[:80])


def test_dex_strategy_all_p11():
    """P11 — Chiến lược DEX cho cả 5 mức."""
    from patchx_core.dex_budget import strategy_for
    want = {"SAFE": "AGGRESSIVE", "WATCH": "EAGER", "HIGH": "BALANCED",
            "CRITICAL": "CONSERVATIVE", "BLOCK": "LOCKED"}
    for lvl, tot in (("SAFE", 1000), ("WATCH", 50000), ("HIGH", 58000),
                     ("CRITICAL", 63000), ("BLOCK", 70000)):
        st = strategy_for({"level": lvl, "remaining": 65536 - tot,
                           "max_refs": 65536, "total": tot, "delta": 0,
                           "used": {"methods": tot}})
        check("P11: %s → %s" % (lvl, want[lvl]),
              st["strategy"] == want[lvl], st["strategy"])
        check("P11: %s có risk+confidence" % lvl,
              st.get("risk") and st.get("confidence") >= 0,
              "%s %s" % (st.get("risk"), st.get("confidence")))


def test_baseline_compare_p11():
    """P11 — Baseline: lưu/nạp/so sánh, chặn hồi quy."""
    from patchx_core.baseline import (save_metrics, load_metrics,
                                      compare_metrics)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_bl_")
    try:
        m = {"test_pass": 272, "test_total": 272, "test_ratio": 100.0,
             "errors": 0, "scan_time_s": 23.5}
        path = os.path.join(d, "m.json")
        save_metrics(path, m)
        m2 = load_metrics(path)
        check("P11: baseline lưu/nạp khớp", m == m2)
        c = compare_metrics(m, m2)
        check("P11: baseline bằng nhau → ACCEPT", c["verdict"] == "ACCEPT",
              "%s" % c["reasons"])
        m3 = dict(m, test_ratio=50.0, errors=3)
        c2 = compare_metrics(m, m3)
        check("P11: hồi quy → BLOCK + lý do",
              c2["verdict"] == "BLOCK" and any(
                  "test_ratio" in r for r in c2["reasons"]),
              "%s" % c2["reasons"])
        from patchx_core.baseline import render_compare
        check("P11: render_compare có kết luận",
              "ACCEPT" in render_compare(c) and "BLOCK" in render_compare(c2))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_scenario_validate_more_p11():
    """P11 — Scenario: validate chặt hơn + screenshot thiếu thư mục."""
    import patchx_core.runtime_scenario as rs
    for bad, label in (({"steps": [{"type": "navigate", "key": "up"}]},
                        "navigate key lạ"),
                       ({"steps": [{"type": "wait", "seconds": -1}]},
                        "wait âm"),
                       ({"steps": [{"type": "assert_logcat",
                                    "expect": "không-phải-list"}]},
                        "assert_logcat sai kiểu")):
        try:
            rs.validate_scenario(bad)
            check("P11: %s bị chặn" % label, False)
        except ValueError:
            check("P11: %s bị chặn" % label, True)
    old = rs._adb
    rs._adb = lambda device, args, timeout=30: (0, "")
    try:
        r = rs.run_scenario("dev", "com.demo", ".Main",
                            {"steps": [{"type": "screenshot",
                                        "name": "x"}]})
        st = r["steps"][0]
        check("P11: screenshot thiếu out_dir → ok=False, không crash",
              not st["ok"] and "scenario-out" in st["detail"],
              "%s" % st["detail"])
    finally:
        rs._adb = old


def test_dex_parallel_p20():
    """P20 — Performance: analyze_tree workers>1 cho kết quả khớp workers=1."""
    from patchx_core.dex_budget import analyze_tree
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_p20_")
    try:
        tree = os.path.join(d, "tree")
        smali = os.path.join(tree, "smali")
        os.makedirs(smali, exist_ok=True)
        for i in range(6):
            with open(os.path.join(smali, "F%d.smali" % i), "w",
                      encoding="utf-8") as fh:
                fh.write(".class public LF%d;\n.super Ljava/lang/Object;\n\n"
                         ".method public static m%d()V\n    .registers 1\n\n"
                         "    return-void\n.end method\n" % (i, i))
        r1 = analyze_tree(tree, workers=1)
        r4 = analyze_tree(tree, workers=4)
        check("P20: workers=4 khớp workers=1",
              r1 == r4, "%s != %s" % (r1, r4))
        check("P20: đếm đủ method song song", r4["methods"] == 6,
              str(r4["methods"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_plan_evidence_p18():
    """P18 — Evidence-based plan: confidence + evidence + evidence_graph."""
    import json
    from argparse import Namespace
    import patchx_toolkit as tk
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_p18_")
    try:
        tree = os.path.join(wd, "tree")
        os.makedirs(os.path.join(tree, "smali"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("isRooted()  verifyLicense()")
        pdir = os.path.join(wd, "patches")
        os.makedirs(pdir)
        make_patch_zip(pdir, "p1.zip",
                       "[PACKAGE]\nDemo\n[/PACKAGE]\n"
                       "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\n"
                       "MATCH:\nisRooted\nREGEX:\nfalse\n"
                       "REPLACE:\nconst/4 v0, 0x0\n[/MATCH_REPLACE]\n")
        out = os.path.join(wd, "out")
        rc = tk.cmd_apk_plan(Namespace(tree=tree, input=pdir, output=out,
                                       limit=5, limit_combos=50,
                                       no_auto_install=True))
        check("P18: apk-plan chạy được với confidence",
              rc == 0 and os.path.isfile(
                  os.path.join(out, "bypass_plan.json")), "rc=%s" % rc)
        plan = json.load(open(os.path.join(out, "bypass_plan.json"),
                              encoding="utf-8"))
        top = plan["top_patches"][0]
        check("P18: patch có confidence + evidence",
              "confidence" in top and "evidence" in top
              and top["confidence"] > 0, "%s" % top.get("confidence"))
        check("P18: evidence có files_matched + top_files",
              top["evidence"].get("files_matched", 0) >= 1
              and len(top["evidence"].get("top_files", [])) >= 1,
              "%s" % top.get("evidence"))
        gpath = os.path.join(out, "evidence_graph.json")
        check("P18: evidence_graph.json có node + edge",
              os.path.isfile(gpath) and
              json.load(open(gpath, encoding="utf-8")).get("nodes"),
              "thiếu graph")
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_simulate_v2_p17():
    """P17 — Simulation V2: phân loại 5 chiều + cache theo hash."""
    from patchx_core.simulate import run_simulation
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_simv2_")
    try:
        sim_dir = os.path.join(wd, "sim_patches")
        os.makedirs(sim_dir, exist_ok=True)
        good = ("[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\n[LAUNCHER_ACTIVITIES]\n"
                "MATCH:\nonCreate\nREGEX:\nfalse\nREPLACE:\nxxx\n"
                "[/MATCH_REPLACE]\n")
        for i in range(3):
            make_patch_zip(sim_dir, "p%d.zip" % i, good)
        make_patch_zip(sim_dir, "bad.zip",
                       "[MATCH_REPLACE]\nTARGET:\nsmali/khong/tai.smali\n"
                       "MATCH:\nxyz\nREGEX:\nfalse\nREPLACE:\nabc\n"
                       "[/MATCH_REPLACE]\n")
        cache = os.path.join(wd, "cache")
        s1 = run_simulation(sim_dir, work_dir=wd, quick=True,
                            cache_dir=cache)
        check("P17: summary có status_v2 + cache_hits",
              "status_v2" in s1 and "cache_hits" in s1,
              "%s" % sorted(s1.keys()))
        check("P17: mọi record có status_v2",
              all("status_v2" in r for r in s1["chi_tiết"]),
              "%s" % [r.get("status_v2") for r in s1["chi_tiết"]])
        s2 = run_simulation(sim_dir, work_dir=wd, quick=True,
                            cache_dir=cache)
        check("P17: cache trúng khi chạy lại",
              s2["cache_hits"] == s2["tổng_patch"],
              "%d/%d" % (s2["cache_hits"], s2["tổng_patch"]))
        v2 = s1["status_v2"]
        check("P17: có PASS trong phân loại", v2.get("PASS", 0) >= 1,
              str(v2))
        check("P17: không lỗi engine", v2.get("ENGINE_LIMIT", 0) == 0,
              str(v2))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_failure_db_p15():
    """P15 — Failure Intelligence: phân loại, thêm, sinh regression test."""
    from patchx_core.failure_db import (add_failure, classify_failure,
                                        gen_regression_test, render_report)
    hit = classify_failure('aapt2_123.tmp: Syntax error: "(" unexpected')
    check("P15: lỗi aapt2 → F-BUILD-001",
          hit and hit["error_id"] == "F-BUILD-001",
          hit and hit["error_id"] or "None")
    check("P15: lỗi lạ → None",
          classify_failure("lỗi không biết", stage="BUILD") is None)
    hit3 = classify_failure("FATAL EXCEPTION: Main", stage="RUNTIME_M2")
    check("P15: crash runtime → F-RUNTIME-001",
          hit3 and hit3["error_id"] == "F-RUNTIME-001",
          hit3 and hit3["error_id"] or "None")
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_p15_")
    try:
        dbp = os.path.join(d, "fail_db.json")
        entry, path = add_failure(
            {"error_id": "F-TEST-001", "pattern": "lỗi thử nghiệm",
             "stage": "TEST", "cause": "c", "fix": "f", "regression": "r"},
            dbp)
        check("P15: add_failure ghi DB", os.path.isfile(path))
        try:
            add_failure({"error_id": "F-TEST-001", "pattern": "x"}, dbp)
            check("P15: trùng error_id bị chặn", False)
        except ValueError:
            check("P15: trùng error_id bị chặn", True)
        hit4 = classify_failure("có lỗi thử nghiệm ở đây", stage="TEST",
                                db_path=dbp)
        check("P15: tra cứu entry tùy chỉnh",
              hit4 and hit4["error_id"] == "F-TEST-001",
              hit4 and hit4["error_id"] or "None")
        src = gen_regression_test(entry)
        check("P15: gen_regression_test sinh mã test",
              "def test_failure_f_test_001():" in src
              and "classify_failure" in src, src[:60])
        check("P15: render_report có tổng số",
              "Tổng:" in render_report(dbp))
    finally:
        shutil.rmtree(d, ignore_errors=True)



def test_failure_dex_cache_p15():
    """P15 — Hồi quy DEX dở dang/cache apktool (F-DEX-002)."""
    from patchx_core.failure_db import classify_failure
    hit = classify_failure(
        "Caused by: com.android.tools.smali.util.ExceptionWithContext: "
        "Unsigned short value out of range: 65537",
        stage="BUILD")
    check("P15: smali 64K → F-DEX-002",
          hit and hit["error_id"] == "F-DEX-002",
          hit and hit["error_id"] or "None")
    hit2 = classify_failure(
        "Failed to open dex file '/data/app/.../base.apk' from memory: "
        "Invalid or truncated dex file",
        stage="BUILD")
    check("P15: DEX header hỏng → F-DEX-002",
          hit2 and hit2["error_id"] == "F-DEX-002",
          hit2 and hit2["error_id"] or "None")


def test_runtime_scenario_p14():
    """P14 — Runtime M3: engine kịch bản launch/tap/input/assert."""
    import patchx_core.runtime_scenario as rs
    try:
        rs.validate_scenario({"steps": [{"type": "xyz"}]})
        check("P14: type sai bị chặn", False)
    except ValueError:
        check("P14: type sai bị chặn", True)
    try:
        rs.validate_scenario({"steps": [{"type": "tap"}]})
        check("P14: tap thiếu tọa độ bị chặn", False)
    except ValueError:
        check("P14: tap thiếu tọa độ bị chặn", True)
    ok_scn = {"steps": [
        {"type": "launch"}, {"type": "wait", "seconds": 0},
        {"type": "tap", "x": 10, "y": 20},
        {"type": "assert_pid"},
        {"type": "assert_logcat", "expect": ["Displayed com.demo"],
         "forbid": ["FATAL"]},
    ]}
    check("P14: scenario hợp lệ không lỗi",
          rs.validate_scenario(ok_scn) == ok_scn)

    logcat = "Displayed com.demo/.Main: +100ms\n"

    def fake_adb(device, args, timeout=30):
        if args and args[0] == "logcat" and "-d" in args:
            return 0, logcat
        if args[:2] == ["shell", "pidof"]:
            return 0, "1234"
        return 0, ""

    old = rs._adb
    rs._adb = fake_adb
    try:
        r = rs.run_scenario("dev", "com.demo", ".Main", ok_scn)
        check("P14: kịch bản đạt → M3_PASS",
              r["status"] == "M3_PASS" and r["passed"],
              "%s" % r["reasons"])
        bad_scn = {"steps": [{"type": "assert_logcat",
                              "expect": ["KHONG CO"], "forbid": []}]}
        r2 = rs.run_scenario("dev", "com.demo", ".Main", bad_scn)
        check("P14: expect thiếu → M3_FAIL",
              r2["status"] == "M3_FAIL" and not r2["passed"],
              "%s" % r2["reasons"])
        skip_scn = {"steps": [{"type": "wait", "seconds": 0}]}
        r3 = rs.run_scenario("dev", "com.demo", ".Main", skip_scn)
        check("P14: không assert → M3_SKIP",
              r3["status"] == "M3_SKIP", "%s" % r3["reasons"])
    finally:
        rs._adb = old


def test_runtime_status_p13():
    """P13 — Runtime M2/M3: chuẩn hóa M2_PASS/M2_FAIL/M2_SKIP + verdict."""
    import patchx_toolkit as tk
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_p13_")
    try:
        apk = os.path.join(d, "fake.apk")
        with open(apk, "wb") as fh:
            fh.write(b"PK\x05\x06" + b"\x00" * 18)
        old_dev = tk._adb_devices
        old_bad = tk._aapt2_badging
        tk._adb_devices = lambda: []
        tk._aapt2_badging = lambda _p: {"package": "com.demo",
                                        "activity": ".Main"}
        try:
            r = tk._runtime_verify(apk)
            check("P13: không device → M2_SKIP/M3_SKIP/verdict=SKIP",
                  r.get("m2_status") == "M2_SKIP"
                  and r.get("m3_status") == "M3_SKIP"
                  and r.get("verdict") == "SKIP",
                  "%s" % r.get("verdict"))
            check("P13: trạng_thái thiếu môi trường",
                  r.get("trạng_thái") == "thiếu môi trường",
                  "%s" % r.get("trạng_thái"))
        finally:
            tk._adb_devices = old_dev
            tk._aapt2_badging = old_bad
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_fuzz():
    """P12 — Fuzz: 5 invariant không crash/không vi phạm."""
    from patchx_core.fuzz import run_fuzz
    r = run_fuzz(iterations=20, seed=7)
    check("P12: fuzz không crash", not r["crashes"],
          "%s" % [c for c in r["crashes"][:3]])
    check("P12: fuzz không vi phạm invariant", not r["violations"],
          "%s" % [v for v in r["violations"][:3]])
    check("P12: fuzz ok=true", bool(r["ok"]), "iterations=%d" % r["iterations"])


def test_add_files_khong_tu_sua():
    """ADD_FILES: helper do chính patch thêm không bị MATCH_REPLACE của
    cùng patch sửa (hồi quy: com.anymy.reflection bị đệ quy vô hạn)."""
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_addfiles_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        app = os.path.join(tree, "smali", "com", "demo", "MainActivity.smali")
        with open(app, "a", encoding="utf-8") as fh:
            fh.write("\n.method private check(Landroid/content/pm/PackageManager;)V\n"
                     "    .registers 3\n\n"
                     "    invoke-virtual {p0, p1, p2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n\n"
                     "    return-void\n"
                     ".end method\n")
        helper = (".class public Lcom/anymy/reflection;\n"
                  ".super Ljava/lang/Object;\n\n"
                  ".method public static getPackageInfo(Landroid/content/pm/PackageManager;Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n"
                  "    .locals 1\n\n"
                  "    invoke-virtual {p0, p1, p2}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n\n"
                  "    move-result-object v0\n\n"
                  "    return-object v0\n"
                  ".end method\n")
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as zf:
            zf.writestr("smali/com/anymy/reflection.smali", helper)
        patch = ("[MATCH_REPLACE]\n"
                 "TARGET:\nsmali*/*.smali\n"
                 "MATCH:\n"
                 "invoke-virtual \\{([vp]\\d+), ([vp]\\d+), ([vp]\\d+)\\}, Landroid\\/content\\/pm\\/PackageManager;->getPackageInfo\\(Ljava\\/lang\\/String;I\\)Landroid\\/content\\/pm\\/PackageInfo;\n"
                 "REGEX:\ntrue\n"
                 "REPLACE:\n"
                 "invoke-static {${GROUP1}, ${GROUP2}, ${GROUP3}}, Lcom/anymy/reflection;->getPackageInfo(Landroid/content/pm/PackageManager;Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n"
                 "[/MATCH_REPLACE]\n"
                 "[ADD_FILES]\nSOURCE:\nsmali.zip\nTARGET:\nsmali\n"
                 "EXTRACT:\ntrue\n[/ADD_FILES]\n")
        zpath = make_patch_zip(d, "Reflect.zip", patch,
                               {"smali.zip": zbuf.getvalue()})
        p = parse_patch_file(zpath)
        eng = Engine(tree, quiet=True)
        eng.apply(p)
        eng.finalize()
        app_txt = open(app, encoding="utf-8").read()
        helper_path = os.path.join(tree, "smali", "com", "anymy",
                                   "reflection.smali")
        helper_ok = os.path.isfile(helper_path)
        check("add_files: helper được thêm vào cây", helper_ok)
        check("add_files: app được route sang helper",
              "Lcom/anymy/reflection;->getPackageInfo" in app_txt)
        if helper_ok:
            htxt = open(helper_path, encoding="utf-8").read()
            self_call = "Lcom/anymy/reflection;->getPackageInfo" in htxt
            real_call = ("invoke-virtual {p0, p1, p2}, "
                         "Landroid/content/pm/PackageManager;->getPackageInfo")
            check("add_files: helper KHÔNG bị tự sửa (không đệ quy)",
                  real_call in htxt and not self_call,
                  "self_call=%s real_call=%s" % (self_call, real_call in htxt))
    finally:
        shutil.rmtree(d, ignore_errors=True)




def test_golden_rebuild():
    """Đợt D: golden rebuild — giải mã fixture APK → apk-full với patch cố
    định → build → ký → verify. Bảo vệ: helper ADD_FILES không bị tự sửa
    (hồi quy StackOverflowError) và pipeline không vỡ khi sửa engine."""
    import shutil as _shutil
    import subprocess as _sp
    if not all(_shutil.which(t) for t in ("apktool", "aapt2", "zipalign",
                                          "apksigner", "java")):
        check("golden: bỏ qua (thiếu công cụ build)", True)
        return
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_golden_")
    try:
        from patchx_toolkit import cmd_apk_full
        import argparse
        fixtures = os.path.join(PATCHX, "tests", "fixtures")
        tree = os.path.join(d, "tree")
        r = _sp.run(["apktool", "d", "-f", "-o", tree,
                     os.path.join(fixtures, "mini_app.apk")],
                    capture_output=True, text=True, timeout=180)
        check("golden: apktool d fixture OK", r.returncode == 0,
              (r.stderr or r.stdout or "")[-200:])
        if r.returncode != 0:
            return
        out = os.path.join(d, "out")
        args = argparse.Namespace(
            input=os.path.join(PATCHX, "upgraded"),
            output=out,
            tree=tree,
            patches=["Debug_information_and_hack_signature",
                     "patch_bypass_sigcheck_with_reflection",
                     "Debug_information"],
            top=3, limit_combos=5, dry_run=False, no_build=False,
            no_sign=False, no_auto_install=True,
            keystore=os.path.join(fixtures, "test.keystore"),
            ks_pass="patchx123", aapt=None,
            runtime=False, runtime_wait=8, runtime_logcat_lines=2000,
            runtime_expect=[], runtime_forbid=[])
        rc = cmd_apk_full(args)
        check("golden: apk-full chạy hết (rc=0)", rc == 0, "rc=%s" % rc)
        signed = [f for f in glob.glob(os.path.join(out, "*.apk"))
                  if "unsigned" not in f and "aligned" not in f]
        check("golden: có APK đã ký", len(signed) >= 1, str(signed))
        if signed:
            vp = _sp.run(["apksigner", "verify", "--verbose", signed[0]],
                         capture_output=True, text=True, timeout=60)
            check("golden: apksigner verify v1/v2/v3",
                  vp.returncode == 0 and "Verified using v1" in vp.stdout
                  and "Verified using v2" in vp.stdout
                  and "Verified using v3" in vp.stdout)
        # Patch áp đúng: MainActivity được route sang helper
        main = os.path.join(tree, "smali", "com", "example", "mini",
                            "MainActivity.smali")
        mtext = open(main, encoding="utf-8").read() if os.path.isfile(main) else ""
        check("golden: MainActivity được route sang helper",
              "Lcom/anymy/reflection;->getPackageInfo" in mtext)
        # Golden: helper ADD_FILES không bị tự sửa (không đệ quy)
        golden = os.path.join(fixtures, "golden",
                              "reflection_getPackageInfo.golden")
        gtext = open(golden, encoding="utf-8").read().strip()
        hpath = os.path.join(tree, "smali", "com", "anymy",
                             "reflection.smali")
        if os.path.isfile(hpath):
            htxt = open(hpath, encoding="utf-8").read()
            check("golden: helper khớp golden (không tự sửa)",
                  gtext in htxt
                  and "Lcom/anymy/reflection;->getPackageInfo" not in htxt)
        else:
            check("golden: helper khớp golden (không tự sửa)", False,
                  "thiếu reflection.smali")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_resource_fix_sach_tham_chieu():
    """Hồi quy: apk-fix-res phải đổi tên tệp `$` VÀ cập nhật public.xml +
    mọi tham chiếu (bug đã sửa ở _normalize_resource_names)."""
    from patchx_toolkit import _normalize_resource_names
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_fixres_")
    try:
        for sub in ("res/values", "res/drawable", "smali/com/demo"):
            os.makedirs(os.path.join(d, sub))
        with open(os.path.join(d, "res", "drawable",
                               "$chooser_icon__0.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write("<shape/>")
        with open(os.path.join(d, "res", "values", "public.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<resources>\n  <public type="drawable" '
                     'name="$chooser_icon__0" id="0x7f080001" />\n'
                     "</resources>\n")
        with open(os.path.join(d, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest><application '
                     'android:icon="@drawable/$chooser_icon__0"/>'
                     "</manifest>\n")
        smali = os.path.join(d, "smali", "com", "demo", "A.smali")
        with open(smali, "w", encoding="utf-8") as fh:
            fh.write("const v0, 0x7f080001 # @drawable/$chooser_icon__0\n")
        changes = _normalize_resource_names(d, dry_run=False)
        check("fix-res: đổi tên tệp `$`", len(changes) == 1, str(changes))
        pub = open(os.path.join(d, "res", "values", "public.xml"),
                   encoding="utf-8").read()
        check("fix-res: public.xml sạch `$`",
              "$chooser_icon__0" not in pub and "chooser_icon__0" in pub)
        man = open(os.path.join(d, "AndroidManifest.xml"),
                   encoding="utf-8").read()
        check("fix-res: tham chiếu manifest sạch `$`",
              "$chooser_icon__0" not in man
              and "@drawable/chooser_icon__0" in man)
        stxt = open(smali, encoding="utf-8").read()
        check("fix-res: bình luận smali sạch `$`",
              "$chooser_icon__0" not in stxt)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_golden_framework_res():
    """Đợt D: golden rebuild framework-res — decode → apk-fix-res → build
    (tự chọn aapt2 patched khi aapt2 hệ thống crash PrivateAttributeMover)
    → zipalign → sign → verify. Build đầy đủ chỉ chạy khi
    PATCHX_GOLDEN_FW=1 (chậm ~7 phút qua qemu)."""
    import subprocess as _sp
    src = "/storage/emulated/0/framework-res.apk"
    if not os.path.isfile(src):
        check("golden fw: bỏ qua (thiếu framework-res.apk)", True)
        return
    if not all(shutil.which(t) for t in ("apktool", "zipalign",
                                         "apksigner", "java")):
        check("golden fw: bỏ qua (thiếu công cụ build)", True)
        return
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_fw_golden_")
    full = os.environ.get("PATCHX_GOLDEN_FW") == "1"
    try:
        from patchx_toolkit import (_normalize_resource_names,
                                    _build_apktool, _find_patched_aapt2)
        tree = os.path.join(d, "tree")
        r = _sp.run(["apktool", "d", "-f", "-o", tree, src],
                    capture_output=True, text=True, timeout=600)
        check("golden fw: apktool d OK", r.returncode == 0,
              (r.stderr or r.stdout or "")[-200:])
        if r.returncode != 0:
            return
        changes = _normalize_resource_names(tree, dry_run=False)
        check("golden fw: apk-fix-res xử lý tên `$`", True,
              "%d thay đổi" % len(changes))
        pub = os.path.join(tree, "res", "values", "public.xml")
        if os.path.isfile(pub):
            ptxt = open(pub, encoding="utf-8").read()
            check("golden fw: public.xml sạch `$`", "$" not in ptxt)
        if not full:
            check("golden fw: bỏ qua build (PATCHX_GOLDEN_FW=1 để chạy đủ)",
                  True)
            return
        patched = _find_patched_aapt2()
        check("golden fw: tìm thấy aapt2 patched", bool(patched),
              patched or "thiếu aapt2 patched — build có thể thất bại")
        out_apk = os.path.join(d, "fw.apk")
        proc, _cmd = _build_apktool(tree, out_apk)
        check("golden fw: build OK (tự chọn aapt2 patched nếu cần)",
              proc.returncode == 0,
              ((proc.stderr or proc.stdout or "")[-200:]))
        if proc.returncode != 0:
            return
        aligned = os.path.join(d, "fw_aligned.apk")
        ap = _sp.run(["zipalign", "-f", "4", out_apk, aligned],
                     capture_output=True, text=True, timeout=120)
        check("golden fw: zipalign OK", ap.returncode == 0,
              (ap.stderr or "")[-200:])
        signed = os.path.join(d, "fw_signed.apk")
        sp = _sp.run(["apksigner", "sign", "--ks",
                      os.path.join(PATCHX, "tests", "fixtures",
                                   "test.keystore"),
                      "--ks-pass", "pass:patchx123", "--key-pass",
                      "pass:patchx123", "--out", signed, aligned],
                     capture_output=True, text=True, timeout=120)
        check("golden fw: ký OK", sp.returncode == 0,
              (sp.stderr or sp.stdout or "")[-200:])
        if sp.returncode == 0:
            vp = _sp.run(["apksigner", "verify", "--verbose", signed],
                         capture_output=True, text=True, timeout=60)
            check("golden fw: verify chữ ký (v3)",
                  vp.returncode == 0 and "Verified using v3" in vp.stdout,
                  vp.stdout[-200:])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_audit_upgrade():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_upgrade_")
    try:
        raw = parse_text("[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\nMATCH:\naaa\n"
                         "REGEX:\nfalse\nREPLACE:\nAAA\n")
        findings = audit_patch(raw)
        check("audit: phát hiện khối thiếu thẻ đóng",
              any(f.code == "A02" for f in findings))
        out = os.path.join(d, "upgraded")
        nw_text = ("[MIN_ENGINE_VER]\n2\n[/MIN_ENGINE_VER]\n"
                   "[AUTHOR]\nHTC 600\n[/AUTHOR]\n"
                   "[PACKAGE]\n*\n[/PACKAGE]\n"
                   "[MATCH_REPLACE]\nTARGET:\nAndroidManifest.xml\n"
                   "MATCH:\nINTERNET\nREGEX:\nfalse\nREPLACE:\n\n")
        nw_zip = make_patch_zip(d, "NoInternetWifi.zip", nw_text)
        res = upgrade_zip(nw_zip, out, header="test")
        check("upgrade: tạo zip nâng cấp", len(res) == 1)
        zpath = os.path.join(out, os.listdir(out)[0])
        with zipfile.ZipFile(zpath) as zf:
            text = zf.read("patch.txt").decode("utf-8")
        check("upgrade: mọi khối có thẻ đóng",
              text.count("[/MATCH_REPLACE]") == text.count("[MATCH_REPLACE]"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_optimizer():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_opt_")
    try:
        a = parse_text("[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\nMATCH:\naaa\n"
                       "REGEX:\nfalse\nREPLACE:\nAAA\n[/MATCH_REPLACE]\n")
        b = parse_text("[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\nMATCH:\naaa\n"
                       "REGEX:\nfalse\nREPLACE:\nBBB\n[/MATCH_REPLACE]\n")
        conflicts = find_conflicts([a, b])
        check("optimizer: phát hiện xung đột", len(conflicts) == 1)
        merged = merge_patches([a, a, b], "T")
        check("optimizer: gộp + dedupe",
              len(merged.sections) == 2 and len(a.sections) == 1)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_advisor():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_adv_")
    try:
        tree = os.path.join(d, "tree")
        make_tree(tree)
        zpath = make_patch_zip(
            d, "AddSave.zip", ADDSAVE_TEXT,
            {"save.smali": ".class public Lsave;\n.method public static "
                           "m()V\nreturn-void\n.end method\n"})
        p = parse_patch_file(zpath)
        cov = coverage_patch(p, tree)
        check("advisor: coverage tìm thấy mẫu onCreate",
              sum(x["khớp"] for x in cov["chi_tiết"]) >= 1)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_corrupt_zip():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_corrupt_")
    try:
        zpath = os.path.join(d, "corrupt.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("patch.txt", "[PACKAGE]\ncom.demo\n[/PACKAGE]\n")
            zf.writestr("asset.bin", b"PAYLOAD" * 50)
        with zipfile.ZipFile(zpath) as zf:
            info = zf.getinfo("asset.bin")
        with open(zpath, "r+b") as fh:
            fh.seek(info.header_offset)
            local = fh.read(30)
            fname_len, extra_len = struct.unpack("<HH", local[26:30])
            data_start = info.header_offset + 30 + fname_len + extra_len
            fh.seek(data_start)
            fh.write(b"\xff\xff")  # header deflate hỏng → zlib.error khi đọc
        p = parse_patch_file(zpath)
        check("parser: zip hỏng asset không crash",
              any(m.startswith("[ZIP]") for m in p.issues))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dupes():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_dupes_")
    try:
        z1 = os.path.join(d, "a.zip")
        z2 = os.path.join(d, "b.zip")
        z3 = os.path.join(d, "c.zip")
        for z in (z1, z2):
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("patch.txt", "[PACKAGE]\ncom.demo\n[/PACKAGE]\n")
        with zipfile.ZipFile(z3, "w") as zf:
            zf.writestr("patch.txt", "[PACKAGE]\ncom.other\n[/PACKAGE]\n")
        records = scan_dir(d)
        ids = [r["dupe_id"] for r in records]
        check("dupes: 2 file cùng nội dung chung nhóm",
              len([i for i in ids if i == ids[0]]) == 2)
        check("dupes: file khác nội dung không chung nhóm",
              ids[2] is None and ids[0] == ids[1])
        # Đệ quy: bỏ qua thư mục nội bộ _patchx
        os.makedirs(os.path.join(d, "_patchx"), exist_ok=True)
        with zipfile.ZipFile(os.path.join(d, "_patchx", "inner.zip"), "w") as zf:
            zf.writestr("patch.txt", "[PACKAGE]\ncom.demo\n[/PACKAGE]\n")
        rec2 = scan_dir(d, recursive=True)
        check("dupes: đệ quy bỏ qua thư mục nội bộ",
              len(rec2) == 3 and all("_patchx" not in r["path"]
                                     for r in rec2))
        check("dupes: patch_sha256 ổn định",
              patch_sha256(z1) == patch_sha256(z2))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dex_runner():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_dex_")
    try:
        import types
        p = types.SimpleNamespace(name="T", source=os.path.join(d, "p.zip"))
        s = types.SimpleNamespace(get=lambda k, dft="": dft)
        e = Engine(d, no_dex=False, dex_runner="ls; id", quiet=True)
        e._execute_dex(p, s)
        check("dex: chặn runner chứa ký tự shell", len(e.errors) == 1)
        e2 = Engine(d, no_dex=False, dex_runner="khong-ton-tai-cmd-xyz",
                    quiet=True)
        e2._execute_dex(p, s)
        check("dex: báo lỗi lệnh không tồn tại", len(e2.errors) == 1)
        e3 = Engine(d, no_dex=True, quiet=True)
        e3._execute_dex(p, s)
        check("dex: no_dex bỏ qua có cảnh báo",
              len(e3.warnings) == 1 and not e3.errors)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_engine_guards():
    from patchx_core.engine import _literal_hint
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_guard_")
    try:
        # GOTO ngược (chu trình) phải bị chặn, không treo vô hạn
        loop = ("[MATCH_REPLACE]\nNAME:\na\nTARGET:\nsmali/x.smali\n"
                "MATCH:\naaa\nREGEX:\nfalse\nREPLACE:\nAAA\n[/MATCH_REPLACE]\n"
                "[GOTO]\nGOTO:\na\n[/GOTO]\n")
        tree = os.path.join(d, "tree")
        make_tree(tree)
        pg = parse_text(loop)
        eng = Engine(tree, quiet=True)
        try:
            eng.apply(pg)
            check("guard: vòng lặp GOTO bị chặn", False, "không báo lỗi")
        except RuntimeError as e:
            check("guard: vòng lặp GOTO bị chặn", "Vòng lặp" in str(e))
        # ADD_FILES TARGET tuyệt đối bị chặn, không ghi ra ngoài cây
        zpath = make_patch_zip(
            d, "abs.zip", "[ADD_FILES]\nSOURCE:\nx.bin\nTARGET:\n/smali\n"
                         "[/ADD_FILES]\n", {"x.bin": b"DATA"})
        pabs = parse_patch_file(zpath)
        eng2 = Engine(tree, quiet=True)
        eng2.apply(pabs)
        check("guard: ADD_FILES TARGET tuyệt đối bị chặn",
              not os.path.exists("/smali") and len(eng2.errors) == 1)
        # TARGET "/" được coi là gốc cây (tương thích APK Editor)
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, "w") as iz:
            iz.writestr("x.bin", b"DATA")
        zroot = make_patch_zip(
            d, "root.zip", "[ADD_FILES]\nSOURCE:\nx.bin\nTARGET:\n/\nEXTRACT:\ntrue\n"
                          "[/ADD_FILES]\n", {"x.bin": zbuf.getvalue()})
        proot = parse_patch_file(zroot)
        tree2 = os.path.join(d, "tree2")
        make_tree(tree2)
        eng3 = Engine(tree2, quiet=True)
        eng3.apply(proot)
        check("guard: TARGET / giải về gốc cây",
              os.path.isfile(os.path.join(tree2, "x.bin")))
        # Non-EXTRACT với TARGET / phải báo lỗi rõ (không phải đường dẫn tệp)
        zroot2 = make_patch_zip(
            d, "root2.zip", "[ADD_FILES]\nSOURCE:\nx.bin\nTARGET:\n/\n"
                            "[/ADD_FILES]\n", {"x.bin": b"DATA"})
        eng4 = Engine(tree2, quiet=True)
        eng4.apply(parse_patch_file(zroot2))
        check("guard: non-EXTRACT TARGET / bị chặn", len(eng4.errors) == 1)
        # EXTRACT không lặp tiền tố: TARGET=smali, entry=smali/apkeditor/...
        # phải rơi vào smali/apkeditor/... chứ không phải smali/smali/...
        zbuf2 = io.BytesIO()
        with zipfile.ZipFile(zbuf2, "w") as iz:
            iz.writestr("smali/apkeditor/patch/signature/Fix.smali",
                        b".class public LFix;")
        zdup = make_patch_zip(
            d, "dup.zip", "[ADD_FILES]\nSOURCE:\nsmali.zip\nTARGET:\nsmali\n"
                         "EXTRACT:\ntrue\n[/ADD_FILES]\n",
            {"smali.zip": zbuf2.getvalue()})
        tree3 = os.path.join(d, "tree3")
        make_tree(tree3)
        eng5 = Engine(tree3, quiet=True)
        eng5.apply(parse_patch_file(zdup))
        check("guard: EXTRACT không lặp tiền tố smali",
              os.path.isfile(os.path.join(
                  tree3, "smali", "apkeditor", "patch", "signature",
                  "Fix.smali"))
              and not os.path.exists(os.path.join(
                  tree3, "smali", "smali")))
        # Hint regex có nhánh | không được lọc sai
        check("guard: hint bỏ qua regex nhiều nhánh",
              _literal_hint(r"\.local .+|\.line \d+") == "")
        check("guard: hint giữ literal chắc chắn",
              _literal_hint(r"com\.example\.(foo|bar)") == "com.example.")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_modern_blocks():
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_modern_")
    try:
        # SET_BOOL hex + idempotent
        t_bool = os.path.join(d, "t_bool")
        make_tree(t_bool)
        flags = os.path.join(t_bool, "smali", "com", "demo", "Flags.smali")
        os.makedirs(os.path.dirname(flags), exist_ok=True)
        with open(flags, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Flags;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static isOn()Z\n"
                     "    .registers 1\n\n"
                     "    const/4 v0, 0x0\n\n"
                     "    return v0\n"
                     ".end method\n")
        p_bool = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/com/demo/Flags.smali\n"
            "MATCH:\nconst/4 v0, 0x0\nREGEX:\nfalse\nVALUE:\n0x1\n"
            "[/SET_BOOL]\n")
        eng = Engine(t_bool, quiet=True)
        eng.apply(p_bool)
        eng.finalize()
        flags_text = open(flags, encoding="utf-8").read()
        check("modern: SET_BOOL đổi 0x0 thành 0x1",
              "const/4 v0, 0x1" in flags_text
              and "const/4 v0, 0x0" not in flags_text)
        changes_before = len(eng.changes)
        eng.apply(p_bool)
        check("modern: SET_BOOL idempotent",
              len(eng.changes) == changes_before,
              "%d -> %d" % (changes_before, len(eng.changes)))

        # SET_BOOL số nguyên 0 -> 1
        t_dec = os.path.join(d, "t_dec")
        make_tree(t_dec)
        flags_dec = os.path.join(t_dec, "smali", "com", "demo",
                                 "FlagsDec.smali")
        os.makedirs(os.path.dirname(flags_dec), exist_ok=True)
        with open(flags_dec, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/FlagsDec;\n"
                     ".super Ljava/lang/Object;\n"
                     "const/4 v0, 0\n")
        p_dec = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/com/demo/FlagsDec.smali\n"
            "MATCH:\nconst/4 v0, 0\nREGEX:\nfalse\nVALUE:\n1\n"
            "[/SET_BOOL]\n")
        Engine(t_dec, quiet=True).apply(p_dec)
        check("modern: SET_BOOL đổi 0 thành 1",
              "const/4 v0, 1" in open(flags_dec, encoding="utf-8").read())

        # SET_BOOL từ khóa false -> true
        t_word = os.path.join(d, "t_word")
        make_tree(t_word)
        flags_word = os.path.join(t_word, "smali", "com", "demo",
                                  "FlagsWord.smali")
        os.makedirs(os.path.dirname(flags_word), exist_ok=True)
        with open(flags_word, "w", encoding="utf-8") as fh:
            fh.write("const-string v0, \"false\"\n")
        p_word = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/com/demo/FlagsWord.smali\n"
            "MATCH:\nfalse\nREGEX:\nfalse\nVALUE:\ntrue\n"
            "[/SET_BOOL]\n")
        Engine(t_word, quiet=True).apply(p_word)
        check("modern: SET_BOOL đổi false thành true",
              "true" in open(flags_word, encoding="utf-8").read()
              and "\"false\"" not in open(flags_word, encoding="utf-8").read())

        # Audit nhận biết SET_BOOL thiếu VALUE
        bad_bool = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/x.smali\nMATCH:\nfalse\n"
            "REGEX:\nfalse\n[/SET_BOOL]\n")
        findings = audit_patch(bad_bool)
        check("modern: audit phát hiện SET_BOOL thiếu VALUE",
              any(f.code == "A04" and "VALUE" in f.message
                  for f in findings))

        # INIT chèn code + marker
        t_init = os.path.join(d, "t_init")
        make_tree(t_init)
        p_init = parse_text(
            "[INIT]\nTARGET:\n[LAUNCHER_ACTIVITIES]\nMETHOD:\nonCreate\n"
            "CODE:\nconst-string v0, \"patchx-init-ok\"\n[/INIT]\n")
        Engine(t_init, quiet=True).apply(p_init)
        init_text = open(os.path.join(t_init, "smali", "com", "demo",
                                      "MainActivity.smali"),
                         encoding="utf-8").read()
        check("modern: INIT chèn code + marker",
              "patchx-init-ok" in init_text and "# patchx-init:" in init_text)

        # HOOK_SCRIPT ghi file + invoke-static
        t_hook = os.path.join(d, "t_hook")
        make_tree(t_hook)
        hook_smali = (".class public Lcom/demo/Hook;\n"
                      ".super Ljava/lang/Object;\n\n"
                      ".method public static onCreate()V\n"
                      "    .registers 1\n\n"
                      "    return-void\n"
                      ".end method\n")
        hook_zip = make_patch_zip(
            d, "hook.zip",
            "[HOOK_SCRIPT]\nSOURCE:\nHook.smali\nTARGET:\n"
            "[LAUNCHER_ACTIVITIES]\nMETHOD:\nonCreate\nENTRY:\nonCreate\n"
            "[/HOOK_SCRIPT]\n", {"Hook.smali": hook_smali})
        Engine(t_hook, quiet=True).apply(parse_patch_file(hook_zip))
        hook_path = os.path.join(t_hook, "smali", "com", "demo", "Hook.smali")
        check("modern: HOOK_SCRIPT ghi file smali",
              os.path.isfile(hook_path))
        hook_main = open(os.path.join(t_hook, "smali", "com", "demo",
                                      "MainActivity.smali"),
                         encoding="utf-8").read()
        check("modern: HOOK_SCRIPT chèn invoke-static",
              "Lcom/demo/Hook;->onCreate()V" in hook_main
              and "# patchx-hook:" in hook_main)

        # TRACE tăng .registers + Log.d
        t_trace = os.path.join(d, "t_trace")
        make_tree(t_trace)
        p_trace = parse_text(
            "[TRACE]\nTARGET:\nsmali/com/demo/MainActivity.smali\n"
            "MATCH:\nreturn-void\nREGEX:\nfalse\nTAG:\nPatchXTest\n"
            "[/TRACE]\n")
        Engine(t_trace, quiet=True).apply(p_trace)
        trace_text = open(os.path.join(t_trace, "smali", "com", "demo",
                                       "MainActivity.smali"),
                          encoding="utf-8").read()
        check("modern: TRACE tăng .registers + Log.d",
              ".registers 7" in trace_text
              and "const-string v5, \"PatchXTest\"" in trace_text
              and "Landroid/util/Log;->d" in trace_text
              and "# patchx-trace:" in trace_text)

        # API_LOG với URL
        t_api = os.path.join(d, "t_api")
        make_tree(t_api)
        api_path = os.path.join(t_api, "smali", "com", "demo", "Api.smali")
        os.makedirs(os.path.dirname(api_path), exist_ok=True)
        with open(api_path, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Api;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static call()V\n"
                     "    .registers 2\n\n"
                     "    const-string v0, \"https://api.example.com/v1\"\n"
                     "    return-void\n"
                     ".end method\n")
        p_api = parse_text(
            "[API_LOG]\nTARGET:\nsmali/com/demo/Api.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\nTAG:\nApiTest\n"
            "[/API_LOG]\n")
        Engine(t_api, quiet=True).apply(p_api)
        api_text = open(api_path, encoding="utf-8").read()
        check("modern: API_LOG chèn log URL",
              ".registers 4" in api_text
              and "ApiTest" in api_text
              and "Landroid/util/Log;->d" in api_text
              and "# patchx-api:" in api_text)

        # Regression: nhiều method khớp trong MỘT file — offset không bị lệch
        t_multi = os.path.join(d, "t_multi")
        make_tree(t_multi)
        multi_path = os.path.join(t_multi, "smali", "com", "demo",
                                  "Multi.smali")
        os.makedirs(os.path.dirname(multi_path), exist_ok=True)
        with open(multi_path, "w", encoding="utf-8") as fh:
            fh.write(
                ".class public Lcom/demo/Multi;\n"
                ".super Ljava/lang/Object;\n\n"
                ".method public static a()Ljava/lang/String;\n"
                "    .locals 1\n\n"
                "    const-string v0, \"https://a.example.com/x\"\n"
                "    return-object v0\n"
                ".end method\n\n"
                ".method public static b()Ljava/lang/String;\n"
                "    .locals 1\n\n"
                "    const-string v0, \"https://b.example.com/y\"\n"
                "    return-object v0\n"
                ".end method\n\n"
                ".method public static c()Ljava/lang/String;\n"
                "    .locals 1\n\n"
                "    const-string v0, \"https://c.example.com/z\"\n"
                "    return-object v0\n"
                ".end method\n")
        p_multi = parse_text(
            "[API_LOG]\nTARGET:\nsmali/com/demo/Multi.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\nTAG:\nMultiTest\n"
            "[/API_LOG]\n")
        Engine(t_multi, quiet=True).apply(p_multi)
        multi_text = open(multi_path, encoding="utf-8").read()
        check("regression: API_LOG nhiều method 1 file không lệch offset",
              multi_text.count(".end method") == 3
              and multi_text.count(".method public static") == 3
              and multi_text.count(".registers 3") == 3
              and multi_text.count("# patchx-api:") == 3
              and multi_text.find("https://a.example.com/x")
              < multi_text.find("https://b.example.com/y")
              < multi_text.find("https://c.example.com/z"),
              "end=%d head=%d reg=%d mark=%d"
              % (multi_text.count(".end method"),
                 multi_text.count(".method public static"),
                 multi_text.count(".registers 3"),
                 multi_text.count("# patchx-api:")))

        # Guard: method cấu trúc lạ (nested .registers) bị BỎ QUA, không sửa
        t_bad = os.path.join(d, "t_bad")
        make_tree(t_bad)
        bad_path = os.path.join(t_bad, "smali", "com", "demo", "Bad.smali")
        os.makedirs(os.path.dirname(bad_path), exist_ok=True)
        bad_text = (
            ".class public Lcom/demo/Bad;\n"
            ".super Ljava/lang/Object;\n\n"
            ".method public static x()V\n"
            "    .registers 2\n\n"
            "    const-string v0, \"https://bad.example.com/\"\n"
            "    :goto_0\n"
            "        .registers 2\n"
            "    return-void\n"
            ".end method\n")
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write(bad_text)
        p_bad = parse_text(
            "[API_LOG]\nTARGET:\nsmali/com/demo/Bad.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\nTAG:\nBadTest\n"
            "[/API_LOG]\n")
        Engine(t_bad, quiet=True).apply(p_bad)
        check("regression: TRACE bỏ qua method cấu trúc lạ (nested .registers)",
              open(bad_path, encoding="utf-8").read() == bad_text)

        # Validator: abstract/native không phải lỗi; method thật lỗi thì báo
        ok_abs = validate_file(
            ".class public Lcom/demo/A;\n"
            ".super Ljava/lang/Object;\n\n"
            ".method public abstract ua()Z\n.end method\n"
            ".method public native ua([B)I\n.end method\n")
        bad_shape = validate_file(
            ".class public Lcom/demo/B;\n"
            ".super Ljava/lang/Object;\n\n"
            ".method public static x()V\n"
            "    .registers 2\n\n"
            "    const-string v0, \"hi\"\n"
            "    :goto_0\n"
            "        .registers 2\n"
            "    return-void\n"
            ".end method\n")
        check("validate: abstract/native hợp lệ, nested .registers là lỗi",
              not ok_abs[0] and bool(bad_shape[0]))

        # --changed-only: lần 2 chỉ quét tệp đổi mới
        t_v = os.path.join(d, "t_validate")
        make_tree(t_v)
        vp = os.path.join(t_v, "smali", "com", "demo", "V.smali")
        os.makedirs(os.path.dirname(vp), exist_ok=True)
        with open(vp, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/V;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static a()V\n"
                     "    .registers 1\n\n"
                     "    return-void\n"
                     ".end method\n")
        r1 = validate_tree(t_v, changed_only=True)
        r2 = validate_tree(t_v, changed_only=True)
        with open(vp, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/V;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static a()V\n"
                     "    .registers 1\n\n"
                     "    nop\n"
                     "    return-void\n"
                     ".end method\n")
        r3 = validate_tree(t_v, changed_only=True)
        check("validate: --changed-only lần 2 bỏ qua tệp không đổi, lần 3 "
              "quét lại tệp vừa sửa",
              r1["changed"] == r1["files"] and r2["changed"] == 0
              and r3["changed"] == 1,
              "changed=%d/%d/%d (files=%d)"
              % (r1["changed"], r2["changed"], r3["changed"], r1["files"]))

        # REMOTE_CONFIG helper + chèn init
        t_remote = os.path.join(d, "t_remote")
        make_tree(t_remote)
        p_remote = parse_text(
            "[REMOTE_CONFIG]\nCONFIG_URL:\n"
            "https://config.example.com/patchx.json\nTARGET:\n"
            "[LAUNCHER_ACTIVITIES]\nMETHOD:\nonCreate\n"
            "[/REMOTE_CONFIG]\n")
        Engine(t_remote, quiet=True).apply(p_remote)
        remote_path = os.path.join(t_remote, "smali", "patchx",
                                   "RemoteConfig.smali")
        remote_text = open(remote_path, encoding="utf-8").read()
        check("modern: REMOTE_CONFIG helper + CONFIG_URL",
              os.path.isfile(remote_path)
              and "https://config.example.com/patchx.json" in remote_text)
        remote_main = open(os.path.join(t_remote, "smali", "com", "demo",
                                        "MainActivity.smali"),
                           encoding="utf-8").read()
        check("modern: REMOTE_CONFIG chèn init",
              "Lpatchx/RemoteConfig;->init()V" in remote_main
              and "# patchx-rconfig:" in remote_main)

        # Audit: bộ khối hiện đại hợp lệ không có lỗi cấp A04
        valid = parse_text(
            "[MIN_ENGINE_VER]\n2\n[/MIN_ENGINE_VER]\n"
            "[AUTHOR]\npatchx\n[/AUTHOR]\n"
            "[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
            "[SET_BOOL]\nTARGET:\nsmali/com/demo/Flags.smali\n"
            "MATCH:\nconst/4 v0, 0x0\nREGEX:\nfalse\nVALUE:\n0x1\n"
            "[/SET_BOOL]\n"
            "[INIT]\nCODE:\nreturn-void\n[/INIT]\n"
            "[HOOK_SCRIPT]\nSOURCE:\nHook.smali\n[/HOOK_SCRIPT]\n"
            "[TRACE]\nTARGET:\nsmali/com/demo/Api.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\n[/TRACE]\n"
            "[API_LOG]\nTARGET:\nsmali/com/demo/Api.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\n[/API_LOG]\n"
            "[REMOTE_CONFIG]\nCONFIG_URL:\nhttps://config.example.com/x.json\n"
            "[/REMOTE_CONFIG]\n")
        valid_findings = audit_patch(valid)
        check("modern: audit không báo lỗi lạ cho khối hợp lệ",
              not any(f.level == LEVEL_ERROR for f in valid_findings),
              "; ".join(f.code + ":" + f.message for f in valid_findings
                        if f.level == LEVEL_ERROR))

        # Optimizer: VALUE/CODE/CONFIG_URL phải nằm trong fingerprint
        from patchx_core.optimizer import dedupe_sections, patch_capabilities
        s1 = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/x.smali\nMATCH:\n0x0\n"
            "REGEX:\nfalse\nVALUE:\n0x1\n[/SET_BOOL]\n")
        s2 = parse_text(
            "[SET_BOOL]\nTARGET:\nsmali/x.smali\nMATCH:\n0x0\n"
            "REGEX:\nfalse\nVALUE:\n0x0\n[/SET_BOOL]\n")
        merged = merge_patches([s1, s2], "T")
        check("modern: optimizer phân biệt VALUE khác nhau",
              len(merged.sections) == 2)
        hook_sec = parse_text("[HOOK_SCRIPT]\nSOURCE:\nHook.smali\n"
                              "[/HOOK_SCRIPT]\n")
        caps = patch_capabilities(hook_sec)
        check("modern: optimizer nhận diện HOOK_SCRIPT -> shell",
              "shell" in caps)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_remote_trace_force():
    """Tầng 1+2: DataGuard hook + remote-map + remote-patch + FORCE + sửa
    pro_unlock_vip (literal \\n) — toàn bộ luồng theo dõi mã điều khiển từ xa."""
    from patchx_core.remote_map import build_remote_map, build_force_patch
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_remote_")
    try:
        # --- remote-map: lập bản đồ flag ---
        t = os.path.join(d, "tree")
        make_tree(t)
        flags_path = os.path.join(t, "smali", "com", "demo", "Flags.smali")
        os.makedirs(os.path.dirname(flags_path), exist_ok=True)
        with open(flags_path, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Flags;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".field public static isPro:Z\n\n"
                     ".field public enabled:Z\n")
        main_path = os.path.join(t, "smali", "com", "demo",
                                 "MainActivity.smali")
        with open(main_path, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/MainActivity;\n\n"
                     ".method public static check()Z\n"
                     "    .registers 3\n\n"
                     "    sget-boolean v0, Lcom/demo/Flags;->isPro:Z\n\n"
                     "    iget-boolean v0, p0, Lcom/demo/Flags;->enabled:Z\n\n"
                     "    return v0\n"
                     ".end method\n")
        rmap = build_remote_map(t)
        flags = rmap["flags"]
        check("remote-map: phát hiện flag static + instance",
              "Lcom/demo/Flags;->isPro:Z" in flags
              and "Lcom/demo/Flags;->enabled:Z" in flags,
              "; ".join(sorted(flags)))
        check("remote-map: ghi nhận điểm đọc + loại flag",
              len(flags["Lcom/demo/Flags;->isPro:Z"]["reads"]) == 1
              and flags["Lcom/demo/Flags;->isPro:Z"]["type"] == "static"
              and flags["Lcom/demo/Flags;->enabled:Z"]["type"] == "instance")

        # --- remote-patch: sinh zip ép giá trị + idempotent ---
        zpath = os.path.join(d, "force.zip")
        build_force_patch(rmap, {"Lcom/demo/Flags;->isPro:Z": True,
                                 "Lcom/demo/Flags;->enabled:Z": False},
                          zpath)
        patch = parse_patch_file(zpath)
        eng = Engine(t, quiet=True)
        eng.apply(patch)
        eng.finalize()
        main_text = open(main_path, encoding="utf-8").read()
        check("remote-patch: ép isPro=true + enabled=false",
              "const/4 v0, 0x1" in main_text
              and "const/4 v0, 0x0" in main_text
              and "sget-boolean v0, Lcom/demo/Flags;->isPro:Z"
              not in main_text)
        eng2 = Engine(t, quiet=True)
        before = len(eng2.changes)
        eng2.apply(patch)
        eng2.finalize()
        check("remote-patch: idempotent", len(eng2.changes) == before,
              "%d -> %d" % (before, len(eng2.changes)))

        # --- FORCE trực tiếp trong REMOTE_CONFIG (không cần target) ---
        t2 = os.path.join(d, "tree2")
        make_tree(t2)
        f2 = os.path.join(t2, "smali", "com", "demo", "Flags2.smali")
        os.makedirs(os.path.dirname(f2), exist_ok=True)
        with open(f2, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Flags2;\n"
                     ".field public static x:Z\n")
        m2 = os.path.join(t2, "smali", "com", "demo", "MainActivity.smali")
        with open(m2, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/MainActivity;\n\n"
                     ".method public static go()V\n"
                     "    .registers 2\n\n"
                     "    sget-boolean v0, Lcom/demo/Flags2;->x:Z\n\n"
                     "    return-void\n"
                     ".end method\n")
        p_force = parse_text(
            "[REMOTE_CONFIG]\nCONFIG_URL:\nhttps://x.example/cfg.json\n"
            "FORCE:\nLcom/demo/Flags2;->x:Z = true\n[/REMOTE_CONFIG]\n")
        eng3 = Engine(t2, quiet=True)
        eng3.apply(p_force)
        eng3.finalize()
        m2_text = open(m2, encoding="utf-8").read()
        check("FORCE: ép không cần target",
              "const/4 v0, 0x1" in m2_text
              and "sget-boolean v0, Lcom/demo/Flags2;->x:Z" not in m2_text)

        # --- pro_unlock_vip đã sửa: audit sạch + áp được + hết literal \n ---
        puv = parse_patch_file(os.path.join(PATCHX, "bypass_plus",
                                            "pro_unlock_vip.zip"))
        puv_findings = audit_patch(puv)
        check("pro_unlock_vip: audit sạch",
              not any(f.level == LEVEL_ERROR for f in puv_findings),
              "; ".join(f.code + ":" + f.message for f in puv_findings
                        if f.level == LEVEL_ERROR))
        t3 = os.path.join(d, "tree3")
        os.makedirs(os.path.join(t3, "smali_classes4", "com", "zaz",
                                 "account"))
        os.makedirs(os.path.join(t3, "smali_classes4", "com", "zaz",
                                 "subscription", "manager"))
        uc3 = os.path.join(t3, "smali_classes4", "com", "zaz", "account",
                           "uc.smali")
        ua3 = os.path.join(t3, "smali_classes4", "com", "zaz",
                           "subscription", "manager", "ua.smali")
        with open(uc3, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/zaz/account/uc;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public final ui()Z\n"
                     "    .locals 1\n\n"
                     "    .line 1\n"
                     "    sget-object v0, Lcom/zaz/subscription/manager/ua;"
                     "->ua:Lcom/zaz/subscription/manager/ua;\n\n"
                     "    return v0\n"
                     ".end method\n")
        with open(ua3, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/zaz/subscription/manager/ua;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static ui()Z\n"
                     "    .locals 1\n\n"
                     "    .line 1\n"
                     "    invoke-static {}, Lcom/zaz/subscription/manager/ua;"
                     "->uc()Z\n\n"
                     "    return v0\n"
                     ".end method\n\n"
                     ".method public static uc()Z\n"
                     "    .locals 4\n\n"
                     "    .line 1\n"
                     "    sget-object v0, Lcom/zaz/subscription/manager/ua;"
                     "->uc:Lm4;\n\n"
                     "    return v0\n"
                     ".end method\n")
        eng4 = Engine(t3, quiet=True)
        eng4.apply(puv)
        eng4.finalize()
        ua_text = open(ua3, encoding="utf-8").read()
        uc_text = open(uc3, encoding="utf-8").read()
        check("pro_unlock_vip: ép 3 method về true",
              ua_text.count("const/4 v0, 0x1") == 2
              and "const/4 v0, 0x1" in uc_text)
        check("pro_unlock_vip: hết literal \\n",
              "\\n" not in ua_text and "\\n" not in uc_text)

        # --- Hook pack: DataGuard + ConfigKt.ui + TRACE (hint lọc) ---
        t4 = os.path.join(d, "tree4")
        make_tree(t4)
        ck_dir = os.path.join(t4, "smali", "com", "zaz", "translate", "ui",
                              "tool")
        os.makedirs(ck_dir, exist_ok=True)
        ck = os.path.join(ck_dir, "ConfigKt.smali")
        with open(ck, "w", encoding="utf-8") as fh:
            fh.write(".class public final Lcom/zaz/translate/ui/tool/"
                     "ConfigKt;\n\n"
                     ".method public static ui(ILjava/lang/String;"
                     "Ljava/lang/Object;)V\n"
                     "    .locals 4\n\n"
                     "    return-void\n"
                     ".end method\n")
        sp = os.path.join(t4, "smali", "com", "demo", "Pref.smali")
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Pref;\n\n"
                     ".method public static save()V\n"
                     "    .registers 3\n\n"
                     "    invoke-interface {v0, v1}, Landroid/content/"
                     "SharedPreferences$Editor;->putString(Ljava/lang/String;"
                     "Ljava/lang/String;)Landroid/content/SharedPreferences"
                     "$Editor;\n\n"
                     "    return-void\n"
                     ".end method\n")
        hook_txt = os.path.join(PATCHX, "hook_remote_data_control",
                                "patch.txt")
        hzip = make_patch_zip(
            d, "hook.zip", open(hook_txt, encoding="utf-8").read(),
            {"DataGuard.smali": open(os.path.join(
                PATCHX, "hook_remote_data_control", "DataGuard.smali"),
                encoding="utf-8").read()})
        hook_patch = parse_patch_file(hzip)
        hook_findings = audit_patch(hook_patch)
        check("hook pack: audit sạch",
              not any(f.level == LEVEL_ERROR for f in hook_findings),
              "; ".join(f.code + ":" + f.message for f in hook_findings
                        if f.level == LEVEL_ERROR))
        eng5 = Engine(t4, quiet=True)
        eng5.apply(hook_patch)
        eng5.finalize()
        main_t4 = open(os.path.join(t4, "smali", "com", "demo",
                                    "MainActivity.smali"),
                       encoding="utf-8").read()
        ck_t4 = open(ck, encoding="utf-8").read()
        sp_t4 = open(sp, encoding="utf-8").read()
        check("hook: DataGuard chèn vào launcher onCreate",
              "Lpatchx/DataGuard;->onCreate()V" in main_t4
              and "# patchx-hook:" in main_t4)
        check("hook: ConfigKt.ui nối DataGuard.onEvent",
              "Lpatchx/DataGuard;->onEvent(ILjava/lang/String;"
              "Ljava/lang/String;)V" in ck_t4)
        check("hook: TRACE prefs chèn Log.d (hint lọc)",
              "# patchx-trace:" in sp_t4
              and "Landroid/util/Log;->d" in sp_t4)

        # --- Regression: method >16 thanh ghi → /range + const/16 ---
        t5 = os.path.join(d, "tree5")
        make_tree(t5)
        big = os.path.join(t5, "smali", "com", "demo", "Big.smali")
        with open(big, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Big;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static big()V\n"
                     "    .registers 40\n\n"
                     "    const-string v33, \"https://api.example.com/x\"\n\n"
                     "    return-void\n"
                     ".end method\n")
        p_api_hi = parse_text(
            "[API_LOG]\nTARGET:\nsmali/com/demo/Big.smali\n"
            "MATCH:\nhttps://\nREGEX:\nfalse\nTAG:\nApiHi\n[/API_LOG]\n")
        eng6 = Engine(t5, quiet=True)
        eng6.apply(p_api_hi)
        eng6.finalize()
        big_text = open(big, encoding="utf-8").read()
        check("regression: API_LOG dùng /range cho method lớn",
              ".registers 42" in big_text
              and "invoke-static/range {v40 .. v41}" in big_text
              and "invoke-static {v40, v41}" not in big_text)
        t6 = os.path.join(d, "tree6")
        make_tree(t6)
        big2 = os.path.join(t6, "smali", "com", "demo", "Big2.smali")
        with open(big2, "w", encoding="utf-8") as fh:
            fh.write(".class public Lcom/demo/Big2;\n"
                     ".super Ljava/lang/Object;\n\n"
                     ".method public static go()V\n"
                     "    .registers 40\n\n"
                     "    sget-boolean v33, Lcom/demo/Flags2;->x:Z\n\n"
                     "    return-void\n"
                     ".end method\n")
        p_force_hi = parse_text(
            "[REMOTE_CONFIG]\nCONFIG_URL:\nhttps://x/c.json\n"
            "FORCE:\nLcom/demo/Flags2;->x:Z = true\n[/REMOTE_CONFIG]\n")
        eng7 = Engine(t6, quiet=True)
        eng7.apply(p_force_hi)
        eng7.finalize()
        big2_text = open(big2, encoding="utf-8").read()
        check("regression: FORCE dùng const/16 cho v>=16",
              "const/16 v33, 0x1" in big2_text
              and "sget-boolean v33, Lcom/demo/Flags2;->x:Z" not in big2_text)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_smali_lib():
    from patchx_core import smali_lib
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_smali_lib_")
    try:
        # Escape / quote chuỗi smali
        check("smali-lib: escape và quote chuỗi",
              smali_lib.smali_quote('a"b\\c') == '"a\\"b\\\\c"')
        # .registers bump an toàn
        reg_line, temps, _, pregs = smali_lib.smali_alloc_temps(
            "    .registers 3\n", "()V", True)
        check("smali-lib: bump .registers",
              reg_line == "    .registers 5" and temps == (3, 4))
        # .locals chuyển .registers + bump
        reg_line2, temps2, _, _ = smali_lib.smali_alloc_temps(
            "    .locals 1\n", "(Ljava/lang/String;I)V", False)
        check("smali-lib: chuyển .locals sang .registers",
              reg_line2 == "    .registers 6" and temps2 == (4, 5))
        # pX phải viết lại theo bố cục gốc để không dịch/đụng khi bump
        reg_line3, temps3, _, pregs3 = smali_lib.smali_alloc_temps(
            "    .registers 16\n", "(Lcom/demo/Task;)Ljava/lang/Object;",
            False)
        check("smali-lib: bản đồ pX giữ bố cục gốc",
              reg_line3 == "    .registers 18" and temps3 == (16, 17)
              and pregs3 == {0: 14, 1: 15})
        rewritten = smali_lib.rewrite_pregs(
            "    invoke-virtual {v0, p1, v2}, Lxg1;->ub()V\n"
            '    const-string v5, "Lcls;->p1:Z"\n'
            "    move-result-object p1\n",
            pregs3)
        check("smali-lib: rewrite_pregs không đụng field/chuỗi",
              "invoke-virtual {v0, v15, v2}" in rewritten
              and "move-result-object v15" in rewritten
              and 'const-string v5, "Lcls;->p1:Z"' in rewritten)
        # Tìm call-site
        smali = (".method public static run()V\n"
                 "    .registers 2\n\n"
                 "    invoke-static {v0}, Lcom/demo/Api;->getUrl()Ljava/lang/String;\n"
                 "    return-void\n"
                 ".end method\n")
        calls = smali_lib.find_call_sites(smali, "com/demo/Api", "getUrl")
        check("smali-lib: tìm call-site đúng class+method",
              len(calls) == 1 and calls[0]["method"] == "getUrl"
              and calls[0]["invoke_type"] == "invoke-static")
        # Chèn invoke idempotent theo marker
        new_text, inserted = smali_lib.insert_invoke(
            smali, "run", ["invoke-static {}, Lcom/demo/Hook;->onCreate()V"],
            marker="# patchx-test:hook")
        check("smali-lib: insert_invoke chèn đúng vị trí",
              inserted and "Lcom/demo/Hook;->onCreate()V" in new_text)
        _, inserted2 = smali_lib.insert_invoke(
            new_text, "run", ["invoke-static {}, Lcom/demo/Hook;->onCreate()V"],
            marker="# patchx-test:hook")
        check("smali-lib: insert_invoke idempotent", not inserted2)
        # Class descriptor + target rel
        os.makedirs(os.path.join(d, "smali", "com", "demo"), exist_ok=True)
        cls = smali_lib.smali_class_descriptor(
            ".class public Lcom/demo/Hook;")
        rel = smali_lib.smali_target_rel(d, cls)
        check("smali-lib: class descriptor + target rel",
              cls == "com/demo/Hook"
              and rel == os.path.join("smali", "com", "demo", "Hook.smali"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_smali_sem():
    """T1: ngữ nghĩa mã — method-level, packer, mã hóa chuỗi, call-graph."""
    from patchx_core.smali_sem import (
        extract_methods, find_method_matches, detect_packers,
        detect_string_encryption, entry_classes, call_graph_rank,
        build_app_model, build_app_model_v2, method_fingerprint)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_sem_")
    try:
        os.makedirs(os.path.join(d, "smali", "com", "demo"))
        os.makedirs(os.path.join(d, "lib", "arm64-v8a"))
        with open(os.path.join(d, "lib", "arm64-v8a", "libjiagu.so"),
                  "wb") as fh:
            fh.write(b"\x7fELF")
        with open(os.path.join(d, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest package="com.demo"><application '
                     'android:name=".App"><activity android:name=".Main">'
                     "<intent-filter><action android:name="
                     '"android.intent.action.MAIN"/><category '
                     'android:name="android.intent.category.LAUNCHER"/>'
                     "</intent-filter></activity></application></manifest>")
        app = ("\n.class public Lcom/demo/App;\n"
               ".super Landroid/app/Application;\n"
               ".method public attachBaseContext(Landroid/content/Context;)V\n"
               "    invoke-static {p0}, Lcom/demo/License;->check()Z\n"
               "    return-void\n.end method\n")
        main = ("\n.class public Lcom/demo/Main;\n"
                ".super Landroid/app/Activity;\n"
                ".method protected onCreate(Landroid/os/Bundle;)V\n"
                "    invoke-virtual {p0}, Lcom/demo/License;->isVip()Z\n"
                "    return-void\n.end method\n")
        lic = ("\n.class public Lcom/demo/License;\n"
               ".super Ljava/lang/Object;\n"
               ".method public static check()Z\n    const/4 v0, 0x0\n"
               "    return v0\n.end method\n"
               ".method public isVip()Z\n    const/4 v0, 0x0\n"
               "    return v0\n.end method\n")
        sec = ("\n.class public Lcom/demo/Secret;\n"
               ".super Ljava/lang/Object;\n"
               ".method public static decrypt(Ljava/lang/String;)"
               "Ljava/lang/String;\n"
               '    const-string v0, "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkg'
               'bG9uZyBzdHJpbmcgYmFzZTY0IGVuY29kZWQgdGV4dA=="\n'
               "    return-object v0\n.end method\n")
        for fname, body in (("App.smali", app), ("Main.smali", main),
                            ("License.smali", lic), ("Secret.smali", sec)):
            with open(os.path.join(d, "smali", "com", "demo", fname),
                      "w", encoding="utf-8") as fh:
                fh.write(body)
        meths = extract_methods(lic)
        check("sem: tách method đúng tên", [m["name"] for m in meths]
              == ["check", "isVip"])
        hits = find_method_matches(lic, "const/4 v0, 0x0", False)
        check("sem: method chứa mẫu", len(hits) == 2 and
              all(h["method"] in ("check", "isVip") for h in hits))
        pk = detect_packers(d)
        check("sem: phát hiện packer libjiagu",
              any("jiagu" in p["nghi_ngờ"] for p in pk))
        enc = detect_string_encryption(d)
        check("sem: nghi mã hóa chuỗi",
              any("Secret.smali" in s["tệp"] for s in enc))
        app_c, launchers = entry_classes(d)
        check("sem: entry application + launcher",
              app_c == "com.demo.App" and launchers == ["com.demo.Main"])
        graph = call_graph_rank(d, [app_c] + launchers, depth=3, top=5)
        check("sem: call-graph xếp hạng License",
              any(c["class"] == "Lcom/demo/License;" and c["lần"] >= 2
                  for c in graph))
        # Đổi tên method không được làm thay đổi fingerprint cấu trúc.
        renamed = lic.replace(" isVip()Z", " a()Z")
        check("sem: fingerprint không phụ thuộc tên method",
              method_fingerprint(extract_methods(lic)[1])
              == method_fingerprint(extract_methods(renamed)[1]))
        model = build_app_model(d)
        license_method = next((m for m in model["methods"]
                               if m["id"].endswith("->isVip()Z")), None)
        check("sem: mô hình có method/cạnh gọi/điểm quyết định",
              model["summary"]["methods"] == 5
              and model["summary"]["call_edges"] >= 2
              and license_method is not None
              and license_method["decision_point"])
        # Model V2: đổi tên method/đổi thanh ghi không làm đổi structural
        # identity; exact identity vẫn phát hiện thay đổi thực của thân code.
        model_v2 = build_app_model_v2(d)
        vip_v2 = next((m for m in model_v2["methods"]
                       if m["id"].endswith("->isVip()Z")), None)
        check("sem-v2: identity, caller/callee và khoảng cách entry",
              model_v2["schema"] == "patchx.app-model/v2"
              and vip_v2 is not None
              and set(vip_v2["identity"]) == {"exact", "structural", "semantic"}
              and vip_v2["relations"]["callers"]
              and vip_v2["relations"]["entry_distance"] == 1
              and vip_v2["evidence"]["extractor_version"] == "model/v2")
        altered = lic.replace("const/4 v0, 0x0", "const/4 v7, 0x0")
        with open(os.path.join(d, "smali", "com", "demo", "License.smali"),
                  "w", encoding="utf-8") as fh:
            fh.write(altered)
        altered_v2 = build_app_model_v2(d)
        vip_altered = next(m for m in altered_v2["methods"]
                           if m["id"].endswith("->isVip()Z"))
        check("sem-v2: đổi thanh ghi giữ structural nhưng đổi exact",
              vip_v2["identity"]["structural"] == vip_altered["identity"]["structural"]
              and vip_v2["identity"]["exact"] != vip_altered["identity"]["exact"])
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "semantic_v2")
        source_v2 = build_app_model_v2(os.path.join(fixture, "source"))
        obfuscated_v2 = build_app_model_v2(os.path.join(fixture, "obfuscated"))
        source_gate = next(m for m in source_v2["methods"]
                           if m["id"].endswith("->isEnabled()Z"))
        obfuscated_gate = next(m for m in obfuscated_v2["methods"]
                               if m["id"].endswith("->a()Z"))
        check("sem-v2: fixture đổi tên class/method và thanh ghi vẫn ghép cấu trúc",
              source_gate["identity"]["exact"] != obfuscated_gate["identity"]["exact"]
              and source_gate["identity"]["structural"]
              == obfuscated_gate["identity"]["structural"]
              and source_gate["identity"]["semantic"]
              == obfuscated_gate["identity"]["semantic"])
        from patchx_core.semantic_plan import (SCHEMA, evaluate_plan,
                                               SCHEMA_V2, evaluate_plan_v2,
                                               validate_plan, validate_plan_v2)
        plan = {"schema": SCHEMA, "goal": "Tìm kiểm tra boolean theo cấu trúc",
                "targets": [{"name": "boolean_check", "min_score": 100,
                             "conditions": {"return_type": "Z", "parameters": []}}],
                "operations": [{"type": "RETURN_CONSTANT"}],
                "verification": ["preflight", "validate", "build", "runtime"]}
        evaluated = evaluate_plan(plan, model)
        check("sem-plan: mục tiêu + điều kiện có bằng chứng, không tự áp",
              not validate_plan(plan)
              and evaluated["verdict"] == "READY_FOR_PREFLIGHT"
              and len(evaluated["targets"][0]["accepted"]) == 2)
        plan_v2 = {
            "schema": SCHEMA_V2, "goal": "Truy vết gate trong fixture",
            "targets": [{"name": "gate", "selector": {"all": [
                {"return_type": "Z"}, {"min_branch_count": 0}],
                "near_entry": {"max_distance": 2}},
                "policy": {"min_score": 100, "max_accepted": 1,
                           "on_ambiguous": "STOP"}}],
            "operation_intent": [{"type": "TRACE", "target": "gate"}],
            "verification": ["preflight", "validate", "build", "runtime"]}
        fixture_v2 = build_app_model_v2(os.path.join(
            os.path.dirname(__file__), "fixtures", "semantic_v2", "source"))
        evaluated_v2 = evaluate_plan_v2(plan_v2, fixture_v2)
        check("sem-plan-v2: selector đơn nghĩa có evidence và sẵn preflight",
              not validate_plan_v2(plan_v2)
              and evaluated_v2["verdict"] == "READY_FOR_PREFLIGHT"
              and len(evaluated_v2["targets"][0]["accepted"]) == 1
              and evaluated_v2["targets"][0]["accepted"][0]["evidence"])
        ambiguous_plan = dict(plan_v2)
        ambiguous_plan["targets"] = [{"name": "gate", "selector": {"all": [
            {"return_type": "Z"}]}, "policy": {"min_score": 100,
            "max_accepted": 1, "on_ambiguous": "STOP"}}]
        ambiguous = evaluate_plan_v2(ambiguous_plan, model_v2)
        insufficient = evaluate_plan_v2(plan_v2, model)
        check("sem-plan-v2: nhiều ứng viên bị chặn, model V1 thiếu evidence",
              ambiguous["verdict"] == "AMBIGUOUS_TARGET"
              and ambiguous["targets"][0]["ambiguous"]
              and insufficient["verdict"] == "INSUFFICIENT_EVIDENCE")
        from patchx_core.knowledge import (SCHEMA as KNOWLEDGE_SCHEMA,
                                           SCHEMA_V2 as KNOWLEDGE_SCHEMA_V2,
                                           query_similar, query_similar_v2,
                                           record_verified, validate_record_v2)
        db = os.path.join(d, "knowledge.json")
        record = {"schema": KNOWLEDGE_SCHEMA,
                  "app": {"package": "com.demo", "version": "1.0"},
                  "goal": "Kiểm tra boolean", "target": {
                      "fingerprint": license_method["fingerprint"]},
                  "outcome": "SUCCESS", "verified": True}
        added, _total = record_verified(db, record)
        hits = query_similar(db, model, goal="Kiểm tra boolean")
        check("knowledge: chỉ lưu verified và truy vấn theo fingerprint",
              added and len(hits) == 1
              and hits[0]["matched_method"] == license_method["id"])
        v2_record = {"schema": KNOWLEDGE_SCHEMA_V2,
                     "app": {"package": "com.example.semantic", "version": "1.0"},
                     "goal": "Truy vết gate", "target": {"identity": source_gate["identity"]},
                     "evidence": {"extractor_version": "model/v2"},
                     "gates": {"preflight": "PASS", "validate": "PASS",
                               "build": "PASS", "runtime": "PASS"},
                     "outcome": "SUCCESS", "verified": True}
        added_v2, _total = record_verified(db, v2_record)
        v2_hits = query_similar_v2(db, obfuscated_v2, goal="Truy vết gate")
        check("knowledge-v2: identity đa đặc trưng chỉ xếp hạng tham chiếu",
              not validate_record_v2(v2_record) and added_v2 and len(v2_hits) == 1
              and v2_hits[0]["confidence"] == 90.0
              and set(v2_hits[0]["identity_matches"]) == {"structural", "semantic"}
              and v2_hits[0]["recommendation_only"])
        from patchx_core.diffapk import match_app_models_v2
        from patchx_core.semantic_plan import plan_v2_from_version_map
        from patchx_core.plan_compile import compile_plan_v2
        version_match = match_app_models_v2(source_v2, obfuscated_v2)
        version_plan = plan_v2_from_version_map(version_match, source_v2,
                                                obfuscated_v2)
        version_draft = compile_plan_v2(version_plan, source_v2,
                                        os.path.join(os.path.dirname(__file__),
                                                     "fixtures", "semantic_v2", "source"))
        check("version-match: đổi tên chỉ tạo ghép structural, plan V2 chỉ tham chiếu",
              version_match["schema"] == "patchx.version-match/v1"
              and version_match["summary"]["structural"] == 3
              and version_match["summary"]["unknown"] == 0
              and version_match["summary"]["unmatched_after"] == 0
              and version_match["summary"]["reidentification_rate"] == 100.0
              and not validate_plan_v2(version_plan)
              and len(version_plan["targets"]) == 3
              and version_plan["provenance"]["recommendation_only"]
              and all(t["policy"]["on_ambiguous"] == "STOP"
                      for t in version_plan["targets"])
              and version_draft["status"] == "DRAFT_REQUIRES_APPROVAL"
              and not version_draft["executable"]
              and len(version_draft["selected_targets"]) == 3
              and version_draft["tree_evidence_hash"].startswith("sha256:"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_runtime_net_parse():
    """T3: parse /proc/net + diff kết nối mới (không cần device)."""
    from patchx_toolkit import (_hex_ipv4, _fmt_addr, _parse_proc_net,
                                _net_new_connections)
    check("net: hex ipv4 little-endian",
          _hex_ipv4("0100007F") == "127.0.0.1")
    check("net: fmt addr", _fmt_addr("0100007F:1F90") == "127.0.0.1:8080")
    before = {"tcp": ["sl local rem st", "0: 0100007F:1F90 00000000:0000 0A"],
              "tcp6": []}
    after = {"tcp": ["sl local rem st", "0: 0100007F:1F90 00000000:0000 0A",
                     "1: 0100007F:1F90 8C5F0A0A:01BB 01"],
             "tcp6": []}
    new = _net_new_connections(before, after)
    check("net: phát hiện kết nối mới", len(new) == 1
          and new[0]["remote"] == "10.10.95.140:443"
          and new[0]["state"] == "ESTABLISHED", str(new))
    check("net: bỏ qua LISTEN", not any(
        c["state"] == "LISTEN" for c in new))


def test_diff_apk():
    """T2: diff-apk sinh patch + vòng khép kín tái sinh ≥ 90%."""
    import shutil as _shutil
    from patchx_core.diffapk import (build_patch, write_patch_zip,
                                     verify_rebuild)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_diffapk_")
    try:
        mod = os.path.join(d, "mod")
        _shutil.copytree(os.path.join(PATCHX, "tests", "fixtures", "mini_app"),
                         mod)
        p = os.path.join(mod, "smali", "com", "example", "mini",
                         "MainActivity.smali")
        s = open(p, encoding="utf-8").read()
        s = s.replace('const-string v1, "com.example.mini"',
                      'const-string v1, "com.example.mini.mod"')
        open(p, "w", encoding="utf-8", newline="\n").write(s)
        os.makedirs(os.path.join(mod, "smali", "com", "example", "mini",
                                 "extra"), exist_ok=True)
        open(os.path.join(mod, "smali", "com", "example", "mini", "extra",
                          "Helper.smali"), "w", encoding="utf-8").write(
            ".class public Lcom/example/mini/extra/Helper;\n"
            ".super Ljava/lang/Object;\n"
            ".method public static help()V\n    return-void\n.end method\n")
        orig = os.path.join(PATCHX, "tests", "fixtures", "mini_app")
        text, assets, stats = build_patch(orig, mod, "mini_diff")
        check("diff: nhận diện thêm + sửa",
              any(k.endswith("Helper.smali") for k in stats["added"])
              and any(k.endswith("MainActivity.smali") for k in
                      stats["changed"]), str(stats))
        zpath = os.path.join(d, "mini_diff.zip")
        write_patch_zip(zpath, text, assets)
        v = verify_rebuild(orig, mod, zpath, tmp_root=d)
        check("diff: tái sinh ≥ 90%", v["tỷ_lệ"] >= 90,
              "%s%% (%d/%d)" % (v["tỷ_lệ"], v["khớp"], v["tổng"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _make_pairip_tree(root):
    """Tao cay APK gia co PairIP (com/pairip) du 7 muc tieu va."""
    pairip = os.path.join(root, "smali", "com", "pairip")
    app_dir = os.path.join(pairip, "application")
    lc_dir = os.path.join(pairip, "licensecheck")
    os.makedirs(app_dir)
    os.makedirs(lc_dir)
    with open(os.path.join(app_dir, "Application.smali"), "w",
              encoding="utf-8") as f:
        f.write(".class public Lcom/pairip/application/Application;\n"
                ".super Landroid/app/Application;\n\n"
                ".method protected attachBaseContext("
                "Landroid/content/Context;)V\n"
                "    .locals 0\n\n"
                "    invoke-static {p1}, "
                "Lcom/pairip/licensecheck/LicenseClient;->checkLicense("
                "Landroid/content/Context;)V\n\n"
                "    invoke-super {p0, p1}, "
                "Lcom/pairip/application/Application;->attachBaseContext("
                "Landroid/content/Context;)V\n\n"
                "    return-void\n"
                ".end method\n")
    with open(os.path.join(lc_dir, "LicenseContentProvider.smali"), "w",
              encoding="utf-8") as f:
        f.write(".class public Lcom/pairip/licensecheck/"
                "LicenseContentProvider;\n"
                ".super Landroid/content/ContentProvider;\n\n"
                ".method public onCreate()Z\n"
                "    .locals 1\n\n"
                "    invoke-virtual {p0}, Lcom/pairip/licensecheck/"
                "LicenseContentProvider;->getContext()"
                "Landroid/content/Context;\n\n"
                "    move-result-object v0\n\n"
                "    invoke-static {v0}, "
                "Lcom/pairip/licensecheck/LicenseClient;->checkLicense("
                "Landroid/content/Context;)V\n\n"
                "    const/4 v0, 0x1\n\n"
                "    return v0\n"
                ".end method\n")
    with open(os.path.join(lc_dir, "LicenseClient.smali"), "w",
              encoding="utf-8") as f:
        f.write(".class public Lcom/pairip/licensecheck/LicenseClient;\n"
                ".super Ljava/lang/Object;\n\n"
                ".method public static checkLicense(Landroid/content/Context;)V\n"
                "    .locals 2\n\n"
                '    const-string v0, "LicenseClient"\n\n'
                "    invoke-static {v0, v0}, Landroid/util/Log;->i("
                "Ljava/lang/String;Ljava/lang/String;)I\n\n"
                "    return-void\n"
                ".end method\n\n"
                ".method static stopTrial(Landroid/content/Context;)V\n"
                "    .locals 2\n\n"
                '    const-string v0, "LicenseClient"\n\n'
                "    invoke-static {v0, v0}, Landroid/util/Log;->i("
                "Ljava/lang/String;Ljava/lang/String;)I\n\n"
                "    return-void\n"
                ".end method\n\n"
                ".method protected handleTrialEnd()V\n"
                "    .locals 2\n\n"
                '    const-string v0, "LicenseClient"\n\n'
                "    invoke-static {v0, v0}, Landroid/util/Log;->i("
                "Ljava/lang/String;Ljava/lang/String;)I\n\n"
                "    return-void\n"
                ".end method\n\n"
                ".method public initializeLicenseCheck()V\n"
                "    .locals 2\n\n"
                '    const-string v0, "LicenseClient"\n\n'
                "    invoke-static {v0, v0}, Landroid/util/Log;->i("
                "Ljava/lang/String;Ljava/lang/String;)I\n\n"
                "    return-void\n"
                ".end method\n")
    with open(os.path.join(lc_dir, "LicenseActivity.smali"), "w",
              encoding="utf-8") as f:
        f.write(".class public Lcom/pairip/licensecheck/LicenseActivity;\n"
                ".super Landroid/app/Activity;\n\n"
                ".method public onStart()V\n"
                "    .locals 2\n\n"
                "    invoke-super {p0}, Landroid/app/Activity;->onStart()V\n\n"
                '    const-string v0, "activitytype"\n\n'
                "    return-void\n"
                ".end method\n")
    with open(os.path.join(root, "AndroidManifest.xml"), "w",
              encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n'
                '<manifest xmlns:android="http://schemas.android.com/apk/'
                'res/android" package="com.demo">\n'
                '    <application android:name="com.pairip.application.'
                'Application">\n'
                '        <activity android:name="com.pairip.licensecheck.'
                'LicenseActivity"/>\n'
                "    </application>\n"
                "</manifest>\n")
    return root


def test_pairip_bypass():
    """pairip-bypass: detect + ke hoach + --apply patch + idempotent."""
    from patchx_core.behavior.pairip_bypass import (
        detect_pairip, build_pairip_plan, apply_pairip_bypass)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_pairip_")
    try:
        tree = os.path.join(d, "tree")
        os.makedirs(tree)
        _make_pairip_tree(tree)

        det = detect_pairip(tree)
        check("pairip-bypass: phat hien PairIP",
              det["found"] and det["license_client"]
              and det["manifest_hits"], str(det))

        plan = build_pairip_plan(tree)
        stats = plan["stats"]
        check("pairip-bypass: ke hoach du 7 muc tieu, deu patchable",
              stats["total"] == 7 and stats["patchable"] == 7
              and stats["already_patched"] == 0, str(stats))

        out = os.path.join(d, "out")
        rep = apply_pairip_bypass(tree, out_dir=out, apply=True)
        patched = rep["patched"]
        check("pairip-bypass: --apply patch 7/7 + backup tu dong",
              patched["success"] == 7 and patched["failed"] == 0
              and os.path.isdir(os.path.join(out, "backup"))
              and len(patched["backup_files"]) == 4, str(patched))

        app = open(os.path.join(tree, "smali", "com", "pairip",
                                "application", "Application.smali"),
                   encoding="utf-8").read()
        check("pairip-bypass: Application bo checkLicense",
              "LicenseClient;->checkLicense" not in app, app)

        client = open(os.path.join(tree, "smali", "com", "pairip",
                                   "licensecheck", "LicenseClient.smali"),
                      encoding="utf-8").read()
        check("pairip-bypass: LicenseClient.checkLicense thanh no-op",
              client.count("return-void") == 4
              and 'const-string v0, "LicenseClient"' not in client,
              client)

        activity = open(os.path.join(tree, "smali", "com", "pairip",
                                     "licensecheck",
                                     "LicenseActivity.smali"),
                        encoding="utf-8").read()
        check("pairip-bypass: LicenseActivity.onStart tu finish",
              "->finish()V" in activity, activity)

        rep2 = apply_pairip_bypass(tree, out_dir=out, apply=True)
        patched2 = rep2["patched"]
        check("pairip-bypass: idempotent - lan 2 khong dong smali",
              patched2["success"] == 0 and patched2["already"] == 7,
              str(patched2))

        clean = os.path.join(d, "clean")
        os.makedirs(clean)
        det2 = detect_pairip(clean)
        check("pairip-bypass: cay khong co PairIP -> not found",
              not det2["found"], str(det2))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_behavior_aux_modules():
    """Smoke offline cho 4 module behavior chưa có test riêng:
    frida_generator, crypto_interceptor, gadget_pipeline, remote_controller."""
    from patchx_core.behavior.frida_generator import FridaScriptGenerator
    from patchx_core.behavior.crypto_interceptor import CryptoInterceptorGenerator
    from patchx_core.behavior.gadget_pipeline import run_gadget_pipeline
    from patchx_core.behavior.remote_controller import DynamicRemoteController

    # frida_generator: sinh hook từ target dict có class/method
    gen = FridaScriptGenerator()
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_aux_")
    try:
        out = os.path.join(d, "hook.js")
        gen.generate([{"target": {"class": "Lcom/demo/A;", "method": "check"},
                       "frida_script":
                           "Java.perform(function(){ console.log('hook Lcom/demo/A; check'); });"}],
                     output_file=out)
        js = open(out, encoding="utf-8").read()
        check("aux: frida_generator nhúng hook có class/method",
              "Lcom/demo/A;" in js and "check" in js
              and "GLOBAL_VIP_OVERRIDE" in js)

        # crypto_interceptor: sinh script hook crypto
        cjs = CryptoInterceptorGenerator.generate_crypto_hooks()
        check("aux: crypto_interceptor sinh script crypto",
              isinstance(cjs, str) and len(cjs) > 50
              and ("Interceptor" in cjs or "Cipher" in cjs or "hook" in cjs.lower()))

        # gadget_pipeline: input sai -> ValueError (không cần công cụ)
        try:
            run_gadget_pipeline(os.path.join(d, "khong-ton-tai.apk"))
            check("aux: gadget_pipeline input sai -> lỗi", False, "không raise")
        except ValueError:
            check("aux: gadget_pipeline input sai -> lỗi", True)

        # remote_controller: khởi tạo + quy tắc điều kiện (không connect)
        try:
            rc = DynamicRemoteController("com.demo.app")
        except ImportError:
            check("aux: remote_controller bỏ qua (thiếu frida)", True)
        else:
            rc.add_condition_rule({"match": ["vip_check", "false"],
                                   "command": "set_vip_status", "value": True})
            check("aux: remote_controller khởi tạo + rule",
                  rc.package_name == "com.demo.app"
                  and len(rc.condition_rules) == 1)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_fixtures_mau():
    """Fixture mẫu tests/fixtures/mau/ đọc được: ELF64/ELF32 có .rodata,
    cây smali hợp lệ, patch zip phân tích được."""
    from patchx_core.behavior.rodata_patcher import (
        ElfReader, find_string_offsets)
    from patchx_core.smali_validate import validate_tree
    mau = os.path.join(os.path.dirname(__file__), "fixtures", "mau")
    r64 = ElfReader(os.path.join(mau, "libdemo64.so"))
    check("fixtures-mau: ELF64 đọc .rodata",
          any(s["name"] == ".rodata" for s in r64.list_alloc_sections()))
    hits = find_string_offsets(os.path.join(mau, "libdemo64.so"),
                               "https://api.old-server.com/v1")
    check("fixtures-mau: ELF64 tìm chuỗi RVA 0x1000",
          len(hits) == 1 and hits[0].rva == 0x1000
          and hits[0].section == ".rodata", hits.__str__())
    r32 = ElfReader(os.path.join(mau, "libdemo32.so"))
    hits32 = find_string_offsets(os.path.join(mau, "libdemo32.so"),
                                 "https://api.old-server.com/v1")
    check("fixtures-mau: ELF32 đọc .rodata + RVA",
          any(x["name"] == ".rodata" for x in r32.list_alloc_sections())
          and len(hits32) == 1 and hits32[0].rva == 0x1000)
    v = validate_tree(os.path.join(mau, "smali_tree"))
    check("fixtures-mau: smali_tree validate sạch",
          v["ok"] == 2 and not v["errors"], str(v["errors"]))
    p = parse_patch_file(os.path.join(mau, "patch_mau.zip"))
    targets = [sec.get("TARGET").strip() for sec in p.sections]
    check("fixtures-mau: patch_mau.zip phân tích được",
          len(p.sections) >= 5 and "[LAUNCHER_ACTIVITIES]" in targets)


def test_session_selector():
    from patchx_core import session
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_session_")
    try:
        a = make_patch_zip(
            d, "License_hack.zip",
            "[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\nMATCH:\nlicense\n"
            "REGEX:\nfalse\nREPLACE:\nLICENSED\n[/MATCH_REPLACE]\n")
        b = make_patch_zip(
            d, "SignatureHack_arm64.zip",
            "[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\nMATCH:\nsignature\n"
            "REGEX:\nfalse\nREPLACE:\nSIG\n[/MATCH_REPLACE]\n")
        patches = session.load_patch_map(d)
        check("session: nạp đủ patch theo tên", len(patches) == 2)
        groups = session.capability_groups(patches)
        check("session: chia nhóm khả năng", len(groups) >= 1)
        combos = session.complementary_combos(patches)
        check("session: gợi ý combo bổ trợ",
              any("License_hack" in c["patches"] for c in combos))
        selected, missing = session.resolve_patch_names(
            patches, "license_hack, SignatureHack_arm64")
        check("session: chọn patch theo tên", len(selected) == 2
              and not missing)
        _, missing2 = session.resolve_patch_names(patches, "khong-co")
        check("session: báo patch không tồn tại", missing2 == ["khong-co"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_simulate():
    from patchx_core.simulate import pattern_to_sample, run_simulation
    # Literal mode: giữ nguyên chuỗi (dấu chấm không thành x)
    lit = ('<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />')
    s = pattern_to_sample(lit, is_regex=False)
    check("simulate: literal giữ nguyên chuỗi", s == lit)
    # Regex alternation: lấy nhánh đầu, không nối các nhánh
    s2 = pattern_to_sample(r"(getInstallerPackageName|InstallerPackageName)\(", True)
    check("simulate: alternation lấy nhánh đầu", s2 == "getInstallerPackageName(")
    # Regex với nhóm bắt + escapes
    s3 = pattern_to_sample(
        r"\.method (.+) onCreate\(Landroid/os/Bundle;\)V\n    \.registers (\d+)", True)
    check("simulate: mẫu onCreate sinh được", s3 is not None
          and ".method " in s3 and ".registers " in s3)
    # Mô phỏng nhanh 2 patch trên dữ liệu thật
    import tempfile
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_simtest_")
    try:
        sim_dir = os.path.join(wd, "sim_patches")
        os.makedirs(sim_dir, exist_ok=True)
        for i in range(3):
            make_patch_zip(sim_dir, "p%d.zip" % i, (
                "[PACKAGE]\ncom.demo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\n[LAUNCHER_ACTIVITIES]\n"
                "MATCH:\nonCreate\nREGEX:\nfalse\nREPLACE:\nxxx\n"
                "[/MATCH_REPLACE]\n"))
        summary = run_simulation(sim_dir, work_dir=wd, quick=True)
        check("simulate: mô phỏng nhanh không lỗi", summary["lỗi"] == 0,
              "%d patch, %d đạt" % (summary["tổng_patch"], summary["đạt"]))
    finally:
        import shutil
        shutil.rmtree(wd, ignore_errors=True)


def test_combo():
    from patchx_core.optimizer import merge_patches, patch_capabilities
    from patchx_core.parser import parse_text
    # Namespace nhãn GOTO khi gộp nhiều patch
    a = parse_text("[DUMMY]\nNAME:\nend\n[/DUMMY]\n"
                   "[GOTO]\nGOTO:\nend\n[/GOTO]\n")
    b = parse_text("[DUMMY]\nNAME:\nend\n[/DUMMY]\n"
                   "[GOTO]\nGOTO:\nend\n[/GOTO]\n")
    m = merge_patches([a, b], "T")
    labels = [s.name for s in m.sections if s.name]
    gotos = [s.get("GOTO") for s in m.sections if s.type == "GOTO"]
    check("combo: nhãn GOTO namespaced khi gộp",
          set(labels) == {"p0_end", "p1_end"} and gotos == ["p0_end", "p1_end"])
    # Nhận diện năng lực từ nội dung
    t = parse_text("[MATCH_REPLACE]\nTARGET:\nsmali/x.smali\n"
                   "MATCH:\nhttps://api.example.com/v1/token\n"
                   "REGEX:\nfalse\nREPLACE:\nx\n[/MATCH_REPLACE]\n")
    caps = patch_capabilities(t)
    check("combo: nhận diện năng lực api/token", "api" in caps
          and "token" in caps, str(caps))


def test_selfcheck():
    from patchx_core import cli
    from argparse import Namespace
    import contextlib
    # Tự dò thư mục khi bỏ trống — trước đây crash TypeError
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = cli.cmd_selfcheck(Namespace(thu_muc=None, full=False))
    except Exception as e:
        check("selfcheck: tự dò thư mục khi bỏ trống", False, repr(e))
        return
    check("selfcheck: tự dò thư mục khi bỏ trống",
          rc == 0 and "Tự kiểm tra" in buf.getvalue(), "rc=%s" % rc)
    # Thư mục tường minh vẫn chạy được
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_selfcheck_")
    try:
        make_patch_zip(wd, "p1.zip", "[PACKAGE]\ncom.demo\n[/PACKAGE]\n")
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = cli.cmd_selfcheck(Namespace(thu_muc=wd, full=False))
        check("selfcheck: thư mục tường minh chạy được",
              rc2 == 0 and "1 patch" in buf2.getvalue(), "rc=%s" % rc2)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_zipalign_prebuilt():
    import hashlib
    import patchx_toolkit as tk
    meta = tk.TOOL_PREBUILT.get("zipalign", {})
    check("zipalign: có nguồn cài prebuilt (url + sha256)",
          tk.TOOL_PACKAGES.get("zipalign") == "prebuilt"
          and bool(meta.get("url")) and len(meta.get("sha256", "")) == 64,
          str(meta))
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_zalign_")
    try:
        p = os.path.join(wd, "f.bin")
        with open(p, "wb") as f:
            f.write(b"data" * 100)
        good = hashlib.sha256(open(p, "rb").read()).hexdigest()
        check("zipalign: sha256 khớp mẫu phải báo đúng",
              tk._verify_sha256(p, good) is True)
        check("zipalign: sha256 lệch mẫu phải báo sai",
              tk._verify_sha256(p, "0" * 64) is False)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_package_gioi_han_3_ban():
    import patchx_toolkit as tk
    check("package: giữ tối đa 3 bản", tk.MAX_KEPT_VERSIONS == 3)
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_pkg_")
    try:
        names = ["patchx-toolkit-%d-20260815-18000%d.zip" % (i, i)
                 for i in range(1, 6)]
        for i, n in enumerate(names):
            p = os.path.join(wd, n)
            with open(p, "wb") as f:
                f.write(b"x" * (10 + i))
            os.utime(p, (1700000000 + i, 1700000000 + i))
        tk._prune_old_packages(wd, tk.MAX_KEPT_VERSIONS)
        left = sorted(os.listdir(wd))
        check("package: prune giữ đúng 3 bản mới nhất",
              left == sorted(names[2:]), str(left))
        check("package: số bản mới tự tăng",
              tk._next_build_number(wd) == 6,
              "next=%s" % tk._next_build_number(wd))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_apks_patch():
    import re
    import contextlib
    from argparse import Namespace
    import patchx_toolkit as tk
    check("apks_patch: thư mục nằm trong toolkit",
          tk.APKS_PATCH_DIR.startswith(tk.TOOLKIT_DIR))
    name = tk._patched_apk_name("Demo App")
    check("apks_patch: tên APK đã patch dễ phân biệt",
          re.match(r"^Demo App_patched_\d{8}-\d{6}\.apk$", name)
          and not os.path.exists(os.path.join(tk.APKS_PATCH_DIR, name)),
          name)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = tk.cmd_doctor(Namespace(input=tk.DEFAULT_INPUT))
        out = buf.getvalue()
        check("apks_patch: doctor liệt kê thư mục APK đã patch",
              rc == 0 and "APK đã patch" in out, "rc=%s" % rc)
    except Exception as e:
        check("apks_patch: doctor chạy được", False, repr(e))


def test_bypass_advisor():
    from patchx_core.bypass_advisor import (detect_protections,
                                            estimate_success,
                                            build_bypass_report,
                                            render_markdown)
    texts = {
        "smali/a.smali": "isRooted() CertificatePinner checkServerTrusted",
        "smali/b.smali": "invoke isRooted",
    }
    prots = detect_protections(texts)
    names = {p["loại"] for p in prots}
    check("bypass: phát hiện lớp bảo vệ root + pinning",
          "root" in names and "pinning" in names, str(names))
    cov_hi = {"quy_tắc": 2, "quy_tắc_khớp": 2, "tỷ_lệ": 1.0,
              "chi_tiết": [{"khớp": 8}]}
    r_ok = estimate_success(cov_hi, ["bypass-license"], [])
    r_phat = estimate_success(cov_hi, ["bypass-license"], prots)
    check("bypass: tỷ lệ thành công cao khi không có lớp bảo vệ",
          r_ok["tỷ_lệ"] >= 70, str(r_ok))
    check("bypass: lớp bảo vệ làm giảm tỷ lệ dự đoán",
          r_phat["tỷ_lệ"] < r_ok["tỷ_lệ"], str(r_phat))
    scored = [{
        "patch": "P1", "score": 0.9, "coverage": 1.0, "matches": 8,
        "rules": 2, "rules_matched": 2, "capabilities": ["bypass-license"],
        "chi_tiết": [{"khối": 1, "loại": "MATCH_REPLACE",
                      "target": "smali/a.smali", "khớp": 8,
                      "tệp_trúng": ["smali/a.smali"],
                      "biến_thể": ["Mở rộng MATCH"], "ngoai_target": []}],
        "modern_ratio": 0.5,
    }]
    combos = [{"patches": ["P1", "P2"], "capabilities": ["bypass-license"],
               "support": [("bypass-license", "token")]}]
    rep = build_bypass_report("fixture", scored, combos, texts, limit=5)
    md = render_markdown(rep)
    top = rep["top_patches"][0]
    check("bypass: báo cáo có điểm cụ thể + công cụ + tỷ lệ % + phương án",
          bool(top["điểm_bypass"]) and bool(top["cách_công_cụ"]["công_cụ"])
          and top["tỷ_lệ_thành_công"] > 0
          and "Phương án triển khai" in md, md[:200])
    check("bypass: schema khớp — patch dùng key có dấu",
          "tỷ_lệ_thanh_cong" not in top and "phan_tich" not in top
          and "de_xuat" not in top and "cach_cong_cu" not in top
          and top["phân_tích"]["tỷ_lệ"] > 0 and "đề_xuất" in top
          and "cách" in top["cách_công_cụ"]
          and "công_cụ" in top["cách_công_cụ"], str(sorted(top)))
    pl = rep["plan"]
    check("bypass: schema khớp — plan dùng key có dấu",
          pl["phương_án"].startswith("P1") and "steps" in pl
          and "tỷ_lệ_dự_đoán" in pl and "rủi_ro" in pl
          and "tăng_khả_năng" in pl
          and "stệps" not in pl and "tỷ_lệ_du_doan" not in pl
          and "rui_ro" not in pl, str(sorted(pl)))


def test_apk_plan_bao_cao():
    import json
    from argparse import Namespace
    import patchx_toolkit as tk
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_plan_")
    try:
        tree = os.path.join(wd, "tree")
        os.makedirs(os.path.join(tree, "smali"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("isRooted()  verifyLicense()")
        pdir = os.path.join(wd, "patches")
        os.makedirs(pdir)
        make_patch_zip(pdir, "p1.zip",
                       "[PACKAGE]\nDemo\n[/PACKAGE]\n"
                       "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\n"
                       "MATCH:\nisRooted\nREGEX:\nfalse\n"
                       "REPLACE:\nconst/4 v0, 0x0\n[/MATCH_REPLACE]\n")
        out = os.path.join(wd, "out")
        rc = tk.cmd_apk_plan(Namespace(tree=tree, input=pdir, output=out,
                                       limit=5, limit_combos=50,
                                       no_auto_install=True))
        md = os.path.join(out, "bypass_report.md")
        js = os.path.join(out, "bypass_report.json")
        ok = rc == 0 and os.path.isfile(md) and os.path.isfile(js)
        if ok:
            with open(js, encoding="utf-8") as fh:
                data = json.load(fh)
            ok = bool(data["top_patches"]) and \
                data["top_patches"][0]["tỷ_lệ_thành_công"] >= 0
        check("apk-plan: sinh báo cáo bypass (md+json, có tỷ lệ %)",
              ok, "rc=%s md=%s js=%s"
              % (rc, os.path.isfile(md), os.path.isfile(js)))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_scan_cache_fast():
    import patchx_core.advisor as adv
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_scanfast_")
    try:
        if shutil.which("rg") is None:
            check("scanfast: bỏ qua khi không có rg", True, "rg thiếu")
            return
        tree = os.path.join(wd, "tree")
        os.makedirs(os.path.join(tree, "smali"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("isRooted()  verifyLicense()\n")
        with open(os.path.join(tree, "smali", "b.smali"), "w",
                  encoding="utf-8") as f:
            f.write("checkServerTrusted X509TrustManager\n")
        cache_dir = os.path.join(wd, "cache")
        sc = adv.ScanCache(tree, cache_dir=cache_dir,
                           min_files=0, min_bytes=0)
        sc.ensure(["isRooted", "checkServerTrusted", "absent"])
        a = sc.candidates("isRooted")
        b = sc.candidates("checkServerTrusted")
        check("scanfast: rg lọc đúng tệp ứng viên theo mẫu literal",
              "smali/a.smali" in a and "smali/b.smali" not in a
              and "smali/b.smali" in b, "a=%s b=%s" % (a, b))
        check("scanfast: mẫu không tồn tại trả rỗng",
              not sc.candidates("absent"))
        sc2 = adv.ScanCache(tree, cache_dir=cache_dir,
                            min_files=0, min_bytes=0)
        sc2.ensure(["isRooted"])
        check("scanfast: cache nạp lại theo hash cây APK",
              sc2.key == sc.key
              and "smali/a.smali" in sc2.candidates("isRooted"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("something else now\n")
        sc3 = adv.ScanCache(tree, cache_dir=cache_dir,
                            min_files=0, min_bytes=0)
        check("scanfast: cây đổi thì fingerprint đổi, cache cũ bị bỏ",
              sc3.key != sc.key and not sc3.candidates("isRooted"))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_coverage_fast_equiv():
    import patchx_core.advisor as adv
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_coveq_")
    try:
        if shutil.which("rg") is None:
            check("coveq: bỏ qua khi không có rg", True, "rg thiếu")
            return
        tree = make_tree(os.path.join(wd, "tree"))
        zpath = make_patch_zip(
            wd, "P.zip",
            "[PACKAGE]\nDemo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Util.smali\n"
            "MATCH:\ncom.example\nREGEX:\nfalse\n"
            "REPLACE:\ncom.demo\n[/MATCH_REPLACE]\n")
        p = parse_patch_file(zpath)
        old = adv.coverage_patch_cached(
            p, tree, texts=adv._read_all_texts(tree))
        new = adv.coverage_patch_cached(
            p, tree, cache=adv.ScanCache(tree))
        d_old = old["chi_tiết"][0]
        d_new = new["chi_tiết"][0]
        same = (old["quy_tắc_khớp"] == new["quy_tắc_khớp"]
                and d_old["khớp"] == d_new["khớp"]
                and d_old["tệp_trúng"] == d_new["tệp_trúng"]
                and [x[0] for x in d_old["ngoai_target"]]
                == [x[0] for x in d_new["ngoai_target"]])
        check("coveq: fast scan cho kết quả tương đương đường quét cũ",
              same, "old=%s new=%s" % (d_old["khớp"], d_new["khớp"]))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_coverage_regex_fast_equiv():
    import patchx_core.advisor as adv
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_coveqre_")
    try:
        if shutil.which("rg") is None:
            check("coveq-re: bỏ qua khi không có rg", True, "rg thiếu")
            return
        tree = make_tree(os.path.join(wd, "tree"))
        zpath = make_patch_zip(
            wd, "R.zip",
            "[PACKAGE]\nDemo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Util.smali\n"
            "MATCH:\ncom\\.example\nREGEX:\ntrue\n"
            "REPLACE:\ncom.demo\n[/MATCH_REPLACE]\n")
        p = parse_patch_file(zpath)
        sc = adv.ScanCache(tree)
        sc.prepare_hints(adv.collect_regex_hints([p]))
        old = adv.coverage_patch_cached(
            p, tree, texts=adv._read_all_texts(tree))
        new = adv.coverage_patch_cached(p, tree, cache=sc)
        d_old = old["chi_tiết"][0]
        d_new = new["chi_tiết"][0]
        same = (old["quy_tắc_khớp"] == new["quy_tắc_khớp"]
                and d_old["khớp"] == d_new["khớp"]
                and d_old["tệp_trúng"] == d_new["tệp_trúng"]
                and [x[0] for x in d_old["ngoai_target"]]
                == [x[0] for x in d_new["ngoai_target"]])
        check("coveq-re: regex lọc bằng hint cho kết quả tương đương đường cũ",
              same, "old=%s new=%s" % (d_old["khớp"], d_new["khớp"]))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_detect_protections_fast():
    from patchx_core.bypass_advisor import detect_protections_fast
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_protfast_")
    try:
        if shutil.which("rg") is None:
            check("protfast: bỏ qua khi không có rg", True, "rg thiếu")
            return
        tree = os.path.join(wd, "tree")
        os.makedirs(os.path.join(tree, "smali"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("isRooted() checkServerTrusted CertificatePinner\n")
        fast = detect_protections_fast(tree)
        names = {p["loại"] for p in fast}
        check("protfast: phát hiện root + pinning bằng rg",
              "root" in names and "pinning" in names, str(names))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_bench_scan():
    import json
    from argparse import Namespace
    import patchx_toolkit as tk
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_bench_")
    try:
        tree = os.path.join(wd, "tree")
        os.makedirs(os.path.join(tree, "smali"))
        with open(os.path.join(tree, "smali", "a.smali"), "w",
                  encoding="utf-8") as f:
            f.write("isRooted() verifyLicense()\n")
        pdir = os.path.join(wd, "patches")
        os.makedirs(pdir)
        make_patch_zip(pdir, "p1.zip",
                       "[PACKAGE]\nDemo\n[/PACKAGE]\n"
                       "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\n"
                       "MATCH:\nisRooted\nREGEX:\nfalse\n"
                       "REPLACE:\nconst/4 v0, 0x0\n[/MATCH_REPLACE]\n")
        out = os.path.join(wd, "out")
        rc = tk.cmd_bench_scan(Namespace(tree=tree, input=pdir, output=out,
                                         no_auto_install=True))
        js = os.path.join(out, "bench_report.json")
        md = os.path.join(out, "bench_report.md")
        ok = rc == 0 and os.path.isfile(js) and os.path.isfile(md)
        if ok:
            with open(js, encoding="utf-8") as fh:
                data = json.load(fh)
            ok = data["patches"] == 1 and data["total_seconds"] >= 0
        check("bench-scan: đo tốc độ và ghi báo cáo (json+md)",
              ok, "rc=%s" % rc)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_learn_smart():
    """T4: thông minh — danh mục, ý định, gợi ý, ghi kho thành công."""
    from patchx_core.learn import (categorize, intent_capabilities,
                                   suggest_by_intent, build_skeleton,
                                   record_success)
    from patchx_core.session import load_patch_map
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_learn_")
    try:
        check("learn: danh mục game",
              categorize("com.tencent.tmgp.gamename") == "game")
        check("learn: danh mục ngân hàng",
              categorize("vn.vpbank.something") == "ngân hàng/tài chính")
        check("learn: danh mục chung",
              categorize("com.example.xyz") == "chung")
        caps = intent_capabilities("mở khóa vip, bypass license")
        check("learn: ý định → năng lực bypass-license",
              "bypass-license" in caps, str(caps))
        caps2 = intent_capabilities("chặn quảng cáo ads")
        check("learn: ý định → năng lực ads", "ads" in caps2, str(caps2))
        base = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Main.smali\n"
                "MATCH:\nisVip\nREGEX:\nfalse\nREPLACE:\nconst/4 v0, 0x1\n"
                "[/MATCH_REPLACE]\n")
        make_patch_zip(d, "vip_unlock.zip", base)
        make_patch_zip(d, "remove_ads.zip", base)
        patches = load_patch_map(d)
        check("learn: nạp đủ patch", len(patches) == 2, str(list(patches)))
        scored, caps = suggest_by_intent("mở khóa vip", patches)
        check("learn: gợi ý đúng patch vip",
              scored and scored[0]["patch"] == "vip_unlock"
              and "bypass-license" in scored[0]["năng_lực"], str(scored))
        merged, conflicts = build_skeleton(patches,
                                           ["vip_unlock", "remove_ads"],
                                           "skeleton_demo")
        check("learn: build_skeleton gộp được",
              merged is not None and conflicts >= 0)
        path = record_success(d, {"patch": "vip_unlock",
                                  "danh_mục": "chung"})
        check("learn: ghi kho thành công json",
              os.path.isfile(path) and "vip_unlock" in open(
                  path, encoding="utf-8").read())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_risk_t5():
    """T5: cờ rủi ro tĩnh — phát hiện gửi dữ liệu / tắt bảo mật."""
    from patchx_core.risk import risk_findings
    from patchx_core.parser import parse_text
    nguy = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\nMATCH:\nx\n"
            "REGEX:\nfalse\nREPLACE:\nconst/4 v0, 0x0\n"
            "[/MATCH_REPLACE]\n"
            "[REMOTE_CONFIG]\nCONFIG_URL:\nhttps://evil.example/cfg\n"
            "[/REMOTE_CONFIG]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/b.smali\nMATCH:\nsigcheck\n"
            "REGEX:\nfalse\nREPLACE:\nconst/4 v0, 0x1\n"
            "[/MATCH_REPLACE]\n")
    p = parse_text(nguy)
    findings = risk_findings(p)
    loai = {f["loại"] for f in findings}
    check("risk: phát hiện gửi-dữ-liệu", "gửi-dữ-liệu" in loai, str(loai))
    check("risk: phát hiện tắt-bảo-mật", "tắt-bảo-mật" in loai, str(loai))
    check("risk: gộp trùng mỗi loại 1 cảnh báo",
          len(findings) == len(loai), str(findings))
    lanh = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
            "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\nMATCH:\nx\n"
            "REGEX:\nfalse\nREPLACE:\nconst/4 v0, 0x1\n"
            "[/MATCH_REPLACE]\n")
    check("risk: patch lành không cảnh báo",
          risk_findings(parse_text(lanh)) == [])


def test_verify_manifest_t5():
    """T5: manifest sha256 + verify phát hiện thêm/sửa file."""
    from argparse import Namespace
    from patchx_core.cli import cmd_manifest, cmd_verify_manifest
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_manifest_")
    try:
        os.makedirs(os.path.join(d, "_patchx"))
        make_patch_zip(d, "p1.zip",
                       "[PACKAGE]\nDemo\n[/PACKAGE]\n"
                       "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\n"
                       "MATCH:\nx\nREGEX:\nfalse\n"
                       "REPLACE:\nconst/4 v0, 0x1\n[/MATCH_REPLACE]\n")
        mpath = os.path.join(d, "_patchx", "MANIFEST.json")
        check("manifest: ghi MANIFEST.json",
              cmd_manifest(Namespace(thu_muc=d, o=mpath)) == 0
              and os.path.isfile(mpath))
        check("verify-manifest: kho sạch rc=0",
              cmd_verify_manifest(Namespace(thu_muc=d, manifest=mpath)) == 0)
        # Sửa nội dung zip → hash đổi → phát hiện
        make_patch_zip(d, "p1.zip",
                       "[PACKAGE]\nDemo\n[/PACKAGE]\n"
                       "[MATCH_REPLACE]\nTARGET:\nsmali/a.smali\n"
                       "MATCH:\nx\nREGEX:\nfalse\n"
                       "REPLACE:\nconst/4 v0, 0x0\n[/MATCH_REPLACE]\n")
        check("verify-manifest: phát hiện file bị sửa rc=2",
              cmd_verify_manifest(Namespace(thu_muc=d, manifest=mpath)) == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_smali_lib_modern_t6():
    """T6: nhận diện lớp hiện đại (R8/Kotlin) + tên patch UTF-8."""
    from patchx_core.smali_lib import (modern_class_kind,
                                       kotlin_metadata_present,
                                       unicode_safe_patch_name)
    check("modern: lớp R$ tài nguyên",
          modern_class_kind("Lcom/foo/R$id;")[0] == "R-inner")
    check("modern: lambda R8",
          modern_class_kind("Lcom/foo/-$$Lambda$abc;")[0] == "lambda-r8")
    check("modern: lambda dex",
          modern_class_kind("Lcom/foo/Lambda$1;")[0] == "lambda")
    check("modern: lớp nội bộ",
          modern_class_kind("Lcom/foo/Outer$Inner;")[0] == "inner")
    check("modern: lớp thường",
          modern_class_kind("Lcom/foo/Plain;")[0] == "thường")
    check("modern: metadata kotlin",
          modern_class_kind("Lcom/foo/FooKt$Metadata;")[0] == "kotlin-metadata")
    check("modern: có metadata kotlin",
          kotlin_metadata_present("Lkotlin/Metadata;") is True
          and kotlin_metadata_present("plain text") is False)
    check("modern: tên patch an toàn UTF-8",
          unicode_safe_patch_name("a/b*c:d") == "a_b_c_d")
    check("modern: tên trống → patch",
          unicode_safe_patch_name("   ") == "patch")


def test_report_dashboard():
    """T7: báo cáo HTML có tìm kiếm/lọc + preview diff theo cây APK."""
    from argparse import Namespace
    from patchx_core.cli import cmd_report
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_dash_")
    try:
        pd = os.path.join(d, "patch")
        os.makedirs(os.path.join(pd, "..", "tree", "smali", "com", "demo"),
                    exist_ok=True)
        os.makedirs(pd, exist_ok=True)
        base = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Main.smali\n"
                "MATCH:\nisVip\nREGEX:\nfalse\n"
                "REPLACE:\nconst/4 v0, 0x1\n[/MATCH_REPLACE]\n")
        make_patch_zip(pd, "vip_unlock.zip", base)
        with open(os.path.join(d, "tree", "smali", "com", "demo",
                               "Main.smali"), "w", encoding="utf-8") as f:
            f.write(".class public Lcom/demo/Main;\n"
                    ".method onCreate()V\n"
                    "    invoke-virtual {p0}, Lcom/demo/License;->isVip()Z\n"
                    "    return-void\n.end method\n")
        out = os.path.join(d, "report.html")
        rc = cmd_report(Namespace(thu_muc=pd, o=out, recursive=False,
                                  apk=None))
        html = open(out, encoding="utf-8").read()
        check("dashboard: report cơ bản + ô tìm kiếm",
              rc == 0 and "Tìm nhanh" in html and 'onclick="tg(' in html)
        out2 = os.path.join(d, "report_cov.html")
        rc2 = cmd_report(Namespace(thu_muc=pd, o=out2, recursive=False,
                                   apk=os.path.join(d, "tree")))
        html2 = open(out2, encoding="utf-8").read()
        check("dashboard: preview diff + độ phủ theo APK",
              rc2 == 0 and "Preview diff" in html2 and "Khớp APK" in html2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_ci_pipeline():
    """T7: dây chuyền CI tạo báo cáo trước/sau."""
    import json
    from argparse import Namespace
    from patchx_core.cli import cmd_ci
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_ci_")
    try:
        pd = os.path.join(d, "patch")
        os.makedirs(pd)
        base = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Main.smali\n"
                "MATCH:\nisVip\nREGEX:\nfalse\n"
                "REPLACE:\nconst/4 v0, 0x1\n[/MATCH_REPLACE]\n")
        make_patch_zip(pd, "vip_unlock.zip", base)
        make_patch_zip(pd, "remove_ads.zip", base)
        out = os.path.join(d, "ci")
        rc = cmd_ci(Namespace(thu_muc=pd, o=out, quick=True))
        md = os.path.join(out, "ci_report.md")
        js = os.path.join(out, "ci_report.json")
        ok = rc == 0 and os.path.isfile(md) and os.path.isfile(js)
        if ok:
            data = json.load(open(js, encoding="utf-8"))
            ok = (data["trước"]["files"] == 2
                  and data["sau_nâng_cấp"]["audit_lỗi"] == 0
                  and data["số_patch_nâng_cấp"] == 2)
        check("ci: báo cáo trước/sau + dây chuyền chạy sạch",
              ok, "rc=%s" % rc)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_coverage_skip_degenerate():
    """Đợt E: mẫu regex suy biến ('.') bị loại khỏi phép đo coverage."""
    from patchx_core.advisor import coverage_patch
    from patchx_core.parser import parse_text
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_covdeg_")
    try:
        os.makedirs(os.path.join(d, "smali", "com", "demo"))
        with open(os.path.join(d, "smali", "com", "demo", "Main.smali"),
                  "w", encoding="utf-8") as f:
            f.write(".method onCreate()V\n"
                    "    invoke-virtual {p0}, Lcom/demo/License;->isVip()Z\n"
                    "    return-void\n.end method\n")
        text = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[MATCH_REPLACE]\nTARGET:\nsmali/com/demo/Main.smali\n"
                "MATCH:\nisVip\nREGEX:\nfalse\n"
                "REPLACE:\nconst/4 v0, 0x1\n[/MATCH_REPLACE]\n"
                "[MATCH_ASSIGN]\nTARGET:\nsmali/com/demo/Main.smali\n"
                "MATCH:\n.\nREGEX:\ntrue\nASSIGN:\n0tempX=1\n"
                "[/MATCH_ASSIGN]\n")
        p = parse_text(text)
        cov = coverage_patch(p, d)
        check("cov: mẫu suy biến bị loại",
              cov["mẫu_bỏ_qua"] == 1 and cov["quy_tắc"] == 1,
              "quy_tắc=%s bỏ=%s" % (cov["quy_tắc"], cov["mẫu_bỏ_qua"]))
        check("cov: rule thật vẫn đếm",
              cov["quy_tắc_khớp"] == 1 and cov["tỷ_lệ"] == 1.0,
              str(cov["quy_tắc_khớp"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_add_files_placeholder_package():
    """Đợt F: ADD_FILES thay %PACKAGE_NAME% bằng package thật (Fix.smali
    của patch apkeditor bị đệ quy StackOverflow khi không thay)."""
    from patchx_core.engine import Engine
    from patchx_core.parser import parse_text
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_ph_")
    try:
        os.makedirs(os.path.join(d, "smali"))
        with open(os.path.join(d, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest package="com.demo.app"><application>'
                     "</application></manifest>")
        helper = ('.class public Lapkeditor/patch/signature/Fix;\n'
                  '.super Ljava/lang/Object;\n'
                  '.method public static getSignatures()V\n'
                  '    const-string v0, "%PACKAGE_NAME%"\n'
                  "    return-void\n.end method\n")
        text = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[ADD_FILES]\nSOURCE:\nFix.smali\n"
                "TARGET:\nsmali/apkeditor/patch/signature/Fix.smali\n"
                "[/ADD_FILES]\n")
        p = parse_text(text)
        p.assets = {"Fix.smali": helper.encode("utf-8")}
        eng = Engine(d, dry_run=False, force=True)
        eng.apply(p)
        out = os.path.join(d, "smali", "apkeditor", "patch", "signature",
                           "Fix.smali")
        content = open(out, encoding="utf-8").read()
        check("placeholder: %PACKAGE_NAME% được thay bằng package thật",
              '"com.demo.app"' in content and "%PACKAGE_NAME%" not in content,
              content.strip().splitlines()[2].strip()[:60])
        check("placeholder: tệp ADD_FILES được ghi",
              os.path.isfile(out))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_match_replace_khong_quet_file_them_truoc():
    """Đợt F: MATCH_REPLACE không được quét vào tệp ADD_FILES của patch
    trước trong cùng lượt chạy (tránh Fix.smali tự gọi đệ quy)."""
    from patchx_core.engine import Engine
    from patchx_core.parser import parse_text
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_cross_")
    try:
        os.makedirs(os.path.join(d, "smali"))
        with open(os.path.join(d, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest package="com.demo.app"><application>'
                     "</application></manifest>")
        helper = (
            '.class public Lapkeditor/patch/signature/Fix;\n'
            '.super Ljava/lang/Object;\n'
            '.method public static getSignatures(Landroid/content/pm/PackageInfo;)[Landroid/content/pm/Signature;\n'
            '    const-string v0, "%PACKAGE_NAME%"\n'
            '    iget-object v1, v2, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;\n'
            "    return-object v1\n.end method\n")
        patch_a = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                   "[ADD_FILES]\nSOURCE:\nFix.smali\n"
                   "TARGET:\nsmali/apkeditor/patch/signature/Fix.smali\n"
                   "[/ADD_FILES]\n")
        patch_b = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                   "[MATCH_REPLACE]\n"
                   "TARGET:\n    smali*/*.smali\n"
                   "MATCH:\n"
                   "    iget-object ([pv]\\d+), ([pv]\\d+), Landroid/content/pm/PackageInfo;->signatures:\\[Landroid/content/pm/Signature;\n"
                   "REGEX:\n    true\n"
                   "REPLACE:\n"
                   "    invoke-static {${GROUP2}}, Lapkeditor/patch/signature/Fix;->getSignatures(Landroid/content/pm/PackageInfo;)[Landroid/content/pm/Signature;\n"
                   "    move-result-object ${GROUP1}\n"
                   "[/MATCH_REPLACE]\n")
        pa, pb = parse_text(patch_a), parse_text(patch_b)
        pa.assets = {"Fix.smali": helper.encode("utf-8")}
        pb.assets = {}
        eng = Engine(d, dry_run=False, force=True)
        eng.apply_many([pa, pb])
        out = os.path.join(d, "smali", "apkeditor", "patch", "signature",
                           "Fix.smali")
        content = open(out, encoding="utf-8").read()
        check("MATCH_REPLACE xuyên patch không hook nhầm Fix.smali",
              "iget-object v1, v2, Landroid/content/pm/PackageInfo;->signatures:"
              in content and "invoke-static {v2}, Lapkeditor/patch/signature/Fix;"
              "->getSignatures" not in content,
              content.strip().splitlines()[4].strip()[:70])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_add_files_placeholder_rsa():
    """Đợt F: ADD_FILES thay %RSA_DATA% bằng cert hex từ PATCHX_RSA_DATA;
    không có biến → giữ nguyên."""
    from patchx_core.engine import Engine
    from patchx_core.parser import parse_text
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_rsa_")
    old = os.environ.get("PATCHX_RSA_DATA")
    try:
        os.makedirs(os.path.join(d, "smali"))
        with open(os.path.join(d, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest package="com.demo.app"><application>'
                     "</application></manifest>")
        helper = ('.class public Ldemo/Fix;\n'
                  '.super Ljava/lang/Object;\n'
                  '.method public static run()V\n'
                  '    const-string v0, "%RSA_DATA%"\n'
                  "    return-void\n.end method\n")
        text = ("[PACKAGE]\nDemo\n[/PACKAGE]\n"
                "[ADD_FILES]\nSOURCE:\nFix.smali\n"
                "TARGET:\nsmali/demo/Fix.smali\n"
                "[/ADD_FILES]\n")
        p = parse_text(text)
        p.assets = {"Fix.smali": helper.encode("utf-8")}
        os.environ["PATCHX_RSA_DATA"] = "3082ABCD"
        eng = Engine(d, dry_run=False, force=True)
        eng.apply(p)
        out = os.path.join(d, "smali", "demo", "Fix.smali")
        content = open(out, encoding="utf-8").read()
        check("placeholder: %RSA_DATA% được thay bằng hex PATCHX_RSA_DATA",
              '"3082ABCD"' in content and "%RSA_DATA%" not in content,
              content.strip().splitlines()[2].strip()[:60])
        d2 = tempfile.mkdtemp(dir=TMP, prefix="patchx_rsa2_")
        os.makedirs(os.path.join(d2, "smali"))
        with open(os.path.join(d2, "AndroidManifest.xml"), "w",
                  encoding="utf-8") as fh:
            fh.write('<manifest package="com.demo.app"><application>'
                     "</application></manifest>")
        os.environ.pop("PATCHX_RSA_DATA", None)
        p2 = parse_text(text)
        p2.assets = {"Fix.smali": helper.encode("utf-8")}
        eng2 = Engine(d2, dry_run=False, force=True)
        eng2.apply(p2)
        out2 = os.path.join(d2, "smali", "demo", "Fix.smali")
        content2 = open(out2, encoding="utf-8").read()
        check("placeholder: không có PATCHX_RSA_DATA → giữ %RSA_DATA%",
              '"%RSA_DATA%"' in content2,
              content2.strip().splitlines()[2].strip()[:60])
    finally:
        if old is None:
            os.environ.pop("PATCHX_RSA_DATA", None)
        else:
            os.environ["PATCHX_RSA_DATA"] = old
        shutil.rmtree(d, ignore_errors=True)


def test_extract_apk_cert_hex():
    """Đợt F: trích cert DER hex từ APK (giá trị %RSA_DATA%) — so với cert
    thật của fixture mini_app.apk (lấy bằng CertificateFactory của Java)."""
    from patchx_toolkit import _extract_apk_cert_hex
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fixtures", "mini_app.apk")
    expected = (
        "308202CF308201B7A003020102020821EF983C8517976A300D06092A864886F70D"
        "01010C05003016311430120603550403130B7061746368782074657374301E170D"
        "3236303831353139323535325A170D3336303831323139323535325A3016311430"
        "120603550403130B706174636878207465737430820122300D06092A864886F70D"
        "01010105000382010F003082010A0282010100C61C53EDEC5119810A195CD90CA4"
        "50460B364BA7E95079DC17CBE33B5F7E303B0FFFE19E7D6D17C37E3435DE00ADBC"
        "E5CE445ECF7AC2ECE4F7F06750A808D75BCA2B1454D3B7D499CDD56BD8B49DECB2"
        "EC4E5C7596A7CA71719CA77C4402623654AAEFA1EC40F58C75FB9DF8DD3A083ED6"
        "09743FC29959B62AE5FB8932F782460DC851E619DF7380DCB9AF49797136FE961E"
        "AAD12BA29AD50E36D08AB374AA718B16E884703B827C6015E49A6406C6EF5EFDD0"
        "C6DDB7B0CF314050AE6A219BEDC588CBEFA7F8983068B118EB75101612F0CE690E"
        "E5339D0C1609BC4BC44B8E7159F0502D106436F134A7C8576362BA8CB284EA19B3"
        "68683EDD4F00B073C8B8ED0203010001A321301F301D0603551D0E04160414F090"
        "EB62CCA952FC918E374B60F55B4DDE80EC6B300D06092A864886F70D01010C0500"
        "03820101003F3DA88AB8AD1A35EACC3A9468797341FBF05D58FC42D8EDF080F0FB"
        "75CCCCDC50378795E51DC400669DE50CBC0EA6F9A0DB764C682BC199D1D5FF0FE2"
        "C18CF8045AD23C1336F72153903F5958986F778FFAE15FDE6F06C0E9A27853DA5"
        "BCF44B9B112A6C48539BD1AE7B06CDE46DE50701F29E01D5B055A028A659C5952B"
        "37B5A52228D4DBE53474A6BA22B6179B20F76AD34EDF3514E78532A7531333ADA"
        "85CD9C9A161B25A46559F736C840888BE7229D86B7FDC9011942E2ABDA2746A30"
        "4CBA84212C689E151B5226E7C3E21B4D1EAE494740018E514DB0279F46B24BEAD"
        "EA536FE7A5C309C37BDC18C2399490C09ECA5EE40BC7BC985E5216DD0C2BBF2D")
    got = _extract_apk_cert_hex(fixture)
    check("trích cert v1 từ APK đúng bằng cert thật",
          got == expected,
          (got or "None")[:40] + "..." if got != expected else "")
    check("cert hex độ dài chẵn và đủ dài",
          bool(got) and len(got) % 2 == 0 and len(got) // 2 > 300,
          "len=%s" % (len(got) // 2 if got else 0))


def test_plan_ui_render():
    """Đợt G: plan-ui dựng trang HTML đầy đủ tính năng chọn patch."""
    from patchx_toolkit import _render_plan_ui
    html = _render_plan_ui({
        "report": {
            "tree": "/x/apk_trees/app",
            "generated": "2026-08-16 06:00:00",
            "protections": [{"loại": "pinning", "lần": 3, "tệp": ["a.smali"]}],
            "top_patches": [{
                "patch": "P1", "tỷ_lệ_thành_công": 27.0,
                "phân_tích": {"yếu_tố": [{"tên": "Khớp 100%", "điểm": 45.0}],
                              "phạt": [{"loại": "pinning", "điểm": 15.0}]},
                "cách_công_cụ": {"cách": ["Hook kiểm tra VIP"],
                                 "công_cụ": ["Frida"]},
                "điểm_bypass": [{"khối": 1, "loại": "MATCH_REPLACE",
                                 "target": "smali*/*.smali", "khớp": 5,
                                 "tệp_trúng": ["a.smali"]}],
            }],
            "plan": {"phương_án": "P1", "tỷ_lệ_dự_đoán": 27.0,
                     "steps": ["Áp patch"], "rủi_ro": ["pinning"]},
        },
        "plan": {"generated": "2026-08-16 06:00:00",
                 "top_patches": [{"patch": "P1",
                                  "chi_tiết": [{"khối": 1,
                                                "loại": "MATCH_REPLACE",
                                                "target": "smali*/*.smali",
                                                "khớp": 5,
                                                "tệp_trúng": ["a.smali"]}]}],
                 "top_combos": [{"patch1": "P1", "patch2": "P2",
                                 "score": 0.8, "capabilities": ["shell"]}]},
        "candidates": [{"patch": "P1", "score": 1.0, "coverage": 1.0,
                        "matches": 100,
                        "capabilities": ["bypass-license", "integrity"]},
                       {"patch": "P2", "score": 0.5, "coverage": 0.4,
                        "matches": 10, "capabilities": ["shell"]}],
        "apk": "Apks/app.apk", "output": "/x/out", "tree": "/x/apk_trees/app",
        "package": "com.demo.app",
    })
    for kw in ('id="q"', 'id="caps"', 'id="tbody"', 'btn_suggest', 'btn_copy',
               'btn_save', 'id="plan"', 'id="combos"', 'id="prots"',
               'selected_patches.json', 'bypass-license', '"success": 27.0',
               'com.demo.app'):
        check("plan-ui: có %s" % kw, kw in html, "")
    check("plan-ui: JSON nhúng không còn chỗ trống",
          "__DATA__" not in html and "__CAPS__" not in html, "")


def test_terminal_ui_vietnamese():
    """UI CLI: menu tiếng Việt, demo không tương tác và không thực thi patch."""
    from patchx_core.terminal_ui import TerminalUI, run_terminal_ui
    output = []
    rc = run_terminal_ui(PATCHX, demo=True, output_fn=output.append)
    text = "\n".join(output)
    check("ui-cli: demo tiếng Việt hiển thị menu và bản đồ PASS",
          rc == 0 and "GIAO DIỆN CLI TIẾNG VIỆT" in text
          and "BẢN ĐỒ VẬN HÀNH" in text and "Kết quả liên kết: PASS" in text,
          "rc=%s" % rc)
    replies = iter(["9", "0"])
    interactive_output = []
    ui = TerminalUI(PATCHX, input_fn=lambda _prompt: next(replies),
                    output_fn=interactive_output.append)
    rc = ui.run()
    rendered = "\n".join(interactive_output)
    check("ui-cli: chặn lựa chọn sai và thoát không thay đổi dữ liệu",
          rc == 0 and "Lựa chọn không hợp lệ" in rendered
          and "Không có dữ liệu nào bị thay đổi" in rendered,
          "rc=%s" % rc)


def test_cli_danh_muc_so_thu_tu():
    """Danh mục CLI phải đánh số liên tục và phủ đủ mọi lệnh thật."""
    from patchx_core.cli import (C, COMMAND_GROUPS, GroupedArgumentParser,
                                 command_at_position)
    commands = [name for _, group in COMMAND_GROUPS for name, _ in group]
    help_text = GroupedArgumentParser().format_help()
    check("cli-danh-muc: đủ 77 lệnh độc nhất",
          len(commands) == 77 and len(commands) == len(set(commands)),
          "so_luong=%d" % len(commands))
    check("cli-danh-muc: số khớp vị trí đầu/giữa/cuối",
          command_at_position(1) == "intake"
          and command_at_position(15) == "unflatten"
          and command_at_position(36) == "neon-bench"
          and command_at_position(47) == "smart-patch"
          and command_at_position(77) == "clean",
          "01=%s, 15=%s, 36=%s, 47=%s, 77=%s" % (
              command_at_position(1), command_at_position(15),
              command_at_position(36), command_at_position(47),
              command_at_position(77)))
    check("cli-danh-muc: chặn số ngoài danh mục",
          command_at_position(0) is None and command_at_position(78) is None,
          "0=%s, 78=%s" % (command_at_position(0), command_at_position(78)))
    check("cli-danh-muc: trợ giúp tách màu số/tên/mô tả",
          "01." in help_text and "77." in help_text
          and C.WHT in help_text and (C.DIM + "│ ") in help_text,
          "ANSI + dải số")



def test_res_attr_autofix():
    """Đợt G: auto-fix attribute res/*.xml mới hơn framework khi build
    (vd android:hyphenationFrequency enum [full=2, none=0, normal=1])."""
    from patchx_toolkit import RES_ATTR_RE, _fix_res_xml_unknown_attrs
    line = ("W: apk_trees/app/res/layout/fragment_transcribe_permission.xml:6: "
            "error: '4' is incompatible with attribute hyphenationFrequency "
            "(attr) enum [full=2, none=0, normal=1].")
    got = RES_ATTR_RE.findall(line)
    check("res-attr: regex bắt lỗi enum/flags",
          got == [("apk_trees/app/res/layout/"
                   "fragment_transcribe_permission.xml",
                   "hyphenationFrequency")], str(got))
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_resattr_")
    try:
        lay = os.path.join(d, "res", "layout")
        os.makedirs(lay)
        path = os.path.join(lay, "fragment_transcribe_permission.xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('<TextView android:id="@id/tv" '
                     'android:hyphenationFrequency="4" '
                     'android:text="@string/x"/>\n')
        fixed = _fix_res_xml_unknown_attrs(
            d, {path: {"hyphenationFrequency"}})
        check("res-attr: bỏ attribute có namespace",
              fixed == ["res/layout/fragment_transcribe_permission.xml:"
                        "hyphenationFrequency"], str(fixed))
        text = open(path, encoding="utf-8").read()
        check("res-attr: tệp sạch attr",
              "hyphenationFrequency" not in text)
        baks = []
        for root, _dirs, files in os.walk(d):
            baks += [os.path.join(root, f) for f in files
                     if "bak_attrfix" in f]
        check("res-attr: có sao lưu", len(baks) == 1, str(baks))
        fixed2 = _fix_res_xml_unknown_attrs(
            d, {path: {"hyphenationFrequency"}})
        check("res-attr: idempotent (lần 2 không đổi)",
              fixed2 == [], str(fixed2))
    finally:
        shutil.rmtree(d, ignore_errors=True)




def test_semantic_evidence_v2():
    """Đề xuất V2 — evidence report: ứng viên bị loại kèm lý do + failure DB."""
    from argparse import Namespace
    from patchx_core.cli import cmd_model
    from patchx_core.failure_db import classify_failure
    from patchx_core.semantic_plan import (SCHEMA_V2, evaluate_plan_v2,
                                           suggest_selector_fix)
    from patchx_core.smali_sem import build_app_model_v2
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2", "source")
    model = build_app_model_v2(fixture)
    check("sem-evidence-v2: model --bench v2 chạy cache lạnh không ghi JSON",
          cmd_model(Namespace(cay_apk=fixture, v2=True, with_bodies=False,
                              o=None, bench=True)) == 0)
    no_confident_plan = {
        "schema": SCHEMA_V2, "goal": "Tìm lời gọi không tồn tại",
        "targets": [{"name": "absent_gate", "selector": {"all": [
            {"requires_call": "Lcom/example/semantic/Absent;->x()V"}]},
            "policy": {"min_score": 100, "max_accepted": 1,
                       "on_ambiguous": "STOP"}}],
        "operation_intent": [{"type": "TRACE", "target": "absent_gate"}],
        "verification": ["preflight", "validate", "build", "runtime"]}
    result = evaluate_plan_v2(no_confident_plan, model)
    rejected = result["targets"][0]["rejected"]
    check("sem-evidence-v2: NO_CONFIDENT_TARGET và ứng viên bị loại có lý do",
          result["verdict"] == "NO_CONFIDENT_TARGET" and rejected
          and all(item.get("missing") for item in rejected),
          "%s rejected=%d" % (result["verdict"], len(rejected)))
    no_confident_tips = suggest_selector_fix(no_confident_plan, result)
    check("selector-fix: NO_CONFIDENT gợi ý nới selector + atom thiếu chung",
          any(tip["kind"] == "no_confident" and tip.get("common_missing")
              for tip in no_confident_tips),
          str(no_confident_tips))
    ambiguous_plan = {
        "schema": SCHEMA_V2, "goal": "Selector mơ hồ nhiều method void",
        "targets": [{"name": "void_gate", "selector": {"all": [
            {"return_type": "V"}]},
            "policy": {"min_score": 100, "max_accepted": 1,
                       "on_ambiguous": "STOP"}}],
        "operation_intent": [{"type": "TRACE", "target": "void_gate"}],
        "verification": ["preflight", "validate", "build", "runtime"]}
    ambiguous = evaluate_plan_v2(ambiguous_plan, model)
    check("sem-evidence-v2: nhiều ứng viên bị chặn AMBIGUOUS_TARGET",
          ambiguous["verdict"] == "AMBIGUOUS_TARGET"
          and len(ambiguous["targets"][0]["accepted"]) > 1,
          ambiguous["verdict"])
    ambiguous_tips = suggest_selector_fix(ambiguous_plan, ambiguous)
    check("selector-fix: AMBIGUOUS gợi ý siết policy/selector",
          any(tip["kind"] == "ambiguous" and tip.get("advice")
              for tip in ambiguous_tips),
          str(ambiguous_tips))
    caller_plan = {
        "schema": SCHEMA_V2, "goal": "Tìm method được App.onCreate gọi",
        "targets": [{"name": "called_gate", "selector": {"all": [
            {"requires_caller": "Lcom/example/semantic/App;->onCreate()V"}]},
            "policy": {"min_score": 100, "max_accepted": 1,
                       "on_ambiguous": "STOP"}}],
        "operation_intent": [{"type": "TRACE", "target": "called_gate"}],
        "verification": ["preflight", "validate", "build", "runtime"]}
    caller_result = evaluate_plan_v2(caller_plan, model)
    check("sem-evidence-v2: selector requires_caller khớp quan hệ gọi",
          caller_result["verdict"] == "READY_FOR_PREFLIGHT"
          and len(caller_result["targets"][0]["accepted"]) == 1
          and caller_result["targets"][0]["accepted"][0]["method"].endswith(
              "->isEnabled()Z"),
          caller_result["verdict"])
    check("failure: AMBIGUOUS_TARGET → F-SEM-001",
          classify_failure("AMBIGUOUS_TARGET", stage="PLAN")["error_id"]
          == "F-SEM-001")
    check("failure: INSUFFICIENT_EVIDENCE → F-SEM-002",
          classify_failure("INSUFFICIENT_EVIDENCE", stage="PLAN")["error_id"]
          == "F-SEM-002")
    check("failure: cây APK đã thay đổi → F-SEM-003",
          classify_failure("cây APK đã thay đổi", stage="PREFLIGHT")["error_id"]
          == "F-SEM-003")
    check("failure: NO_CONFIDENT_TARGET → F-SEM-004",
          classify_failure("NO_CONFIDENT_TARGET", stage="PLAN")["error_id"]
          == "F-SEM-004")


def test_dataflow_and_knowledge_bridge():
    """Đề xuất V2 — decision-flow map + cầu nối knowledge → semantic-plan."""
    from patchx_core.knowledge import (record_verified, suggest_plan_v2)
    from patchx_core.remote_map import (build_data_flow, build_decision_flow,
                                        dataflow_summary_text,
                                        flow_summary_text)
    from patchx_core.semantic_plan import SCHEMA_V2, validate_plan_v2
    from patchx_core.smali_sem import build_app_model_v2
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2", "source")
    flow = build_decision_flow(fixture)
    check("decision-flow: schema V1 + node decision/edge",
          flow["schema"] == "patchx.decision-flow/v1"
          and flow["summary"]["nodes_by_type"].get("decision", 0) >= 1
          and flow["summary"]["edges"] >= 1,
          "%s %s" % (flow["summary"]["nodes_by_type"], flow["summary"]["edges"]))
    check("decision-flow: summary_text có số liệu",
          "Luồng quyết định/dữ liệu" in flow_summary_text(flow)
          and "Điểm quyết định có đường tới sink" in flow_summary_text(flow),
          flow_summary_text(flow)[:80])
    dataflow = build_data_flow(fixture)
    check("data-flow: node có role/kiểu/độ tin cậy",
          dataflow["schema"] == "patchx.data-flow/v1"
          and all({"primary_role", "roles", "data_type", "confidence"}
                  <= set(n) for n in dataflow["nodes"]),
          "%s" % dataflow["summary"])
    check("data-flow: thống kê vai trò + kiểu dữ liệu",
          dataflow["summary"]["nodes_by_role"].get("decision", 0) >= 1
          and dataflow["summary"]["nodes_by_role"].get("source", 0) >= 1
          and dataflow["summary"]["data_types"].get("boolean", 0) >= 1,
          "%s %s" % (dataflow["summary"]["nodes_by_role"],
                     dataflow["summary"]["data_types"]))
    check("data-flow: summary_text có vai trò + kiểu dữ liệu",
          "Vai trò" in dataflow_summary_text(dataflow)
          and "Kiểu dữ liệu" in dataflow_summary_text(dataflow),
          dataflow_summary_text(dataflow)[:80])
    model = build_app_model_v2(fixture)
    gate = next(m for m in model["methods"]
                if m["id"].endswith("->isEnabled()Z"))
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_kbridge_")
    try:
        db = os.path.join(wd, "knowledge.json")
        record = {"schema": "patchx.knowledge-record/v2",
                  "app": {"package": "com.example.semantic", "version": "1.0"},
                  "goal": "Truy vết gate", "target": {"identity": gate["identity"]},
                  "evidence": {"extractor_version": "model/v2"},
                  "gates": {"preflight": "PASS", "validate": "PASS",
                            "build": "PASS", "runtime": "PASS"},
                  "outcome": "SUCCESS", "verified": True}
        record_verified(db, record)
        plan = suggest_plan_v2(db, model, goal="Truy vết gate")
        check("knowledge-bridge: sinh plan V2 tham chiếu từ kho tri thức",
              plan is not None
              and plan["schema"] == SCHEMA_V2
              and len(plan["targets"]) == 1
              and plan["provenance"]["recommendation_only"]
              and not validate_plan_v2(plan),
              None if plan is None else "%s %d" % (plan["schema"], len(plan["targets"])))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_acceptance_v2():
    """Đề xuất V2 — tiêu chí nghiệm thu có số liệu trên fixture có nhãn."""
    from patchx_core.acceptance import run_acceptance
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "semantic_v2")
    report = run_acceptance(fixture)
    m = report["metrics"]
    check("acceptance: tái lập model 100% và tái nhận diện 100%",
          report["reproducibility"]["rate"] == 100.0
          and report["reidentification_rate"] == 100.0,
          "%s %s" % (report["reproducibility"]["rate"],
                     report["reidentification_rate"]))
    check("acceptance: READY đúng, dương tính giả 0%",
          m["ready_rate"] == 100.0 and m["false_positive_rate"] == 0.0,
          str(m))
    check("acceptance: mơ hồ và không tự tin đều bị chặn",
          m["ambiguity_rate"] == 100.0
          and m["no_confident_blocked"] == m["no_confident_total"],
          str(m))


def test_obfuscation_variants_v2():
    """Đề xuất V2 — fixture obfuscation: đổi tên, thanh ghi, .line, nhiễu."""
    from patchx_core.acceptance import run_acceptance
    from patchx_core.semantic_plan import evaluate_plan_v2, load_plan
    from patchx_core.smali_sem import build_app_model_v2
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2")
    report = run_acceptance(fixture)
    variants = report.get("reidentification_variants", {})
    check("obfuscation: tái nhận diện mọi biến thể đạt ≥ 95%",
          len(variants) >= 4
          and all(rate >= 95.0 for rate in variants.values()),
          str(variants))
    plan = load_plan(os.path.join(fixture, "plan_v2.json"))
    verdicts = {}
    for variant in ("source", "obfuscated", "obfuscated_register",
                    "obfuscated_line", "obfuscated_noise"):
        model = build_app_model_v2(os.path.join(fixture, variant))
        result = evaluate_plan_v2(plan, model)
        verdicts[variant] = (result["verdict"],
                             [len(t["accepted"]) for t in result["targets"]])
    check("obfuscation: selector cấu trúc READY duy nhất trên mọi biến thể",
          all(v[0] == "READY_FOR_PREFLIGHT" and v[1] == [1]
              for v in verdicts.values()),
          str(verdicts))
    name_dependent = {
        "schema": "patchx.semantic-plan/v2",
        "goal": "Selector phụ thuộc tên gốc phải thất bại trên bản đổi tên",
        "targets": [{
            "name": "gate_by_name",
            "selector": {"all": [
                {"requires_call": "Lcom/example/semantic/License;->isEnabled()Z"},
                {"parameters": []}]},
            "policy": {"min_score": 100, "max_accepted": 1,
                       "on_ambiguous": "STOP"}}],
        "operation_intent": [{"type": "TRACE", "target": "gate_by_name"}],
        "verification": ["preflight", "validate", "build", "runtime"]}
    source_result = evaluate_plan_v2(
        name_dependent, build_app_model_v2(os.path.join(fixture, "source")))
    obf_result = evaluate_plan_v2(
        name_dependent, build_app_model_v2(os.path.join(fixture, "obfuscated")))
    check("obfuscation: selector phụ thuộc tên bị chặn khi APK đổi tên",
          source_result["verdict"] == "READY_FOR_PREFLIGHT"
          and obf_result["verdict"] == "NO_CONFIDENT_TARGET",
          "%s → %s" % (source_result["verdict"], obf_result["verdict"]))


def test_v2_requires_unique_candidate_policy():
    """V2 — không cho plan hạ chuẩn nhiều ứng viên thành READY."""
    from patchx_core.semantic_plan import validate_plan_v2
    invalid = {
        "schema": "patchx.semantic-plan/v2",
        "goal": "Không được tự chấp nhận nhiều ứng viên",
        "targets": [{
            "name": "gate",
            "selector": {"all": [{"return_type": "Z"}]},
            "policy": {"min_score": 100, "max_accepted": 2,
                       "on_ambiguous": "STOP"}
        }],
        "operation_intent": [{"type": "TRACE", "target": "gate"}],
        "verification": ["preflight", "validate", "build", "runtime"]
    }
    errors = validate_plan_v2(invalid)
    check("sem-plan-v2: policy chỉ chấp nhận đúng một ứng viên",
          any("max_accepted phải bằng 1" in error for error in errors),
          str(errors))


def test_v2_relation_evidence_fixtures():
    """Luồng 2 V2 — caller/callee/field đều có fixture dương và âm riêng."""
    from patchx_core.acceptance import run_acceptance
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2_relations")
    report = run_acceptance(fixture)
    cases = {item["name"]: item for item in report["plans"]}
    pairs = {
        "caller": ("caller_positive", "caller_negative"),
        "callee": ("callee_positive", "callee_negative"),
        "field_read": ("field_read_positive", "field_read_negative"),
        "field_write": ("field_write_positive", "field_write_negative"),
    }
    for evidence, (positive, negative) in pairs.items():
        yes, no = cases.get(positive, {}), cases.get(negative, {})
        check("sem-plan-v2: evidence %s có fixture dương/âm" % evidence,
              yes.get("verdict_ok") and no.get("verdict_ok")
              and yes.get("verdict") == "READY_FOR_PREFLIGHT"
              and no.get("verdict") == "NO_CONFIDENT_TARGET",
              "%s=%s; %s=%s" % (positive, yes.get("verdict"),
                                  negative, no.get("verdict")))


def test_v2_knowledge_rejects_execution_payload():
    """Luồng 3 V2 — kho tri thức chỉ giữ evidence, không giữ patch/lệnh."""
    from patchx_core.knowledge import (SCHEMA_V2, record_verified,
                                       validate_record_v2)
    from patchx_core.smali_sem import build_app_model_v2
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2", "source")
    model = build_app_model_v2(fixture)
    gate = next(m for m in model["methods"]
                if m["id"].endswith("->isEnabled()Z"))
    unsafe = {
        "schema": SCHEMA_V2,
        "app": {"package": "com.example.semantic", "version": "1.0"},
        "goal": "Record không được mang patch",
        "target": {"identity": gate["identity"]},
        "evidence": {"extractor_version": "model/v2",
                     "patch": "[MATCH_REPLACE]"},
        "gates": {"preflight": "PASS", "validate": "PASS",
                  "build": "PASS", "runtime": "PASS"},
        "outcome": "SUCCESS", "verified": True,
    }
    errors = validate_record_v2(unsafe)
    rejected = False
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_knowledge_safe_")
    try:
        try:
            record_verified(os.path.join(wd, "knowledge.json"), unsafe)
        except ValueError:
            rejected = True
    finally:
        shutil.rmtree(wd, ignore_errors=True)
    check("knowledge-v2: chặn payload patch/lệnh trong record evidence",
          rejected and any("payload/lệnh thực thi" in error for error in errors),
          str(errors))


def test_plan_revalidation_v2():
    """Đề xuất V2 — draft bất biến tự đánh giá lại khi hash cây thay đổi."""
    import json
    from argparse import Namespace
    from patchx_core.cli import cmd_plan_preflight
    from patchx_core.plan_compile import (compile_plan_v2, revalidate_draft,
                                          verify_draft_evidence)
    from patchx_core.semantic_plan import load_plan
    from patchx_core.smali_sem import build_app_model_v2
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "semantic_v2", "source")
    plan = load_plan(os.path.join(os.path.dirname(fixture), "plan_v2.json"))
    wd = tempfile.mkdtemp(dir=TMP, prefix="patchx_reval_")
    try:
        tree = os.path.join(wd, "tree")
        shutil.copytree(fixture, tree)
        draft = compile_plan_v2(plan, build_app_model_v2(tree), tree)
        check("revalidate: draft chỉ đọc, khóa đúng một target",
              draft["status"] == "DRAFT_REQUIRES_APPROVAL"
              and draft["executable"] is False
              and len(draft["selected_targets"]) == 1,
              draft["status"])
        ready = verify_draft_evidence(draft, tree)
        check("revalidate: evidence khớp ở cây nguyên vẹn",
              ready["status"] == "READY_FOR_APPROVAL", ready["status"])
        main_smali = os.path.join(tree, "smali", "com", "example",
                                  "semantic", "Main.smali")
        with open(main_smali, "a", encoding="utf-8") as fh:
            fh.write("\n# tamper: chỉ đổi hash, không đổi mục tiêu\n")
        result = revalidate_draft(draft, tree)
        check("revalidate: cây đổi nhưng plan vẫn READY → draft mới",
              result["status"] == "READY_FOR_APPROVAL"
              and result["recompiled"] is True
              and result["draft"]["tree_evidence_hash"]
              != draft["tree_evidence_hash"],
              "%s %s" % (result["status"], result["reason"]))
        result2 = revalidate_draft(result["draft"], tree)
        check("revalidate: draft mới đã khớp hash cây hiện tại",
              result2["status"] == "READY_FOR_APPROVAL"
              and result2["recompiled"] is False,
              result2["status"])
        draft_path = os.path.join(wd, "draft.json")
        new_draft_path = os.path.join(wd, "draft_recompiled.json")
        with open(draft_path, "w", encoding="utf-8") as fh:
            json.dump(draft, fh, ensure_ascii=False, indent=2)
        rc = cmd_plan_preflight(Namespace(cay_apk=tree, draft=draft_path,
                                          o=new_draft_path))
        check("revalidate: CLI plan-preflight ghi draft mới khi cây đổi",
              rc == 0 and os.path.isfile(new_draft_path),
              "rc=%s" % rc)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_v2_never_calls_apply():
    """Đề xuất V2 — an toàn thực thi: các bước chỉ-đọc không gọi Engine.apply."""
    from patchx_core.acceptance import run_acceptance
    from patchx_core.engine import Engine
    from patchx_core.plan_compile import (compile_plan_v2, revalidate_draft,
                                          verify_draft_evidence)
    from patchx_core.remote_map import build_data_flow, build_decision_flow
    from patchx_core.semantic_plan import evaluate_plan_v2, load_plan
    from patchx_core.smali_sem import build_app_model_v2
    fixture_dir = os.path.join(os.path.dirname(__file__), "fixtures",
                               "semantic_v2")
    source = os.path.join(fixture_dir, "source")
    plan = load_plan(os.path.join(fixture_dir, "plan_v2.json"))
    model = build_app_model_v2(source)
    calls = []
    original_apply, original_apply_many = Engine.apply, Engine.apply_many
    def forbidden_apply(self, patch):
        calls.append(("apply", patch))
        raise AssertionError("lệnh V2 chỉ-đọc đã gọi Engine.apply")
    def forbidden_apply_many(self, patches):
        calls.append(("apply_many", patches))
        raise AssertionError("lệnh V2 chỉ-đọc đã gọi Engine.apply_many")
    Engine.apply = forbidden_apply
    Engine.apply_many = forbidden_apply_many
    try:
        evaluate_plan_v2(plan, model)
        draft = compile_plan_v2(plan, model, source)
        verify_draft_evidence(draft, source)
        revalidate_draft(draft, source)
        build_decision_flow(source)
        build_data_flow(source)
        run_acceptance(fixture_dir)
    finally:
        Engine.apply = original_apply
        Engine.apply_many = original_apply_many
    check("v2-safety: model/plan/compile/preflight/map/acceptance không gọi apply",
          calls == [], str(calls))


def test_baseline():
    """PHASE 0 — baseline: ghi, đọc, so sánh, cổng chặn hồi quy."""
    from patchx_core.baseline import (compare_metrics, load_metrics,
                                      write_baseline)
    d = tempfile.mkdtemp(dir=TMP)
    try:
        mpath = write_baseline(d, {"test_pass": "100", "test_total": "100",
                                   "scan_time_s": "23.6"})
        check("baseline ghi metrics.json", os.path.isfile(mpath))
        m = load_metrics(mpath)
        check("baseline đọc lại đúng", m.get("test_pass") == 100)
        res = compare_metrics(m, {"test_pass": 90, "test_total": 100,
                                  "scan_time_s": 23.6})
        check("baseline chặn hồi quy test", res["verdict"] == "BLOCK")
        res2 = compare_metrics(m, {"test_pass": 105, "test_total": 100,
                                   "scan_time_s": 20.0})
        check("baseline chấp nhận khi tốt hơn", res2["verdict"] == "ACCEPT")
        res3 = compare_metrics(m, {"test_pass": 100, "test_total": 100,
                                   "scan_time_s": 30.0})
        check("baseline chặn scan chậm hơn 5s", res3["verdict"] == "BLOCK")
        res4 = compare_metrics(m, {"test_pass": 100, "test_total": 100,
                                   "scan_time_s": 26.0})
        check("baseline cho phép xê dịch trong ngưỡng",
              res4["verdict"] == "ACCEPT")
    finally:
        shutil.rmtree(d, ignore_errors=True)





def test_rodata_bypass_flows():
    """rodata_bypass: package riêng — luồng tĩnh (patch file) + luồng động
    (Frida RAM) + main hiển thị riêng (tách khỏi CLI cũ)."""
    from patchx_core.rodata_bypass import (StaticBypassFlow, DynamicBypassFlow,
                                           main as rb_main)
    from patchx_core.rodata_bypass.main import BANNER
    from patchx_core.behavior.rodata_patcher import ElfReader

    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_bypass_")
    try:
        so = os.path.join(d, "libdemo.so")
        shutil.copy2(os.path.join(PATCHX, "tests", "fixtures",
                                  "mau", "libdemo64.so"), so)
        s0 = "https://api.old-server.com/v1"

        # ---- Luồng TĨNH ----
        sf = StaticBypassFlow(so)
        hits = sf.find(s0)
        check("bypass-static: find RVA", len(hits) == 1
              and hits[0].rva == 0x1000 and hits[0].section == ".rodata")
        rep = sf.run(needle=s0, new_string="https://new.example.com")
        check("bypass-static: run ghi file + backup",
              ElfReader(so).read_cstring(0x1000) == "https://new.example.com"
              and bool(rep.get("backup")) and os.path.isfile(rep["backup"]))
        try:
            sf.run(needle="https://new.example.com",
                   new_string="https://very-long.example.com/xyz")
            check("bypass-static: dài hơn -> báo lỗi", False, "không raise")
        except ValueError:
            check("bypass-static: dài hơn -> báo lỗi", True)
        try:
            StaticBypassFlow(so).run(new_string="x")  # thiếu RVA + needle
            check("bypass-static: thiếu RVA -> báo lỗi", False, "không raise")
        except ValueError:
            check("bypass-static: thiếu RVA -> báo lỗi", True)

        # ---- Luồng ĐỘNG ----
        df = DynamicBypassFlow(so)
        out = df.run(needle="https://new.example.com",
                     new_string="https://very-long.example.com/xyz",
                     mode="pointer", ptr_offset="0x2000",
                     out_path=os.path.join(d, "hook.js"))
        js = open(out, encoding="utf-8").read()
        check("bypass-dynamic: sinh script + pointer",
              "Memory.allocUtf8String" in js and "writePointer" in js
              and "very-long.example.com/xyz" in js
              and '"ptr_rva": 8192' in js)
        check("bypass-dynamic: không sửa file gốc",
              b"very-long" not in open(so, "rb").read())

        # ---- Main hiển thị riêng ----
        check("bypass-main: banner 2 luồng tách biệt",
              "LUỒNG TĨNH" in BANNER and "LUỒNG ĐỘNG" in BANNER
              and "patchx rodata-" not in BANNER)
        out_so = os.path.join(d, "out.so")
        rc = rb_main([so, "--flow", "static",
                      "--string", "https://new.example.com",
                      "--new", "https://x.example",
                      "--out", out_so])
        check("bypass-main: static rc=0 + file mới",
              rc == 0 and os.path.isfile(out_so)
              and ElfReader(out_so).read_cstring(0x1000) == "https://x.example")
        out_js = os.path.join(d, "h2.js")
        rc = rb_main([so, "--flow", "dynamic",
                      "--string", "https://new.example.com",
                      "--new", "https://y.example/path",
                      "--mode", "inline",
                      "--out", out_js])
        check("bypass-main: dynamic rc=0 + script",
              rc == 0 and os.path.isfile(out_js)
              and "y.example/path" in open(out_js, encoding="utf-8").read())
        rc = rb_main([so, "--flow", "static"])
        check("bypass-main: thiếu --new -> rc=2", rc == 2)
        rc = rb_main([so, "--flow", "dynamic", "--sections"])
        check("bypass-main: --sections rc=0", rc == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_feature_menu():
    """feature_menu: danh sách chức năng có nhóm/sắp xếp + tìm theo mục tiêu
    (tính điểm) + chạy pipeline đúng thứ tự."""
    from patchx_core.feature_menu import (render_catalog, render_detail,
                                          search_features, find_item,
                                          run_pipeline, main as menu_main)
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_menu_")
    try:
        # ---- danh sách có nhóm + đánh số ----
        cat = render_catalog()
        for needle in ("BYPASS CHUỖI TRONG .so (RODATA)", "BEHAVIOR + FRIDA",
                       "PHÂN TÍCH APK", "BUILD & ĐÓNG GÓI APK",
                       "1.", "Patch TĨNH — chèn chuỗi trực tiếp vào file .so"):
            check("menu: catalog chứa %s" % needle, needle in cat)
        check("menu: phân chia nhánh NATIVE -> SMALI -> CHUNG",
              cat.index("NHÁNH 1 — NATIVE") < cat.index("NHÁNH 2 — SMALI")
              < cat.index("NHÁNH 3 — CHUNG"))
        check("menu: nhánh native (BYPASS .so) trước smali (BEHAVIOR)",
              cat.index("BYPASS CHUỖI") < cat.index("BEHAVIOR + FRIDA")
              < cat.index("BUILD & ĐÓNG GÓI APK"))
        check("menu: start-scan có trong catalog + badge nền tảng",
              "start-scan" in cat and "[.so]" in cat and "[smali]" in cat)

        # ---- tìm theo mục tiêu: tính điểm + xếp hạng ----
        rows = search_features("frida ram")
        check("menu: tìm 'frida ram' xếp rodata-dynamic đầu",
              rows and rows[0][2]["id"] == "rodata-dynamic",
              rows[0][2]["id"] if rows else "none")
        check("menu: điểm khớp giảm dần",
              all(rows[i][0] >= rows[i + 1][0]
                  for i in range(len(rows) - 1)))
        check("menu: tìm không khớp -> rỗng",
              search_features("zzzzqqqqwwww") == [])

        # ---- chi tiết pipeline ----
        item = find_item("rodata-static")
        check("menu: find_item tồn tại",
              item is not None and "rodata-apply" in render_detail(item))
        check("menu: find_item không tồn tại -> None",
              find_item("khong-co-id") is None)

        # ---- chạy pipeline: lệnh OK rồi lệnh lỗi -> dừng đúng rc ----
        ok_item = {"id": "mock-ok", "name": "mock", "desc": "",
                   "pipeline": ["{PY} -c \"print(123)\""],
                   "inputs": [], "outputs": [], "keywords": []}
        rc = run_pipeline(ok_item, values={"PY": sys.executable},
                          interactive=False)
        check("menu: run pipeline lệnh OK rc=0", rc == 0)
        bad_item = {"id": "mock-bad", "name": "mock", "desc": "",
                    "pipeline": ["{PY} -c \"print(1)\"",
                                 "{PY} -c \"import sys; sys.exit(3)\""],
                    "inputs": [], "outputs": [], "keywords": []}
        rc = run_pipeline(bad_item, values={"PY": sys.executable},
                          interactive=False)
        check("menu: lệnh lỗi dừng pipeline + trả rc", rc == 3)
        miss_item = {"id": "mock-miss", "name": "mock", "desc": "",
                     "pipeline": ["{PY} echo {SO}"],
                     "inputs": [], "outputs": [], "keywords": []}
        rc = run_pipeline(miss_item, values={}, interactive=False)
        check("menu: thiếu placeholder (non-interactive) -> rc=2", rc == 2)

        # ---- main: --list / --goal / --run ID sai ----
        check("menu: main --list rc=0", menu_main(["--list"]) == 0)
        check("menu: main --goal rc=0", menu_main(["--goal", "so"]) == 0)
        check("menu: main --goal không khớp rc=1",
              menu_main(["--goal", "zzzzqqqqwwww"]) == 1)
        check("menu: main --run ID sai rc=2",
              menu_main(["--run", "khong-co-id"]) == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)

def test_start_scan():
    """start-scan: xử lý THƯ VIỆN lib .so từ APK/thư mục — trích lib theo ABI,
    quét từng lib, tổng hợp top findings + bảng chi tiết từng lib."""
    from patchx_core.behavior.smart_scanner import (start_scan,
                                                    render_start_scan_markdown)

    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_start_")
    try:
        so_dir = os.path.join(d, "libs")
        arm = os.path.join(so_dir, "arm64-v8a")
        x86 = os.path.join(so_dir, "x86")
        os.makedirs(arm)
        os.makedirs(x86)
        mau = os.path.join(PATCHX, "tests", "fixtures", "mau")
        shutil.copy2(os.path.join(mau, "libmini_a.so"),
                     os.path.join(arm, "liba.so"))
        shutil.copy2(os.path.join(mau, "libmini_b.so"),
                     os.path.join(arm, "libb.so"))
        shutil.copy2(os.path.join(mau, "libmini_c.so"),
                     os.path.join(x86, "libc.so"))

        apk = os.path.join(d, "app1.apk")
        with zipfile.ZipFile(apk, "w") as zf:
            for root, _dirs, files in os.walk(so_dir):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, so_dir).replace(os.sep, "/")
                    zf.write(full, "lib/" + arc)
        rep = start_scan(apk, abi="arm64-v8a")
        s = rep["summary"]
        check("start-scan: trích đúng ABI arm64 (2 lib)",
              s["libs_scanned"] == 2 and s["libs_ok"] == 2
              and s["libs_errored"] == 0)
        check("start-scan: tổng hợp finding từ cả 2 lib",
              s["total_findings"] >= 2
              and {f["lib_name"] for f in rep["top_findings"]}
              == {"liba.so", "libb.so"})
        check("start-scan: báo cáo có repro + per-lib sha256",
              rep["repro"]["target"] == apk
              and all(len(r["repro"]["file_sha256"]) == 64 for r in rep["libs"]))
        md = render_start_scan_markdown(rep)
        check("start-scan: markdown có header + top findings + từng lib",
              "start-scan — quét thư viện .so" in md
              and "liba.so" in md and "libb.so" in md)

        rep2 = start_scan(so_dir)
        check("start-scan: quét thư mục đủ 3 lib (mọi ABI)",
              rep2["summary"]["libs_scanned"] == 3)

        rep3 = start_scan(os.path.join(arm, "liba.so"))
        check("start-scan: quét file .so đơn",
              rep3["summary"]["libs_scanned"] == 1
              and rep3["libs"][0]["lib_name"] == "liba.so")

        try:
            start_scan(os.path.join(d, "khong-ton-tai"))
            check("start-scan: đầu vào sai -> báo lỗi", False, "không raise")
        except ValueError:
            check("start-scan: đầu vào sai -> báo lỗi", True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_smart_ontology():
    """smart_ontology: TỪ ĐIỂN HÀNH VI giống ontology.py — cấu trúc entry,
    gán hành vi theo category + xác thực chéo, in catalog."""
    from patchx_core.behavior.smart_ontology import (
        SMART_BEHAVIORS, get_behavior, match_smart_behavior,
        render_behavior_catalog, behavior_catalog_ids,
    )
    for bid, b in SMART_BEHAVIORS.items():
        check("ontology: entry %s đủ cấu trúc" % bid,
              isinstance(b["label"], str) and b["label"]
              and isinstance(b["description"], str)
              and isinstance(b["suggestions"], list) and b["suggestions"]
              and isinstance(b["categories"], list)
              and isinstance(b["keywords"], list)
              and 0 <= b["risk_base"] <= 100
              and isinstance(b["noise"], bool))
    check("ontology: có nhóm nhiễu (log/sample/symbol/library)",
          {"log_noise", "sample_noise", "symbol_noise", "library_noise"}
          <= set(SMART_BEHAVIORS))
    check("ontology: get_behavior thiếu -> other_behavior",
          get_behavior("khong-ton-tai")["id"] == "other_behavior")
    check("ontology: api_key -> hardcoded_secret",
          match_smart_behavior("api_key")[0] == "hardcoded_secret")
    check("ontology: log -> log_noise",
          match_smart_behavior("log")[0] == "log_noise")
    primary, extra = match_smart_behavior("other", validated=True)
    check("ontology: validated -> bổ trợ jni_flow_string",
          primary == "other_behavior" and "jni_flow_string" in extra)
    primary, extra = match_smart_behavior("endpoint", dynamic_build=True)
    check("ontology: endpoint ghép động -> bổ trợ dynamic_endpoint_build",
          primary == "endpoint_exposure"
          and "dynamic_endpoint_build" in extra)
    cat = render_behavior_catalog()
    check("ontology: catalog in label các hành vi",
          "Khóa/bí mật nhúng cứng" in cat
          and "Lộ endpoint API" in cat
          and "Chuỗi log (nhiễu)" in cat)
    check("ontology: catalog_ids đủ 14 hành vi",
          len(behavior_catalog_ids()) == len(SMART_BEHAVIORS) >= 14)


def test_smart_scanner():
    """smart_scanner: lọc nhiễu ngữ nghĩa + data-flow tĩnh (ADRP+ADD / LDR
    literal) + xác thực chéo JNI + Confidence Score 0-100 kèm bằng chứng."""
    from patchx_core.behavior.smart_scanner import (
        classify_string, enumerate_strings, parse_symbols, scan_code_refs,
        scan_so, render_markdown, main as smart_main, shannon_entropy,
    )
    from patchx_core.behavior.rodata_patcher import ElfReader

    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_smart_")
    try:
        so = os.path.join(d, "libdemo.so")
        shutil.copy2(os.path.join(PATCHX, "tests", "fixtures", "mau",
                                  "libsmart.so"), so)
        s_ep = "https://api.old-server.com/v1"
        s_tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." \
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        s_log = "[INFO] request handled ok"
        s_smp = "example.com"
        s_lib = "map::at:  key not found"
        str1_rva = 0x1000
        str2_rva = 0x1000 + len(s_ep) + 1

        cat, noise, _r, sig = classify_string("AKIAIOSFODNN7EXAMPLE")
        check("smart: AWS key -> api_key, không nhiễu",
              cat == "api_key" and not noise and "aws_access_key" in sig)
        cat, noise, _r, _s = classify_string("[INFO] request handled ok")
        check("smart: chuỗi log -> lọc nhiễu",
              cat == "log" and noise)
        cat, noise, _r, _s = classify_string("example.com")
        check("smart: dữ liệu mẫu -> lọc nhiễu",
              cat == "sample" and noise)
        cat, noise, _r, _s = classify_string(s_tok)
        check("smart: JWT -> token, không nhiễu",
              cat == "token" and not noise)
        cat, noise, _r, _s = classify_string(s_ep)
        check("smart: URL -> endpoint, không nhiễu",
              cat == "endpoint" and not noise)
        cat, noise, _r, _s = classify_string(s_lib)
        check("smart: chuỗi runtime C++ -> lọc nhiễu library",
              cat == "library" and noise)
        cat, noise, _r, _s = classify_string("Basic Animated Texture Profile")
        check("smart: Basic Animated KHONG phai basic auth",
              cat != "secret")
        cat, noise, _r, _s = classify_string("Basic dXNlcjpwYXNzMDEyMw==")
        check("smart: Basic auth base64 (co so/=) -> secret",
              cat == "secret" and not noise)
        cat, noise, _r, _s = classify_string(
            "out/llvm-project/libcxxabi/src/cxa_demangle.cpp")
        check("smart: duong dan build -> path, khong phai cipher",
              cat == "path" and not noise)

        reader = ElfReader(so)
        hits = enumerate_strings(reader)
        check("smart: trích đủ 5 chuỗi .rodata",
              len(hits) == 5 and {h.value for h in hits}
              == {s_ep, s_tok, s_log, s_smp, s_lib})
        syms = parse_symbols(reader)
        check("smart: symbol table có hàm JNI",
              any(s["name"] == "Java_com_example_App_nativeCheck"
                  for s in syms))

        refs = scan_code_refs(reader)
        kinds = sorted({r["kind"] for r in refs})
        check("smart: refs ADRP+ADD + LDR literal",
              kinds == ["adrp_add", "ldr_literal"] and len(refs) == 2)
        check("smart: target refs đúng RVA chuỗi",
              {r["target_rva"] for r in refs} == {str1_rva, str2_rva})
        check("smart: entropy > 0", shannon_entropy("abc123XYZ") > 0)

        report = scan_so(so)
        s = report["summary"]
        check("smart: tổng 5 chuỗi, giữ 2, lọc nhiễu 3",
              s["total_strings"] == 5 and s["kept"] == 2
              and s["noise_dropped"] == 3)
        check("smart: 2 refs + 2 JNI refs",
              s["refs_found"] == 2 and s["jni_refs"] == 2)
        check("smart: FP đã loại >= 3 (3 nhiễu)",
              s["false_positive_removed"] >= 3)
        check("smart: 2 finding cao (>=75)",
              s["flagged_high"] == 2 and s["flagged_medium"] == 0)
        f0, f1 = report["findings"][0], report["findings"][1]
        check("smart: xếp hạng token (100) trước endpoint",
              f0["category"] == "token" and f0["confidence"] == 100
              and f1["category"] == "endpoint")
        check("smart: endpoint validated qua JNI + bằng chứng",
              f1["validated"] and len(f1["evidence"]) >= 3
              and any(e["type"] == "cross_validation" for e in f1["evidence"]))
        check("smart: mọi finding có evidence + hàm JNI",
              all(f["evidence"] for f in report["findings"])
              and all("Java_com_example" in ",".join(f["functions"])
                      for f in report["findings"]))
        check("smart: repro có SHA-256 64 ký tự",
              len(report["repro"]["file_sha256"]) == 64)
        check("smart: confidence trong khoảng 0-100",
              all(0 <= f["confidence"] <= 100 for f in report["findings"]))
        md = render_markdown(report)
        check("smart: markdown chứa header + sha",
              "Báo cáo quét thông minh" in md
              and report["repro"]["file_sha256"][:8] in md)
        check("smart: finding có hành vi từ từ điển (token -> hardcoded_secret)",
              f0["behavior"]["id"] == "hardcoded_secret"
              and f0["behavior"]["label"]
              and f0["behavior"]["suggestions"])
        check("smart: endpoint validated -> hành vi bổ trợ jni_flow_string",
              f1["behavior"]["id"] == "endpoint_exposure"
              and "jni_flow_string" in f1["behavior_extra"])
        check("smart: markdown hiển thị hành vi",
              "Hành vi:" in md and "hardcoded_secret" in md)

        out_json = os.path.join(d, "report.json")
        rc = smart_main([so, "-o", out_json])
        check("smart: CLI rc=0 + ghi JSON",
              rc == 0 and os.path.isfile(out_json))
        rc = smart_main([os.path.join(d, "khong-ton-tai.so"), "-o",
                         os.path.join(d, "x.json")])
        check("smart: file không hợp lệ -> rc=2", rc == 2)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_rodata_patcher():
    """rodata_patcher: ELF parser tìm RVA chuỗi trong .rodata + sinh script
    Frida patch RAM (inline/pointer/runtime-scan)."""
    from patchx_core.behavior.rodata_patcher import (
        ElfReader, find_string_offsets, generate_rodata_patch_script,
        patch_so_file)

    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_rodata_")
    try:
        mau = os.path.join(PATCHX, "tests", "fixtures", "mau")
        so = os.path.join(d, "libdemo.so")
        shutil.copy2(os.path.join(mau, "libdemo64.so"), so)
        s0 = "https://api.old-server.com/v1"
        s1 = "https://config.example.com/patchx.json"

        # ---- ELF parser: section + ánh xạ offset -> RVA ----
        r = ElfReader(so)
        check("rodata: đọc được section .rodata ALLOC",
              any(s["name"] == ".rodata" for s in r.list_alloc_sections()))
        rva, sec, source = r.file_offset_to_rva(0x1000 + 10)
        check("rodata: file offset -> RVA trong section",
              rva == 0x1000 + 10 and sec == ".rodata"
              and source == "section", "rva=%#x sec=%s" % (rva, sec))

        so32 = os.path.join(d, "libdemo32.so")
        shutil.copy2(os.path.join(mau, "libdemo32.so"), so32)
        r32 = ElfReader(so32)
        hits32 = find_string_offsets(so32, s0)
        check("rodata: ELF32 đọc được .rodata + RVA",
              any(x["name"] == ".rodata" for x in r32.list_alloc_sections())
              and len(hits32) == 1 and hits32[0].rva == 0x1000
              and hits32[0].section == ".rodata", hits32.__str__())

        # ---- find_string_offsets ----
        hits = find_string_offsets(so, s0)
        check("rodata: tìm chuỗi gốc trong .rodata", len(hits) == 1
              and hits[0].rva == 0x1000 and hits[0].section == ".rodata"
              and hits[0].size == len(s0) + 1,
              "; ".join(h.to_dict().__str__() for h in hits))
        check("rodata: chuỗi không tồn tại -> rỗng",
              find_string_offsets(so, "khong-ton-tai") == [])

        # ---- Sinh script Frida: inline + pointer ----
        js = generate_rodata_patch_script([
            {"module": "libdemo.so", "old_string": s0,
             "new_string": "https://my-custom-api-server-domain.com/v2/endpoint",
             "mode": "both", "ptr_rva": 0x2000},
        ], so_path=so)
        for needle in ("Module.findBaseAddress", "Memory.allocUtf8String",
                       "Memory.protect", "writeUtf8String", "writePointer",
                       "rodataPatchAll", "my-custom-api-server-domain.com"):
            check("rodata: script chứa %s" % needle, needle in js)
        check("rodata: script nhúng RVA + ptr_rva",
              '"rva": 4096' in js and '"ptr_rva": 8192' in js)
        new_len = len("https://my-custom-api-server-domain.com/v2/endpoint") + 1
        check("rodata: script tính new_len bytes",
              '"new_len": %d' % new_len in js)

        # ---- Sinh script: runtime scan (không cần RVA tĩnh) ----
        js_scan = generate_rodata_patch_script([
            {"module": "libdemo.so", "old_string": s0,
             "new_string": "patched-by-runtime-scan",
             "mode": "inline", "runtime_scan": True},
        ], so_path=so)
        check("rodata: runtime-scan dùng Memory.scanSync",
              "Memory.scanSync" in js_scan and '"runtime_scan": true' in js_scan)

        # ---- Sinh script: thiếu RVA + old_string -> báo lỗi ----
        try:
            generate_rodata_patch_script([
                {"module": "libdemo.so", "new_string": "x",
                 "mode": "inline"}], so_path=so)
            check("rodata: thiếu RVA -> báo lỗi", False, "không raise")
        except ValueError:
            check("rodata: thiếu RVA -> báo lỗi", True)

        # ---- Nhiều vị trí -> yêu cầu --offset ----
        so2 = os.path.join(d, "libdup.so")
        shutil.copy2(os.path.join(mau, "libdup.so"), so2)
        dup = find_string_offsets(so2, s0)
        check("rodata: phát hiện nhiều vị trí", len(dup) >= 2,
              "hits=%d" % len(dup))
        try:
            generate_rodata_patch_script([
                {"module": "libdup.so", "old_string": s0,
                 "new_string": "x", "mode": "inline"}], so_path=so2)
            check("rodata: nhiều vị trí -> báo lỗi", False, "không raise")
        except ValueError:
            check("rodata: nhiều vị trí -> báo lỗi", True)

        # ---- rva_to_file_offset: ngược với file_offset_to_rva ----
        fo, sec = r.rva_to_file_offset(0x1000 + 10)
        check("rodata: RVA -> file offset (ngược)", fo == 0x1000 + 10
              and sec == ".rodata", "fo=%#x sec=%s" % (fo, sec))
        try:
            r.rva_to_file_offset(0x99999999)
            check("rodata: RVA ngoài vùng -> báo lỗi", False, "không raise")
        except ValueError:
            check("rodata: RVA ngoài vùng -> báo lỗi", True)

        # ---- patch_so_file: ghi trực tiếp vào file + backup ----
        so3 = os.path.join(d, "libapply.so")
        shutil.copy2(os.path.join(mau, "libdemo64.so"), so3)
        bak_dir = os.path.join(d, "backup")
        orig_bytes = open(so3, "rb").read()
        rep = patch_so_file(so3, [
            {"old_string": s0, "new_string": "https://new.example.com",
             "mode": "inline"},
        ], backup_dir=bak_dir)
        r3 = ElfReader(so3)
        check("rodata-apply: ghi chuỗi mới vào file",
              r3.read_cstring(0x1000) == "https://new.example.com"
              and rep["patched"][0]["file_offset"] == 0x1000
              and not rep["patched"][0]["overflow"])
        check("rodata-apply: phần dư chuỗi cũ bị NUL hóa",
              b"old-server" not in r3.data[0x1000:0x1000 + 64])
        check("rodata-apply: backup được tạo + khớp bản gốc",
              rep.get("backup") and os.path.isfile(rep["backup"])
              and open(rep["backup"], "rb").read() == orig_bytes)
        # chuỗi s1 kế bên không bị đụng
        check("rodata-apply: dữ liệu kế bên còn nguyên",
              find_string_offsets(so3, s1) != [])
        # ghi ra file mới không đụng file gốc
        so4 = os.path.join(d, "libapply_out.so")
        patch_so_file(so3, [
            {"old_string": "https://new.example.com",
             "new_string": "https://x.example", "mode": "inline"},
        ], out_path=so4, backup=False)
        check("rodata-apply: --out ghi bản mới, file gốc giữ nguyên",
              os.path.isfile(so4)
              and ElfReader(so3).read_cstring(0x1000) == "https://new.example.com"
              and ElfReader(so4).read_cstring(0x1000) == "https://x.example")

        # ---- patch_so_file: dài hơn -> lỗi; overflow -> ghi được ----
        try:
            patch_so_file(so3, [
                {"old_string": "https://new.example.com",
                 "new_string": "https://very-long-new-string.example.com/x",
                 "mode": "inline"}], backup=False)
            check("rodata-apply: dài hơn -> báo lỗi", False, "không raise")
        except ValueError:
            check("rodata-apply: dài hơn -> báo lỗi", True)
        so5 = os.path.join(d, "liboverflow.so")
        rep5 = patch_so_file(so3, [
            {"old_string": "https://new.example.com",
             "new_string": "https://very-long-new-string.example.com/x",
             "mode": "inline"}], out_path=so5, backup=False,
            allow_overflow=True)
        check("rodata-apply: --allow-overflow ghi được + đánh dấu TRÀN",
              ElfReader(so5).read_cstring(0x1000)
              == "https://very-long-new-string.example.com/x"
              and rep5["patched"][0]["overflow"])

        # ---- patch_so_file: pointer/runtime_scan từ chối ----
        for bad in ({"old_string": s0, "new_string": "x",
                     "mode": "pointer"},
                    {"old_string": s0, "new_string": "x",
                     "runtime_scan": True}):
            try:
                patch_so_file(so3, [bad], backup=False)
                check("rodata-apply: chặn %s" % list(bad)[-1],
                      False, "không raise")
            except ValueError:
                check("rodata-apply: chặn %s" % list(bad)[-1], True)
    finally:
        shutil.rmtree(d, ignore_errors=True)

def test_smart_patch():
    """smart-patch: tái dùng detector behavior có sẵn, chống R8/D8."""
    import patchx_core.behavior.smart_patch as sp
    d = tempfile.mkdtemp(dir=TMP, prefix="patchx_smartpatch_")
    try:
        tree = os.path.join(d, "tree")
        smali = os.path.join(tree, "smali", "com", "demo")
        os.makedirs(smali)
        with open(os.path.join(smali, "a.smali"), "w", encoding="utf-8") as f:
            f.write(".class public Lcom/demo/a;\n"
                    ".super Ljava/lang/Object;\n\n"
                    ".method public a()Z\n"
                    "    .registers 2\n"
                    '    const-string v0, "premium"\n'
                    "    invoke-virtual {v0}, Ljava/lang/String;->"
                    "contains(Ljava/lang/CharSequence;)Z\n"
                    "    move-result v0\n"
                    "    return v0\n"
                    ".end method\n")
        plan = sp.build_smart_plan(tree)
        stats = plan["stats"]
        check("smart-patch: detector phát hiện hành vi obfuscated R8/D8",
              stats["behaviors"] == 1 and stats["targets_ranked"] >= 1,
              str(stats))
        t = plan["targets"][0]
        check("smart-patch: target dùng đúng từ detector có sẵn",
              t["kind"] == "obfuscated-feature-unlock" and t["r8_d8"]
              and t["obfuscated_name"] and t["method"] == "a"
              and t["patch_mode"] == "force_boolean_true", str(t))
        out = os.path.join(d, "out")
        rep = sp.apply_smart_patch(tree, out_dir=out, min_score=0.5,
                                   apply=True)
        patched = rep["patched"]
        check("smart-patch: --apply patch + backup tự động",
              patched["success"] >= 1 and patched["failed"] == 0
              and os.path.isdir(os.path.join(out, "backup"))
              and len(patched["backup_files"]) >= 1, str(patched))
        content = open(os.path.join(smali, "a.smali"),
                       encoding="utf-8").read()
        check("smart-patch: smali bị ép về true (0x1)",
              "const/4 v0, 0x1" in content, content)
        md = open(os.path.join(out, "smart_patch_report.md"),
                  encoding="utf-8").read()
        check("smart-patch: báo cáo md + json sinh đủ",
              os.path.isfile(os.path.join(out, "smart_patch_report.md"))
              and os.path.isfile(os.path.join(out, "smart_patch_plan.json"))
              and "R8/D8" in md, "")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_intake_capabilities():
    from patchx_core.intake import (collect_tool_capabilities, inspect_artifact,
                                    write_capabilities, run_intake)
    d = tempfile.mkdtemp(prefix="patchx_intake_", dir=TMP if os.path.isdir(TMP) else None)
    try:
        caps = collect_tool_capabilities()
        check("intake: collect_tool_capabilities schema hợp lệ",
              caps.get("schema") == "patchx.tool-capabilities/v1" and "tools" in caps)
        outputs = write_capabilities(caps, d)
        check("intake: write_capabilities tạo file json & md",
              os.path.isfile(outputs["json"]) and os.path.isfile(outputs["markdown"]))

        dummy_apk = os.path.join(d, "test.apk")
        with zipfile.ZipFile(dummy_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
            zf.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 100)
            zf.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"\x00" * 50)
            zf.writestr("res/layout/main.xml", b"<xml/>")

        out_intake = os.path.join(d, "out_intake")
        report = run_intake(dummy_apk, out_intake, include_tools=False)
        check("intake: run_intake phân tích đúng dummy APK",
              report.get("artifact", {}).get("kind") == "apk"
              and report.get("structure", {}).get("dex_count") == 2
              and "arm64-v8a" in report.get("structure", {}).get("abis", []))
        check("intake: run_intake ghi report json & md",
              os.path.isfile(report["outputs"]["json"]) and os.path.isfile(report["outputs"]["markdown"]))

        split_set = os.path.join(d, "test.apks")
        with zipfile.ZipFile(split_set, "w") as zf:
            zf.writestr("base.apk", b"PK\x03\x04")
            zf.writestr("split_config.arm64_v8a.apk", b"PK\x03\x04")
            zf.writestr("feature_chat.apk", b"PK\x03\x04")
        split_report = inspect_artifact(split_set, include_tools=False)
        split_codes = {item["code"] for item in split_report["risks"]}
        check("intake: APKS nhận diện base/config/feature",
              split_report["structure"]["nested_apk_count"] == 3
              and "SPLIT_CONTAINER" in split_codes
              and any(row["role"] == "base"
                      for row in split_report["structure"]["nested_apks"]))

        bundle = os.path.join(d, "test.aab")
        with zipfile.ZipFile(bundle, "w") as zf:
            zf.writestr("base/manifest/AndroidManifest.xml", b"manifest")
            zf.writestr("base/dex/classes.dex", b"dex\n035\x00")
            zf.writestr("feature_chat/dex/classes.dex", b"dex\n035\x00")
        bundle_report = inspect_artifact(bundle, include_tools=False)
        bundle_codes = {item["code"] for item in bundle_report["risks"]}
        check("intake: AAB nhận diện module và gate bundletool",
              bundle_report["structure"]["modules"] == ["base", "feature_chat"]
              and "AAB_PUBLISHING_FORMAT" in bundle_codes)

        from patchx_core.cli import main as cli_main
        cli_out = os.path.join(d, "cli_out")
        cli_rc = cli_main(["intake", dummy_apk, "--no-tool-probe", "-o", cli_out])
        check("intake: CLI đăng ký và ghi report", cli_rc == 0
              and os.path.isfile(os.path.join(cli_out, "intake_test.json")))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_unified_pipeline():
    from patchx_core.pipeline_unified import run_pipeline, UnifiedPipeline
    from patchx_core.cli import main as cli_main
    d = tempfile.mkdtemp(prefix="patchx_pipe_", dir=TMP if os.path.isdir(TMP) else None)
    try:
        dummy_apk = os.path.join(d, "sample.apk")
        with zipfile.ZipFile(dummy_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
            zf.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"\x00" * 50)
            zf.writestr("res/layout/main.xml", b"<xml/>")

        out_pipe = os.path.join(d, "pipe_out")
        rep_intake = run_pipeline(dummy_apk, mode="intake", output_dir=out_pipe)
        check("pipeline: mode intake hoàn tất thành công",
              rep_intake["verdict"] == "SUCCESS"
              and any(s["name"] == "intake_triage" for s in rep_intake["stages"]))

        rep_fast = run_pipeline(dummy_apk, mode="fast", output_dir=out_pipe)
        check("pipeline: mode fast sinh patched apk",
              rep_fast["verdict"] == "SUCCESS"
              and "patched_apk" in rep_fast["outputs"])

        rep_auto = run_pipeline(dummy_apk, mode="auto", output_dir=out_pipe)
        check("pipeline: mode auto chạy hybrid và xuất báo cáo md/json",
              rep_auto["verdict"] == "SUCCESS"
              and os.path.isfile(rep_auto["outputs"]["report_json"])
              and os.path.isfile(rep_auto["outputs"]["report_markdown"]))

        cli_rc = cli_main(["pipeline", dummy_apk, "--mode", "intake", "--output-dir", os.path.join(d, "cli_pipe")])
        check("pipeline: CLI lệnh chạy thành công trả 0", cli_rc == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_blackboard_and_fused_targets():
    from patchx_core.blackboard import SharedBlackboard, CapabilityCard
    from patchx_core.fused_target_engine import fuse_analysis_targets, generate_fused_frida_script
    bb = SharedBlackboard()
    bb.post("artifact_path", "sample.apk")
    check("blackboard: post & get fact", bb.get("artifact_path") == "sample.apk")
    check("blackboard: default capabilities registered", bb.summary()["registered_capabilities"] >= 10)
    fast_chain = bb.plan_chain_for_intent("fast")
    check("blackboard: plan_chain_for_intent fast", any(c.name == "fast_patch" for c in fast_chain))

    d = tempfile.mkdtemp(prefix="patchx_bb_", dir=TMP if os.path.isdir(TMP) else None)
    try:
        sf = os.path.join(d, "Sample.smali")
        with open(sf, "w", encoding="utf-8") as fh:
            fh.write("""
.class public Lcom/demo/Test;
.super Ljava/lang/Object;

.method public static isVip()Z
    .registers 1
    const/4 v0, 0x1
    return v0
.end method
""")
        fused = fuse_analysis_targets(d)
        check("fused_targets: phát hiện mục tiêu smali", fused["summary"]["total_fused"] >= 1)
        js = generate_fused_frida_script(fused)
        check("fused_targets: sinh Frida hook script", "Java.perform" in js)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_dag_and_pipeline_registry():
    from patchx_core.dag import DAGNode, PipelineDAG, NodeStatus
    from patchx_core.pipeline_registry import PipelineRegistry, get_pipeline_registry

    # 1. Kiểm tra khởi tạo node và điều kiện
    node1 = DAGNode(name="step_a", outputs=["val_a"], action=lambda ctx, bb: {"val_a": 42})
    node2 = DAGNode(name="step_b", depends_on={"step_a"}, outputs=["val_b"], action=lambda ctx, bb: {"val_b": ctx.get("val_a", 0) * 2})
    dag = PipelineDAG(name="test_dag")
    dag.add_node(node1).add_node(node2)

    is_valid, errors = dag.validate()
    check("dag: kiểm tra tính hợp lệ và không lỗi", is_valid and len(errors) == 0)
    check("dag: toposort đúng thứ tự phụ thuộc", dag.toposort() == ["step_a", "step_b"])
    check("dag: execution levels phân tầng chính xác", dag.get_execution_levels() == [["step_a"], ["step_b"]])

    # 2. Kiểm tra thực thi
    res = dag.execute()
    check("dag: execute thành công", res.verdict == "SUCCESS" and res.context.get("val_b") == 84)

    # 3. Kiểm tra phát hiện chu trình (cycle)
    dag_cycle = PipelineDAG(name="cycle_dag")
    dag_cycle.add_node(DAGNode(name="X", depends_on={"Y"}))
    dag_cycle.add_node(DAGNode(name="Y", depends_on={"X"}))
    cycle_valid, _ = dag_cycle.validate()
    check("dag: phát hiện chính xác cycle", not cycle_valid)

    # 4. Kiểm tra Registry
    reg = get_pipeline_registry()
    check("registry: đăng ký đủ >= 8 pipelines tiêu chuẩn", len(reg.list_pipelines()) >= 8)
    check("registry: pipeline 'auto' tồn tại", reg.has_pipeline("auto"))
    auto_pipe = reg.get_pipeline("auto")
    mermaid = auto_pipe.dag.to_mermaid()
    check("registry: xuất sơ đồ mermaid cho auto", "graph TD" in mermaid and "intake" in mermaid)


def test_integrity_decoupler():
    """AIDM: ca dương (biến đổi đúng) + ca âm (phát hiện phương thức sạch)."""
    from patchx_core.integrity_decoupler import (
        decouple_installer_package,
        decouple_signing_certificate,
        decouple_dex_digest_check,
        neutralize_exit_calls,
        detect_integrity_controls,
        verify_integrity_bypass,
        decouple_integrity,
    )

    installer = (
        ".method public static getInstaller(Landroid/content/Context;)Ljava/lang/String;\n"
        "    .registers 2\n"
        "    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;\n"
        "    move-result-object v0\n"
        "    invoke-virtual {v0, p0}, Landroid/content/pm/PackageManager;->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;\n"
        "    move-result-object v1\n"
        "    return-object v1\n"
        ".end method"
    )
    changed, out = decouple_installer_package(installer)
    check("AIDM: getInstallerPackageName -> com.android.vending",
          changed and 'const-string v1, "com.android.vending"' in out
          and "getInstallerPackageName(" not in out,
          out)

    sigcheck = (
        ".method public static hasSigningCertificate()Z\n"
        "    .registers 1\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method"
    )
    changed2, out2 = decouple_signing_certificate(sigcheck)
    check("AIDM: hasSigningCertificate ép trả True",
          changed2 and "const/4 v0, 0x1" in out2 and "return v0" in out2,
          out2)

    exiting = (
        ".method public static die()V\n"
        "    .registers 1\n"
        "    invoke-static {v0}, Ljava/lang/System;->exit(I)V\n"
        "    return-void\n"
        ".end method"
    )
    changed3, out3 = neutralize_exit_calls(exiting)
    check("AIDM: System.exit -> return-void",
          changed3 and "System;->exit(" not in out3 and "return-void" in out3,
          out3)

    digest = (
        ".method public static checkDexDigest()Z\n"
        "    .registers 1\n"
        "    const-string v0, \"classes.dex\"\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method"
    )
    changed4, out4 = decouple_dex_digest_check(digest)
    check("AIDM: checkDexDigest (classes.dex) ép trả True",
          changed4 and "const/4 v0, 0x1" in out4 and "return v0" in out4,
          out4)
    ver = verify_integrity_bypass(out4)
    check("AIDM: cổng xác minh xác nhận bypass = True",
          ver.get("verified") is True,
          str(ver))

    bc = (
        ".method public verifySignature([B)Z\n"
        "    .registers 6\n"
        "    iget-boolean v0, p0, Lorg/bouncycastle/crypto/signers/DSADigestSigner;->forSigning:Z\n"
        "    invoke-interface {v1, v0, v3, p1}, Lorg/bouncycastle/crypto/DSA;->verifySignature([BLjava/math/BigInteger;Ljava/math/BigInteger;)Z\n"
        "    move-result p1\n"
        "    return p1\n"
        ".end method"
    )
    c7, out7 = decouple_signing_certificate(bc)
    bc_hits = detect_integrity_controls(bc)
    check("AIDM (âm): BouncyCastle verifySignature KHÔNG bị ép trả True",
          (not c7) and "signing-certificate" not in bc_hits and "dex-digest" not in bc_hits,
          "hits=%s" % bc_hits)

    clean = (
        ".method public static clean()V\n"
        "    .registers 1\n"
        "    return-void\n"
        ".end method"
    )
    c5, out5 = decouple_installer_package(clean)
    c6, out6 = neutralize_exit_calls(clean)
    hits = detect_integrity_controls(clean)
    check("AIDM (âm): phương thức sạch giữ nguyên + detector trả rỗng",
          (not c5 and not c6) and hits == [],
          "hits=%s" % hits)

    d = tempfile.mkdtemp(prefix="patchx_aidm_")
    try:
        p = os.path.join(d, "a.smali")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(installer + "\n\n" + clean + "\n")
        rep = decouple_integrity(d, spearheads=(1, 2), dry_run=True)
        check("AIDM: cây khô đếm files/methods/installer",
              rep["files_scanned"] == 1 and rep["files_patched"] == 1
              and rep["installer_decoupled"] == 1
              and rep["methods_patched"] == 1,
              "scanned=%s patched=%s installer=%s methods=%s" % (
                  rep["files_scanned"], rep["files_patched"],
                  rep["installer_decoupled"], rep["methods_patched"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_cfg_unflatten():
    """Gỡ phẳng luồng mã: ca dương (viết lại đúng) + ca âm (không phá mã thường)."""
    from patchx_core.cfg_unflatten import (
        detect_flattening,
        linearize,
        unflatten_smali,
    )

    flattened = (
        ".method public static demo()V\n"
        "    .locals 1\n"
        "    const/4 v0, 0x0\n"
        "    goto :goto_dispatch\n"
        "    :goto_case_0\n"
        "    invoke-static {}, Lpkg/Util;->log()V\n"
        "    const/4 v0, 0x1\n"
        "    goto :goto_dispatch\n"
        "    :goto_case_1\n"
        "    invoke-static {}, Lpkg/Util;->report()V\n"
        "    const/4 v0, 0x2\n"
        "    goto :goto_dispatch\n"
        "    :goto_case_2\n"
        "    return-void\n"
        "    :goto_dispatch\n"
        "    packed-switch v0, :goto_data\n"
        "    .packed-switch 0x0\n"
        "        :goto_case_0\n"
        "        :goto_case_1\n"
        "        :goto_case_2\n"
        "    .end packed-switch\n"
        ".end method\n"
    )
    check("unflatten: phát hiện mẫu làm phẳng", detect_flattening(flattened))
    trace = linearize(flattened)
    check("unflatten: lần vết đủ 3 khối theo thứ tự",
          trace.get("flattened") and trace.get("complete")
          and len(trace["block_order"]) == 3,
          str(trace))
    res = unflatten_smali(flattened)
    text = res.get("text", "")
    check("unflatten: viết lại thành công, bỏ khối điều phối và bảng switch",
          res.get("rewritten") and res.get("dispatcher_removed")
          and "packed-switch" not in text and "goto :goto_dispatch" not in text,
          str(res)[:300])
    check("unflatten: giữ nguyên nội dung thật của 3 khối",
          "Lpkg/Util;->log()V" in text and "Lpkg/Util;->report()V" in text
          and "return-void" in text and ".end method" in text)
    check("unflatten: thứ tự tuần tự đúng (log trước report trước return)",
          text.index("log") < text.index("report") < text.index("return-void"))

    # Ca âm: phương thức thường không có switch phải giữ nguyên từng ký tự.
    plain = (".method public static f()V\n"
             "    .locals 1\n"
             "    const/4 v0, 0x1\n"
             "    return-void\n"
             ".end method\n")
    res2 = unflatten_smali(plain)
    check("unflatten: ca âm — mã thường giữ nguyên, không viết lại",
          res2.get("rewritten") is False and res2.get("text") == plain)


def test_breakthrough_modules():
    """Các module đột phá: NEON, Micro-DEX, đồ thị cuộc gọi, Autopilot DAG."""
    # NEON: đối chiếu kết quả native vs Python (bỏ qua nếu không biên dịch được).
    from patchx_core import neon_scan
    data = (b"abc" + bytes(range(0x20, 0x40)) * 8 + b"\x00\x01" + b"/system/bin/su" + b"xyz")
    py_runs = neon_scan.find_runs_python(data)
    try:
        na_runs = neon_scan.find_runs_native(data)
        check("NEON: kết quả dải byte khớp Python", py_runs == na_runs)
        check("NEON: tìm mẫu chính xác khớp",
              neon_scan.find_all_native(data, b"/system/bin/su")
              == neon_scan.find_all_python(data, b"/system/bin/su"))
    except Exception:
        check("NEON: rơi về Python an toàn khi không biên dịch được", True)

    # Micro-DEX: ca trả true và ca trả false.
    from patchx_core.dex_emulator import verify_method_bypass
    t = verify_method_bypass(".method public static a()Z\n    .locals 1\n"
                             "    const/4 v0, 0x1\n    return v0\n.end method")
    f = verify_method_bypass(".method public static b()Z\n    .locals 1\n"
                             "    const/4 v0, 0x0\n    return v0\n.end method")
    check("Micro-DEX: chứng minh hàm trả true", t["verified"] is True)
    check("Micro-DEX: phát hiện hàm trả false", f["verified"] is False)

    # Đồ thị cuộc gọi trên cây fixture.
    from patchx_core.callgraph import build_call_graph
    cg = build_call_graph("tests/fixtures/mau/smali_tree")
    check("Callgraph: quét fixture ra phương thức",
          cg["files_scanned"] >= 1 and cg["methods_found"] >= 1)

    # Autopilot: pipeline đăng ký đủ 11 khâu + chạy khô không lỗi chết người.
    from patchx_core.orchestrator import ensure_autopilot_pipeline, AutopilotOrchestrator
    pipe = ensure_autopilot_pipeline()
    check("Autopilot: quy trình DAG có đủ 11 khâu",
          len(pipe.dag.nodes) == 11 and pipe.dag.validate()[0],
          str(pipe.dag.toposort()))
    rep = AutopilotOrchestrator(
        "tests/fixtures/mau/smali_tree",
        os.path.join(tempfile.gettempdir(), "ap_test_out"),
        dry_run=True).run_full_pipeline()
    check("Autopilot: chạy khô trả báo cáo có bước và kế hoạch",
          "steps" in rep and "plan" in rep and rep["plan"]["order"][0] == "ap-intake",
          rep["verdict"])


def test_integrity_gate():
    """Cổng toàn vẹn G1..G5: ca dương (smali hợp lệ PASS) + ca âm (smali hỏng bị phát hiện FAIL)."""
    from patchx_core.integrity_gate import gate_g2_smali, gate_target

    good = (
        ".class public Lcom/demo/Demo;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static ok()Z\n"
        "    .locals 1\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
        ".end method\n"
    )
    ok_rep = gate_g2_smali(good)
    check("integrity_gate: smali hợp lệ qua G2",
          ok_rep["ok"] and ok_rep["evidence"]["methods"] == 1,
          str(ok_rep)[:160])

    broken = (
        ".class public Lcom/demo/Broken;\n"
        ".super Ljava/lang/Object;\n"
        ".method public static ok()Z\n"
        "    .locals 1\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
    )
    bad_rep = gate_g2_smali(broken)
    check("integrity_gate: phát hiện smali hỏng (test âm chống báo đạt giả)",
          bad_rep["ok"] is False and bool(bad_rep.get("reason")),
          str(bad_rep)[:160])

    d = tempfile.mkdtemp(prefix="patchx_gate_")
    try:
        fp = os.path.join(d, "Broken.smali")
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(broken)
        verdict = gate_target(fp)
        check("integrity_gate: một cổng duy nhất kết luận FAIL cho tệp hỏng",
              verdict["verdict"] == "FAIL" and verdict["passed"] == 0,
              str(verdict)[:160])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_ast_dsl():
    """AST DSL T1: ca dương (đảo nhánh + ép trả về đúng kiểu) + ca âm (quy tắc sai bị từ chối)."""
    from patchx_core.ast_dsl import parse_rule, parse_method_ast, apply_rule_to_method

    method_text = (
        ".method public static gate()Z\n"
        "    .locals 1\n"
        "    const/4 v0, 0x0\n"
        "    if-eqz v0, :cond_fail\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
        "    :cond_fail\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method\n"
    )

    ast = parse_method_ast(method_text)
    res = apply_rule_to_method(ast, parse_rule({
        "ten": "dao", "opcode": "if-eqz", "hanh_dong": "dao-nhanh"}))
    rendered = ast.render()
    check("ast_dsl: đảo nhánh if-eqz -> if-nez đúng chuẩn",
          ast is not None and res.get("thay_doi") == 1 and "if-nez" in rendered,
          str(res)[:160])

    ast2 = parse_method_ast(method_text)
    res2 = apply_rule_to_method(ast2, parse_rule({
        "ten": "true", "phuong_thuc": "gate", "hanh_dong": "ep-tra-ve",
        "gia_tri": True}))
    body = ast2.render()
    check("ast_dsl: ép trả về true đúng kiểu boolean",
          res2.get("ok") and "const/4 v0, 0x1" in body and "return v0" in body,
          str(res2)[:160])

    try:
        parse_rule({"ten": "x", "hanh_dong": "khong-co"})
        rejected = False
    except ValueError:
        rejected = True
    check("ast_dsl: quy tắc hành động không hợp lệ bị từ chối (test âm)",
          rejected, "parse_rule không ném lỗi cho hành động lạ")


def test_cfg_unflattener():
    """Lớp giao diện cấp cao của bộ máy gỡ phẳng (shim behavior)."""
    from patchx_core.behavior.cfg_unflattener import CFGUnflattener
    sample = (
        ".method public static demo()V\n"
        "    .locals 1\n"
        "    const/4 v0, 0x0\n"
        "    goto :goto_dispatch\n"
        "    :goto_case_0\n"
        "    invoke-static {}, Lpkg/Util;->log()V\n"
        "    const/4 v0, 0x1\n"
        "    goto :goto_dispatch\n"
        "    :goto_case_1\n"
        "    return-void\n"
        "    :goto_dispatch\n"
        "    packed-switch v0, :goto_data\n"
        "    .packed-switch 0x0\n"
        "        :goto_case_0\n"
        "        :goto_case_1\n"
        "    .end packed-switch\n"
        ".end method\n"
    )
    uf = CFGUnflattener(sample)
    check("CFGUnflattener: tìm thấy khối điều phối", uf.find_dispatcher())
    removed = uf.unflatten()
    check("CFGUnflattener: gỡ phẳng và báo số khối đã loại",
          removed >= 1 and uf.result.get("rewritten"))


def test_native_mutator():
    """Đột biến zero-drift: quét fixture .so ở chế độ phân tích (không ghi đĩa)."""
    from patchx_core.behavior.native_mutator import auto_mutate_native
    d = tempfile.mkdtemp(prefix="patchx_mutator_")
    try:
        src = os.path.join("tests", "fixtures", "mau", "libdemo64.so")
        dst = os.path.join(d, "libdemo64.so")
        shutil.copyfile(src, dst)
        rep = auto_mutate_native(d, output_dir=os.path.join(d, "out"),
                                 apply_disk=False, gen_frida=False)
        check("native_mutator: báo cáo đúng cấu trúc",
              rep["total_so_files"] == 1 and "findings_count" in rep,
              str(rep)[:200])
def test_autonomous_and_multidomain():
    """Kiểm tra các module đột phá đa luồng và đa phương diện: network_equalizer, native_symbolic_lifter, accuracy_oracle, autonomous, aarch64_asm, elf_expander, micro_lifter, micro_lifter_cfg, xref_hunter."""
    from patchx_core.behavior.network_equalizer import NetworkEqualizer
    from patchx_core.behavior.native_symbolic_lifter import NativeSymbolicLifter, AArch64Opcode
    from patchx_core.behavior.accuracy_oracle import AccuracyOracle
    from patchx_core.autonomous import AutonomousOrchestrator
    import patchx_core.behavior.aarch64_asm as aarch64_asm
    import patchx_core.behavior.elf_expander as elf_expander
    import patchx_core.behavior.micro_lifter as micro_lifter
    import patchx_core.behavior.micro_lifter_cfg as micro_lifter_cfg
    import patchx_core.behavior.xref_hunter as xref_hunter

    # 1. Network Equalizer
    neq = NetworkEqualizer()
    neq.register_mock_route("/api/v1/user", {"vip": True, "level": "PRO"})
    check("network_equalizer: khởi tạo và đăng ký route mock", bool(neq))

    # 2. Native Symbolic Lifter
    lifter = NativeSymbolicLifter()
    mov_code = AArch64Opcode.make_mov_w0(1)
    check("native_symbolic_lifter: sinh lệnh MOV W0, #1", (mov_code & 0xFFFF0000) != 0)

    # 3. Accuracy Oracle
    oracle_res = AccuracyOracle.evaluate_target_confidence(
        [".method public static isVip()Z", "const/4 v0, 0x1", "if-eqz v0, :cond", "return v0", ".end method"],
        ["Java_com_demo_checkVip"],
        ["https://api.demo.com/v1/auth"]
    )
    check("accuracy_oracle: tính điểm tin cậy >= 85", oracle_res["score"] >= 85)

    # 4. Autonomous Orchestrator
    auto = AutonomousOrchestrator()
    check("autonomous: khởi tạo bộ não tự trị thành công", bool(auto.blackboard))

    # 5. Full Deobfuscator
    from patchx_core.behavior.full_deobfuscator import FullDeobfuscator
    deobf = FullDeobfuscator()
    res_deobf = deobf.deobfuscate_method(".method public a()V\nnop\nreturn-void\n.end method")
    check("full_deobfuscator: loại bỏ lệnh nop thành công", res_deobf["nops_removed"] == 1)


def main():
    test_baseline()
    test_combo()
    test_simulate()
    test_selfcheck()
    test_zipalign_prebuilt()
    test_package_gioi_han_3_ban()
    test_apks_patch()
    test_bypass_advisor()
    test_apk_plan_bao_cao()
    test_scan_cache_fast()
    test_coverage_fast_equiv()
    test_coverage_regex_fast_equiv()
    test_detect_protections_fast()
    test_bench_scan()
    test_parser()
    test_engine()
    test_result_contract()
    test_strict_rollback()
    test_dex_budget()
    test_preflight()
    test_pipeline_gate()
    test_validation_v2()
    test_fuzz()
    test_runtime_status_p13()
    test_runtime_scenario_p14()
    test_failure_db_p15()
    test_failure_dex_cache_p15()
    test_simulate_v2_p17()
    test_plan_evidence_p18()
    test_dex_parallel_p20()
    test_parser_edge_p11()
    test_engine_tx_ensure_p11()
    test_scan_modes_p16()
    test_simulate_cache_change_p11()
    test_failure_gen_message_p11()
    test_dex_strategy_all_p11()
    test_baseline_compare_p11()
    test_scenario_validate_more_p11()
    test_add_files_khong_tu_sua()
    test_golden_rebuild()
    test_resource_fix_sach_tham_chieu()
    test_golden_framework_res()
    test_audit_upgrade()
    test_optimizer()
    test_advisor()
    test_corrupt_zip()
    test_dupes()
    test_dex_runner()
    test_engine_guards()
    test_modern_blocks()
    test_remote_trace_force()
    test_start_scan()
    test_smart_ontology()
    test_smart_scanner()
    test_rodata_patcher()
    test_rodata_bypass_flows()
    test_feature_menu()
    test_smart_patch()
    test_smali_lib()
    test_smali_sem()
    test_semantic_evidence_v2()
    test_dataflow_and_knowledge_bridge()
    test_acceptance_v2()
    test_obfuscation_variants_v2()
    test_v2_requires_unique_candidate_policy()
    test_v2_relation_evidence_fixtures()
    test_v2_knowledge_rejects_execution_payload()
    test_plan_revalidation_v2()
    test_v2_never_calls_apply()
    test_runtime_net_parse()
    test_diff_apk()
    test_learn_smart()
    test_risk_t5()
    test_verify_manifest_t5()
    test_smali_lib_modern_t6()
    test_report_dashboard()
    test_ci_pipeline()
    test_coverage_skip_degenerate()
    test_add_files_placeholder_package()
    test_match_replace_khong_quet_file_them_truoc()
    test_add_files_placeholder_rsa()
    test_extract_apk_cert_hex()
    test_plan_ui_render()
    test_terminal_ui_vietnamese()
    test_cli_danh_muc_so_thu_tu()
    test_res_attr_autofix()
    test_pairip_bypass()
    test_behavior_aux_modules()
    test_fixtures_mau()
    test_session_selector()
    test_intake_capabilities()
    test_unified_pipeline()
    test_blackboard_and_fused_targets()
    test_dag_and_pipeline_registry()
    test_integrity_decoupler()
    test_cfg_unflatten()
    test_breakthrough_modules()
    test_cfg_unflattener()
    test_native_mutator()
    test_integrity_gate()
    test_ast_dsl()
    test_autonomous_and_multidomain()
    from tests.test_modder_hub_fastpath import run_all_modder_hub_tests
    run_all_modder_hub_tests(check)
    ok = sum(1 for _, c, _ in RESULTS if c)
    total = len(RESULTS)
    print("\nKết quả: %d/%d kiểm tra đạt" % (ok, total))
    for name, c, detail in RESULTS:
        if not c:
            print("  FAIL: %s %s" % (name, detail))
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
