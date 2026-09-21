# -*- coding: utf-8 -*-
"""Xac thuc cau truc smali cua cây APK da giai ma.

Dung chung cho `patchx validate`, `apk-debug` va `apk-build`: phat hien som
tệp smali hong (method mat .end method, directive .registers/.locals long
nhau, ...) TRUOC khi build — rut ngan vong lap fix → test.

Quy uoc: binh luan va thong bao tieng Viet; chuoi smali giu nguyen goc.
"""

import glob
import json
import os
import re

from .smali_lib import METHOD_RE

# Directive khai bao thanh ghi trong than method
REG_DIR_RE = re.compile(r"^(\s*)\.(?:registers|locals)\s+\d+\s*$", re.M)
HEADER_RE = re.compile(r"(?m)^\s*\.method\b")
END_METHOD_RE = re.compile(r"(?m)^\s*\.end method\b")
CLASS_RE = re.compile(r"(?m)^\s*\.class\b")


def smali_files(tree_root):
    """Danh sach duong dan tuong doi moi tệp smali*/*.smali trong cây."""
    out = []
    for d in sorted(glob.glob(os.path.join(tree_root, "smali*"))):
        if not os.path.isdir(d):
            continue
        for root, _dirs, files in os.walk(d):
            for fn in files:
                if fn.endswith(".smali"):
                    out.append(os.path.relpath(os.path.join(root, fn),
                                               tree_root))
    return out


def _body_shape_ok(body, header=""):
    """Cau truc than method hop le:
    - dung MOT directive .registers/.locals, nam trước lệnh/nhan dau tien;
    - khong co method long (dau .method/.end method);
    - method abstract/native (khong co than) luon hop le.
    """
    if not body.strip() or re.search(r"\b(?:abstract|native)\b",
                                     header or ""):
        return True
    if re.search(r"(?m)^\s*\.(?:method|end method)\b", body):
        return False
    dirs = list(REG_DIR_RE.finditer(body))
    if len(dirs) != 1:
        return False
    m_instr = re.search(r"^\s*[^.#\s]", body, re.M)
    return not (m_instr and m_instr.start() < dirs[0].start())


def validate_file(text):
    """Kiem tra cau truc toan tệp smali — tra (errors, methods).

    errors: danh sach chuoi mo ta lỗi; methods: so method da phan tich.
    """
    errors = []
    if not CLASS_RE.search(text):
        errors.append("thieu khai bao .class")
    n_head = len(HEADER_RE.findall(text))
    n_end = len(END_METHOD_RE.findall(text))
    if n_head != n_end:
        errors.append("so .method (%d) khac so .end method (%d)"
                      % (n_head, n_end))
    methods = 0
    for m in METHOD_RE.finditer(text):
        methods += 1
        body = m.group(4)
        if not _body_shape_ok(body, m.group(1)):
            errors.append(
                "method %s: than bat thuong (thieu/trung directive "
                ".registers/.locals, hoac method long)" % m.group(2))
    return errors, methods


def validate_tree(tree_root, changed_only=False, state_file=None):
    """Quet va xac thuc moi tệp smali trong cây.

    changed_only=True: chi kiem tra tệp doi moi (so sanh mtime+kich thuoc
    voi lần trước, luu trong .patchx/cache/validate.json).
    Tra dict: files, ok, errors (danh sach "rel: lỗi"), methods, changed.
    """
    state_path = state_file or os.path.join(
        tree_root, ".patchx", "cache", "validate.json")
    old_state = {}
    if changed_only and os.path.isfile(state_path):
        try:
            with open(state_path, encoding="utf-8") as fh:
                old_state = json.load(fh)
        except Exception:
            old_state = {}
    errors = []
    ok = 0
    methods = 0
    changed = 0
    # Giu trang thai cu roi cap nhat tệp da kiem tra — lần sau chi quet
    # tệp doi moi, khong quet lai toan bo.
    new_state = dict(old_state)
    files = smali_files(tree_root)
    to_check = []
    for rel in files:
        p = os.path.join(tree_root, rel)
        try:
            st = os.stat(p)
        except OSError:
            continue
        key = [st.st_mtime_ns, st.st_size]
        if changed_only and old_state.get(rel) == key:
            continue
        to_check.append((rel, p, key))

    changed = len(to_check)

    def _validate_worker(item):
        rel, p, key = item
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            errs, nm = validate_file(text)
            return rel, key, errs, nm
        except Exception:
            return rel, key, [], 0

    from .pool import run_parallel
    results = run_parallel(_validate_worker, to_check, max_workers=8)

    for rel, key, errs, nm in results:
        methods += nm
        if errs:
            errors.append("%s: %s" % (rel, "; ".join(errs)))
        else:
            ok += 1
        new_state[rel] = key
    if changed_only and new_state:
        try:
            os.makedirs(os.path.dirname(state_path), exist_ok=True)
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(new_state, fh, ensure_ascii=False, indent=1)
        except OSError:
            pass
    return {
        "files": len(files),
        "ok": ok,
        "errors": errors,
        "methods": methods,
        "changed": changed,
        "changed_only": bool(changed_only),
    }


# ---- P9 — Valiđạtion V2: XML / Manifest / DEX / 4 mức FAST-NORMAL-FULL-RELEASE

LEVELS = ("FAST", "NORMAL", "FULL", "RELEASE")


def _xml_well_formed(path):
    """Kiem tra XML well-formed — tra chuoi lỗi hoac None."""
    try:
        import xml.etree.ElementTree as ET
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            ET.fromstring(fh.read())
        return None
    except Exception as e:
        return "XML lỗi: %s" % e


def validate_xml_tree(tree_root):
    """Quet moi tệp .xml trong cây (tru tệp nhi phan res) — tra findings."""
    findings = []
    for dirpath, _dirs, files in os.walk(tree_root):
        for fn in files:
            if not fn.lower().endswith(".xml"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), tree_root)
            if "/raw/" in rel or "/drawable" in rel and ".9." in fn:
                continue
            err = _xml_well_formed(os.path.join(dirpath, fn))
            if err:
                findings.append({"loại": "xml", "mức": "lỗi", "path": rel,
                                 "nội_dung": err})
    return findings


def validate_manifest(tree_root):
    """Kiem tra AndroidManifest.xml: ton tai, well-formed, co package."""
    findings = []
    p = os.path.join(tree_root, "AndroidManifest.xml")
    rel = "AndroidManifest.xml"
    if not os.path.isfile(p):
        findings.append({"loại": "manifest", "mức": "lỗi", "path": rel,
                         "nội_dung": "thieu AndroidManifest.xml"})
        return findings
    err = _xml_well_formed(p)
    if err:
        findings.append({"loại": "manifest", "mức": "lỗi", "path": rel,
                         "nội_dung": err})
        return findings
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse(p).getroot()
        if not root.tag.endswith("manifest"):
            findings.append({"loại": "manifest", "mức": "lỗi", "path": rel,
                             "nội_dung": "the goc khong phai <manifest>"})
        elif not root.get("package"):
            findings.append({"loại": "manifest", "mức": "lỗi", "path": rel,
                             "nội_dung": "thieu thuoc tinh package"})
    except Exception as e:
        findings.append({"loại": "manifest", "mức": "lỗi", "path": rel,
                         "nội_dung": "khong doc duoc manifest: %s" % e})
    return findings


def validate_dex_budget(tree_root, max_files=None):
    """Kiem tra DEX budget — tra findings (BLOCK lỗi, CRITICAL/HIGH canh bao)."""
    from .dex_budget import budget_report
    rep = budget_report(tree_root, max_files=max_files)
    if rep["level"] == "BLOCK":
        return [{"loại": "dex", "mức": "lỗi", "path": "",
                 "nội_dung": "DEX vuot gioi han (%d/%d)"
                 % (rep["total"], rep["max_refs"])}]
    if rep["level"] in ("CRITICAL", "HIGH"):
        return [{"loại": "dex", "mức": "cảnh-báo", "path": "",
                 "nội_dung": "DEX mức %s (con %d refs)"
                 % (rep["level"], rep["remaining"])}]
    return []


def validate_tree_v2(tree_root, level="NORMAL", changed_only=False,
                     max_files=None):
    """P9 — Valiđạtion V2 voi 4 mức:

    - FAST   : chi smali (doi moi neu changed_only);
    - NORMAL : smali + manifest;
    - FULL   : + moi tệp XML + DEX budget;
    - RELEASE: FULL + moi canh bao coi nhu lỗi (gate build).
    """
    level = (level or "NORMAL").upper()
    if level not in LEVELS:
        raise ValueError("level phai la mot trong: %s" % ", ".join(LEVELS))
    findings = []
    r = validate_tree(tree_root, changed_only=changed_only)
    for e in r["errors"]:
        rel = e.split(":", 1)[0]
        findings.append({"loại": "smali", "mức": "lỗi", "path": rel,
                         "nội_dung": e})
    if level in ("NORMAL", "FULL", "RELEASE"):
        findings += validate_manifest(tree_root)
    if level in ("FULL", "RELEASE"):
        findings += validate_xml_tree(tree_root)
        findings += validate_dex_budget(tree_root, max_files=max_files)
    errors = [f for f in findings if f["mức"] == "lỗi"]
    warnings = [f for f in findings if f["mức"] == "cảnh-báo"]
    if level == "RELEASE":
        errors = errors + warnings
        warnings = []
    return {
        "level": level,
        "files": r["files"],
        "methods": r["methods"],
        "changed": r["changed"],
        "findings": findings,
        "errors": errors,
        "warnings": warnings,
        "ok": not errors,
    }
