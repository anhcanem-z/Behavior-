# -*- coding: utf-8 -*-
"""diff-apk (truc T2 — dao pipeline): sinh patch tu khac biet giua ban goc
va ban da mod, kem vong khep kin: ap patch len goc → so noi dung voi ban mod
→ ty le tai sinh (nghiem thu ≥ 90%)."""

import hashlib
import os
import shutil
import tempfile
import time
import zipfile

from .parser import parse_patch_file
from .engine import Engine

TEXT_EXTS = (".smali", ".xml", ".json", ".properties", ".txt", ".yml",
             ".cfg", ".conf", ".yaml")
SKIP_DIRS = ("original", ".patchx", "build", "unknown")


def match_app_models_v2(before, after):
    """Ghep method hai phien ban theo identity V2, bao thu voi truong hop mo ho.

    Khong chon khi mot identity khớp nhieu method. Ket qua la evidence phuc vu
    review/semantic plan, tuyet doi khong phai lệnh thay doi APK.
    """
    if before.get("schema") != "patchx.app-model/v2" or after.get("schema") != "patchx.app-model/v2":
        raise ValueError("match_app_models_v2 can hai patchx.app-model/v2")
    remaining = {m["id"]: m for m in after.get("methods", [])}
    rows = []
    for old in before.get("methods", []):
        candidates = []
        for new in remaining.values():
            same = [k for k in ("exact", "structural", "semantic")
                    if old.get("identity", {}).get(k)
                    and old["identity"].get(k) == new.get("identity", {}).get(k)]
            if same:
                candidates.append((new, same))
        if not candidates:
            rows.append({"before": old["id"], "status": "unknown", "reason": "no_identity_match"})
            continue
        candidates.sort(key=lambda x: (-len(x[1]), x[0]["id"]))
        best_score = len(candidates[0][1])
        best = [x for x in candidates if len(x[1]) == best_score]
        if len(best) != 1:
            rows.append({"before": old["id"], "status": "unknown", "reason": "ambiguous_identity",
                         "candidates": [x[0]["id"] for x in best]})
            continue
        new, identities = best[0]
        remaining.pop(new["id"], None)
        level = "exact" if "exact" in identities else "structural" if "structural" in identities else "semantic"
        rows.append({"before": old["id"], "after": new["id"], "status": level,
                     "identity_matches": identities,
                     "before_identity": old["identity"], "after_identity": new["identity"]})
    summary = {k: sum(1 for r in rows if r["status"] == k)
               for k in ("exact", "structural", "semantic", "unknown")}
    summary["unmatched_after"] = len(remaining)
    known = len(before.get("methods", []))
    reidentified = summary["exact"] + summary["structural"] + summary["semantic"]
    summary["reidentification_rate"] = (
        round(100.0 * reidentified / known, 2) if known else 0.0)
    return {"schema": "patchx.version-match/v1", "matches": rows, "summary": summary}


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _walk(rel_root):
    """Quet cây text: rel path → noi dung chuoi. Bo thu mức noi bo apktool."""
    out = {}
    if not os.path.isdir(rel_root):
        return out
    for root, dirs, files in os.walk(rel_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, rel_root)
            if not fname.lower().endswith(TEXT_EXTS):
                continue
            try:
                out[rel] = open(full, encoding="utf-8",
                                errors="replace").read()
            except OSError:
                continue
    return out


def _read_bytes(tree, rel):
    with open(os.path.join(tree, rel), "rb") as fh:
        return fh.read()


def diff_trees(orig, modded):
    """So sanh hai cây text — tra (added, removed, changed, binary_changed)."""
    a = _walk(orig)
    b = _walk(modded)
    keys = sorted(set(a) | set(b))
    added, removed, changed = [], [], []
    for k in keys:
        if k not in a:
            added.append(k)
        elif k not in b:
            removed.append(k)
        elif a[k] != b[k]:
            changed.append(k)
    # Binary thay doi (chi bao cao, khong sinh patch)
    binary = []
    for root, dirs, files in os.walk(orig):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.lower().endswith(TEXT_EXTS):
                continue
            rel = os.path.relpath(os.path.join(root, fname), orig)
            mp = os.path.join(modded, rel)
            if os.path.isfile(mp) and _sha256_bytes(
                    open(os.path.join(root, fname), "rb").read()) != \
                    _sha256_bytes(open(mp, "rb").read()):
                binary.append(rel)
    return added, removed, changed, binary


def build_patch(orig, modded, name="diff_apk"):
    """Sinh (patch_text, assets) tu khac biet giua hai cây."""
    added, removed, changed, binary = diff_trees(orig, modded)
    blocks = []
    assets = {}
    for k in added:
        assets["assets/" + k] = _read_bytes(modded, k)
        blocks.append("[ADD_FILES]\nSOURCE:\nassets/%s\nTARGET:\n%s\n"
                      "[/ADD_FILES]\n" % (k, k))
    for k in changed:
        assets["assets/" + k] = _read_bytes(modded, k)
        blocks.append("[REPLACE_FILES]\nSOURCE:\nassets/%s\nTARGET:\n%s\n"
                      "[/REPLACE_FILES]\n" % (k, k))
    for k in removed:
        blocks.append("[REMOVE_FILES]\nTARGET:\n%s\n[/REMOVE_FILES]\n" % k)
    text = ("[NAME]\n%s\n[/NAME]\n"
            "[AUTHOR]\npatchx diff-apk\n[/AUTHOR]\n"
            "[MIN_ENGINE_VER]\n1\n[/MIN_ENGINE_VER]\n\n" % name) + \
        "\n".join(blocks)
    return text, assets, {"added": added, "removed": removed,
                          "changed": changed, "binary_changed": binary}


def write_patch_zip(path, patch_text, assets):
    """Ghi patch tu chua: patch.txt + assets/* (giu noi dung goc)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("patch.txt", patch_text)
        for name, data in assets.items():
            zf.writestr(name, data)
    return path


def _apply_to_copy(orig, patch_path, tmp_root):
    """Sao chep cây goc sang thu mức tam va ap patch — tra cây ket qua."""
    copy = os.path.join(tmp_root, "applied")
    shutil.copytree(orig, copy, symlinks=False)
    eng = Engine(copy, quiet=True, no_dex=True)
    eng.apply(parse_patch_file(patch_path))
    eng.finalize()
    return copy


def verify_rebuild(orig, modded, patch_path, tmp_root=None):
    """Vong khep kin: ap patch len ban goc, so text voi ban mod — % tai sinh."""
    own = False
    if tmp_root is None:
        tmp_root = tempfile.mkdtemp(prefix="patchx_diff_verify_")
        own = True
    try:
        applied = _apply_to_copy(orig, patch_path, tmp_root)
        a = _walk(applied)
        b = _walk(modded)
        keys = sorted(set(a) | set(b))
        matched = sum(1 for k in keys if a.get(k) == b.get(k))
        pct = (matched / len(keys) * 100) if keys else 0.0
        return {"tỷ_lệ": round(pct, 1), "khớp": matched, "tổng": len(keys)}
    finally:
        if own:
            shutil.rmtree(tmp_root, ignore_errors=True)


def prepare_tree(src, keep=None):
    """APK → cây (apktool d); thu mức → dung luon. Tra (tree, da_decode, tmp)."""
    if os.path.isdir(src):
        return os.path.abspath(src), False, None
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tu_sinh_dir = os.path.join(root_dir, "outputs", "tu-sinh", "diff_trees")
    os.makedirs(tu_sinh_dir, exist_ok=True)
    tmp = keep or tempfile.mkdtemp(prefix="tree_", dir=tu_sinh_dir)
    tree = os.path.join(tmp, os.path.splitext(
        os.path.basename(src))[0])
    import subprocess
    proc = subprocess.run(["apktool", "d", "-f", "-o", tree, src],
                          text=True, errors="replace",
                          capture_output=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError("apktool d lỗi: %s"
                           % ((proc.stderr or proc.stdout or "")[-300:]))
    return tree, True, tmp
