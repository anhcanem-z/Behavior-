# -*- coding: utf-8 -*-
"""Quet bo suu tap patch: tao index.json va bao cao Markdown."""

import glob
import hashlib
import json
import os
import time
import zipfile

from .parser import parse_patch_file
from .optimizer import cluster_tag

SKIP_DIRS = {"_patchx", "upgraded", "optimized", "combos", "combos_auto",
             "backup", "tests", "__pycache__"}


def _iter_zips(root, recursive=False):
    """Duyet tệp .zip; khi de quy bo qua thu mức noi bo (nhan _patchx...)."""
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in SKIP_DIRS]
            for f in sorted(filenames):
                if f.lower().endswith(".zip"):
                    yield os.path.join(dirpath, f)
    else:
        for z in sorted(glob.glob(os.path.join(root, "*.zip"))):
            yield z


def patch_sha256(z):
    """Hash patch.txt neu doc duoc; nguoc lai hash toan bo zip."""
    try:
        with zipfile.ZipFile(z) as zf:
            for n in zf.namelist():
                if n.lower() == "patch.txt" or n.lower().endswith("/patch.txt"):
                    return hashlib.sha256(zf.read(n)).hexdigest()
    except Exception:
        pass
    h = hashlib.sha256()
    with open(z, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_dir(root, recursive=False, use_cache=True):
    """Quet tat ca .zip trong thu mức, tra ve danh sach ban ghi."""
    cache_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "cache")
    cache_key = hashlib.md5(f"{os.path.abspath(root)}:{recursive}".encode()).hexdigest()[:12]
    cache_file = os.path.join(cache_dir, f"scan_{cache_key}.json")
    cur_mtime = None
    cur_count = None
    if use_cache:
        try:
            cur_mtime = os.path.getmtime(root)
            cur_count = len(os.listdir(root))
            if os.path.isfile(cache_file):
                with open(cache_file, "r", encoding="utf-8") as fh:
                    cached = json.load(fh)
                    if cached.get("mtime") == cur_mtime and cached.get("count") == cur_count:
                        return cached["records"]
        except Exception:
            pass


    records = []
    zips = list(_iter_zips(root, recursive=recursive))
    shas = {z: patch_sha256(z) for z in zips}
    counts = {}
    for h in shas.values():
        counts[h] = counts.get(h, 0) + 1
    dupe_id = 0
    dupe_map = {}
    for z, h in sorted(shas.items()):
        if counts[h] > 1 and h not in dupe_map:
            dupe_id += 1
            dupe_map[h] = dupe_id
    for z in zips:
        h = shas[z]
        rec = {
            "name": os.path.splitext(os.path.basename(z))[0],
            "path": os.path.relpath(z, root),
            "size": os.path.getsize(z),
            "sha256": h,
            "dupe_id": dupe_map.get(h),
            "tag": cluster_tag(os.path.basename(z)),
            "engine_ver": None, "author": None, "package": None,
            "sections": {}, "assets": [], "targets": [], "issues": [],
            "parse_error": None,
        }
        try:
            p = parse_patch_file(z)
            rec["engine_ver"] = p.min_engine_ver
            rec["author"] = p.author
            rec["package"] = p.package
            rec["sections"] = p.section_types()
            rec["assets"] = sorted(p.assets.keys())
            targets = set()
            for s in p.sections:
                t = s.get("TARGET").strip()
                if t:
                    targets.add(t)
            rec["targets"] = sorted(targets)
            rec["issues"] = p.issues
        except Exception as e:
            rec["parse_error"] = str(e)
            rec["issues"] = [str(e)]
        records.append(rec)
    if cur_mtime is not None:
        try:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as fh:
                json.dump({"mtime": cur_mtime, "count": cur_count, "records": records}, fh, ensure_ascii=False)
        except Exception:
            pass
    return records


def write_index(root, out_dir=None, name="patchx", recursive=False):
    """Ghi index.json + report.md cho thu mức patch."""
    records = scan_dir(root, recursive=recursive)
    out_dir = out_dir or root
    os.makedirs(out_dir, exist_ok=True)
    index = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": root,
        "total": len(records),
        "recursive": recursive,
        "patches": records,
    }
    ip = os.path.join(out_dir, name + "_index.json")
    with open(ip, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=2)
    rp = os.path.join(out_dir, name + "_report.md")
    with open(rp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_report(records))
    return ip, rp


def render_report(records):
    """Ket xuat bao cao Markdown tu danh sach ban ghi."""
    lines = ["# Bao cao bo suu tap patch", ""]
    total = len(records)
    ok = sum(1 for r in records if not r["issues"] and not r["parse_error"])
    lines.append("- Tong so patch: %d" % total)
    lines.append("- Patch hop le: %d" % ok)
    lines.append("- Patch co van de: %d" % (total - ok))
    lines.append("")
    dupes = {}
    for r in records:
        if r.get("dupe_id"):
            dupes.setdefault(r["dupe_id"], []).append(r["name"])
    if dupes:
        lines.append("## Nhóm trung noi dung (cung patch.txt)")
        lines.append("")
        for gid, names in sorted(dupes.items()):
            lines.append("- Nhóm %d (%d file): %s" % (
                gid, len(names), ", ".join(names)))
        lines.append("")
    lines.append("| # | Patch | Nhóm | Engine | Tac gia | Khối | Tài nguyên | Vấn đề |")
    lines.append("|---|-------|------|--------|---------|------|------------|--------|")
    for i, r in enumerate(records, 1):
        n_sec = sum(r["sections"].values()) if r["sections"] else 0
        issues = "LỖI: " + r["parse_error"] if r["parse_error"] \
            else "; ".join(r["issues"]) if r["issues"] else "—"
        lines.append("| %d | %s | %s | %s | %s | %d | %d | %s |" % (
            i, r["name"], r["tag"], r["engine_ver"] or "—",
            r["author"] or "—", n_sec, len(r["assets"]), issues))
    lines.append("")
    return "\n".join(lines)


def dedupe_report(records):
    """Bao cao cac nhóm trung lap — goi y ban chuan (file nho nhat)."""
    groups = []
    by_id = {}
    for r in records:
        if r.get("dupe_id"):
            by_id.setdefault(r["dupe_id"], []).append(r)
    for gid in sorted(by_id):
        members = sorted(by_id[gid], key=lambda r: r["size"])
        groups.append({
            "nhóm": gid,
            "bản_chuẩn": members[0]["path"],
            "bản_trùng": [m["path"] for m in members[1:]],
            "sha256": members[0]["sha256"],
            "số_file": len(members),
        })
    return groups
