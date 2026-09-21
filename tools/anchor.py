#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/anchor.py — in bộ NEO ĐỊNH DANH đa chiều cho mọi mốc log/báo cáo.

Quy tắc PATCHX-MULTI-ANCHOR-RULE: không dùng riêng thời gian làm chuẩn đối chiếu;
mỗi mốc phải có ít nhất 3 neo độc lập (thời gian, phiên, máy/môi trường, git, vân tay).

Chỉ ĐỌC — không ghi file, không gọi mạng.

Ví dụ:
    python3 tools/anchor.py
    python3 tools/anchor.py --phien PX-20260917-0125 --viec "dong-bo-quy-tac"
    python3 tools/anchor.py --file AGENTS.md --text "noi dung can bam"
    python3 tools/anchor.py --line AGENTS.md:17           # neo 1 dong
    python3 tools/anchor.py --block AGENTS.md:17:40       # neo 1 khoi dong
    python3 tools/anchor.py --markers AGENTS.md           # liet ke moi khoi marker
    python3 tools/anchor.py --file AGENTS.md --ledger     # ghi so ban cap nhat
    python3 tools/anchor.py --file AGENTS.md --dong --li-do "dong phien"   # neo dong moc
    python3 tools/anchor.py --so AGENTS.md:GEMINI.md      # so sanh neo 2 tep
    python3 tools/anchor.py --dong-bo AGENTS.md --dich /duong/dich/AGENTS.md --li-do "dong bo"
    python3 tools/anchor.py --json
"""

from __future__ import annotations

import argparse
import atexit
import difflib
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time


def _giu_khoa(tep: str, chu_so_huu: str = "anchor.py"):
    """PA1 — mọi ghi tệp dùng chung phải qua khóa mềm (chống ghi đè khi nhiều AI cùng chạy)."""
    try:
        import importlib.util
        duong_dan = os.path.join(os.path.dirname(os.path.abspath(__file__)), "khoa_tep.py")
        spec = importlib.util.spec_from_file_location("khoa_tep", duong_dan)
        mo_dun = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mo_dun)
        het = time.time() + 10
        while time.time() < het:
            if mo_dun.khoa(tep, chu_so_huu, 300):
                atexit.register(lambda: mo_dun.mo_khoa(tep, chu_so_huu))
                return mo_dun
            time.sleep(0.05)
    except Exception:
        return None
    return None


def _nha_khoa(mo_dun, tep: str, chu_so_huu: str = "anchor.py") -> None:
    if mo_dun is None:
        return
    try:
        mo_dun.mo_khoa(tep, chu_so_huu)
    except Exception:
        pass


WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SO_CAP_NHAT = os.path.join(WORKSPACE, "outputs", "anchor", "ledger.jsonl")
EVENTS_FILE = os.path.join(WORKSPACE, "outputs", "su_kien", "events.jsonl")
GIOI_HAN_SO = 500      # quá số dòng này thì nên nén
GIU_LAI_SO = 200       # số dòng mới nhất giữ lại sau khi nén


def _run(cmd: list[str], cwd: str) -> str:
    """Chạy lệnh phụ trợ ở chế độ chỉ đọc; lỗi thì trả chuỗi rỗng."""
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=15)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def neo_thoi_gian() -> dict:
    gio = time.localtime()
    return {
        "gio_dia_phuong": time.strftime("%F %T %Z", gio),
        "epoch": int(time.time()),
        "tz": time.strftime("%Z", gio),
        "offset": time.strftime("%z", gio),
    }


def neo_phien(phien: str, pid: int, gio: time.struct_time) -> dict:
    ma_tu_sinh = "PX-{}-{}-{}".format(time.strftime("%Y%m%d", gio), time.strftime("%H%M%S", gio), pid)
    return {
        "phien_cli": phien or "(không có session id từ CLI)",
        "ma_moc_tu_sinh": ma_tu_sinh,
        "pid": pid,
    }


def neo_may(cwd: str) -> dict:
    return {
        "user": os.environ.get("USER", "?"),
        "uid": os.getuid() if hasattr(os, "getuid") else -1,
        "host": platform.node(),
        "abi": platform.machine(),
        "python": platform.python_version(),
        "shell": os.environ.get("SHELL", "/bin/sh"),
        "cwd": os.path.abspath(cwd),
        "termux": "yes" if os.path.isdir("/data/data/com.termux/files/usr") else "no",
    }


def neo_git(cwd: str) -> dict:
    nhanh = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd)
    if not nhanh:
        return {"co_git": False}
    head = _run(["git", "rev-parse", "--short", "HEAD"], cwd)
    thay_doi = _run(["git", "status", "--porcelain"], cwd)
    so_dong = len([d for d in thay_doi.splitlines() if d.strip()])
    return {
        "co_git": True,
        "nhanh": nhanh,
        "head": head,
        "dirty": so_dong > 0,
        "so_file_thay_doi": so_dong,
    }


def bam_tep(duong_dan: str) -> dict:
    try:
        h = hashlib.sha256()
        with open(duong_dan, "rb") as fh:
            for khoi in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(khoi)
        return {"ten": duong_dan, "sha256": h.hexdigest(), "byte": os.path.getsize(duong_dan)}
    except Exception as loi:
        return {"ten": duong_dan, "loi": str(loi)}


def neo_van_tay(ds_tep: list[str], ds_text: list[str]) -> list[dict]:
    ket_qua: list[dict] = []
    for duong_dan in ds_tep:
        ket_qua.append(bam_tep(duong_dan))
    for chuoi in ds_text:
        ket_qua.append({
            "ten": "(text)",
            "sha256": hashlib.sha256(chuoi.encode("utf-8")).hexdigest(),
            "byte": len(chuoi.encode("utf-8")),
        })
    return ket_qua


def _bam_chuoi(chuoi: str) -> str:
    return hashlib.sha256(chuoi.encode("utf-8")).hexdigest()


def neo_dong(ds_dong: list[str]) -> list[dict]:
    """Neo cấp DÒNG: đường dẫn + số dòng + sha256 nội dung dòng."""
    ket_qua: list[dict] = []
    for muc in ds_dong:
        if ":" not in muc:
            ket_qua.append({"muc": muc, "loi": "dinh dang dung: TEP:SO_DONG"})
            continue
        duong_dan, _, so = muc.rpartition(":")
        try:
            so_dong = int(so)
            with open(duong_dan, encoding="utf-8", errors="replace") as fh:
                dong = fh.read().split("\n")
            noi_dung = dong[so_dong - 1]
        except Exception as loi:
            ket_qua.append({"muc": muc, "loi": str(loi)})
            continue
        ket_qua.append({
            "tep": duong_dan,
            "dong": so_dong,
            "sha256": _bam_chuoi(noi_dung),
            "trich": noi_dung.strip()[:90],
        })
    return ket_qua


def neo_khoi(ds_khoi: list[str]) -> list[dict]:
    """Neo cấp KHỐI: đường dẫn + khoảng dòng A:B + sha256 nội dung khối."""
    ket_qua: list[dict] = []
    for muc in ds_khoi:
        phan = muc.rsplit(":", 2)
        if len(phan) != 3:
            ket_qua.append({"muc": muc, "loi": "định dạng đúng: TỆP:A:B"})
            continue
        duong_dan, tu, den = phan
        try:
            a, b = int(tu), int(den)
            with open(duong_dan, encoding="utf-8", errors="replace") as fh:
                dong = fh.read().split("\n")
            noi_dung = "\n".join(dong[a - 1:b])
        except Exception as loi:
            ket_qua.append({"muc": muc, "loi": str(loi)})
            continue
        ket_qua.append({
            "tep": duong_dan,
            "tu_dong": a,
            "den_dong": b,
            "so_dong": b - a + 1,
            "sha256": _bam_chuoi(noi_dung),
        })
    return ket_qua


def neo_markers(ds_tep: list[str]) -> list[dict]:
    """Liệt kê mọi khối marker `<!-- ...:BEGIN --> ... <!-- ...:END -->` kèm dòng + sha256."""
    ket_qua: list[dict] = []
    for duong_dan in ds_tep:
        try:
            with open(duong_dan, encoding="utf-8", errors="replace") as fh:
                dong = fh.read().split("\n")
        except Exception as loi:
            ket_qua.append({"tep": duong_dan, "loi": str(loi)})
            continue
        dang_mo: tuple[str, int] | None = None
        for i, noi_dung in enumerate(dong, start=1):
            if ":BEGIN -->" in noi_dung and dang_mo is None:
                ten = noi_dung.split("<!--")[-1].split(":BEGIN")[0].strip()
                dang_mo = (ten, i)
            elif ":END -->" in noi_dung and dang_mo is not None:
                ten, bat_dau = dang_mo
                noi_dung_khoi = "\n".join(dong[bat_dau - 1:i])
                ket_qua.append({
                    "tep": duong_dan,
                    "marker": ten,
                    "tu_dong": bat_dau,
                    "den_dong": i,
                    "so_dong": i - bat_dau + 1,
                    "sha256": _bam_chuoi(noi_dung_khoi),
                })
                dang_mo = None
    return ket_qua


def ghi_so_cap_nhat(du_lieu: dict, duong_dan: str, li_do: str, nguon: str = "Codex_va_User", ma_su_kien: str = "") -> dict:
    """Ghi sổ bản cập nhật (append-only) và trả về số bản + hash trước/sau kèm khóa nối ma_su_kien (TC-06)."""
    os.makedirs(os.path.dirname(SO_CAP_NHAT), exist_ok=True)
    tep = os.path.abspath(duong_dan)
    so_ban = 0
    hash_truoc = None
    if os.path.isfile(SO_CAP_NHAT):
        with open(SO_CAP_NHAT, encoding="utf-8") as fh:
            for dong in fh:
                try:
                    rec = json.loads(dong)
                except Exception:
                    continue
                if rec.get("tep") == tep:
                    so_ban += 1
                    hash_truoc = rec.get("sha256")
    try:
        hash_hien_tai = bam_tep(tep)["sha256"]
        kich_thuoc = os.path.getsize(tep)
    except Exception as loi:
        return {"tep": tep, "loi": str(loi)}
    ban_moi = so_ban + 1
    ma_sk = ma_su_kien or "SK-{}-{}-{}".format(
        time.strftime("%Y%m%d-%H%M%S"), os.getpid(), int(time.time() * 1000) % 1000)
    ban_ghi = {
        "kind": "cap-nhat",
        "tep": tep,
        "ban": ban_moi,
        "sha256": hash_hien_tai,
        "sha256_truoc": hash_truoc,
        "thay_doi_so_voi_ban_truoc": (hash_truoc != hash_hien_tai) if hash_truoc else None,
        "byte": kich_thuoc,
        "gio": du_lieu["thoi_gian"]["gio_dia_phuong"],
        "epoch": du_lieu["thoi_gian"]["epoch"],
        "phien": du_lieu["phien"]["phien_cli"],
        "ma_moc": du_lieu["phien"]["ma_moc_tu_sinh"],
        "ma_su_kien": ma_sk,
        "nguon": nguon,
        "git_head": du_lieu["git"].get("head") if du_lieu["git"].get("co_git") else None,
        "git_dirty": du_lieu["git"].get("dirty") if du_lieu["git"].get("co_git") else None,
        "viec": du_lieu.get("viec", ""),
        "li_do": li_do,
    }
    _giu_khoa(SO_CAP_NHAT)
    with open(SO_CAP_NHAT, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ban_ghi, ensure_ascii=False) + "\n")

    # Đồng bộ 2 chiều sang outputs/su_kien/events.jsonl theo TC-06
    try:
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        su_kien_rec = {
            "ma_su_kien": ma_sk,
            "ma_moc": du_lieu["phien"]["ma_moc_tu_sinh"],
            "loai_su_kien": "cap_nhat_tep",
            "tep": os.path.relpath(tep, WORKSPACE) if tep.startswith(WORKSPACE) else tep,
            "sha256_truoc": hash_truoc,
            "sha256_sau": hash_hien_tai,
            "kich_thuoc_byte": kich_thuoc,
            "nguon": nguon,
            "gio": du_lieu["thoi_gian"]["gio_dia_phuong"],
            "epoch": du_lieu["thoi_gian"]["epoch"],
            "phien": du_lieu["phien"]["phien_cli"],
            "git_head": ban_ghi["git_head"],
            "git_dirty": ban_ghi["git_dirty"],
            "li_do": li_do,
            "meta": {"ban": ban_moi}
        }
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh_ev:
            fh_ev.write(json.dumps(su_kien_rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return ban_ghi


def ghi_dong_moc(du_lieu: dict, ds_ban: list[dict], li_do: str, nguon: str = "Codex_va_User") -> dict:
    """Ghi bản ghi ĐÓNG MỐC/ĐÓNG PHIÊN: chốt toàn bộ neo cuối cùng (append-only)."""
    os.makedirs(os.path.dirname(SO_CAP_NHAT), exist_ok=True)
    tat_ca_tep = []
    for ban in ds_ban:
        if "loi" in ban:
            continue
        tat_ca_tep.append({
            "tep": ban["tep"],
            "ban": ban["ban"],
            "sha256": ban["sha256"],
            "sha256_truoc": ban.get("sha256_truoc"),
            "thay_doi": ban.get("thay_doi_so_voi_ban_truoc"),
            "byte": ban.get("byte"),
        })
    for marker in du_lieu.get("markers", []):
        if "loi" in marker:
            continue
        tat_ca_tep.append({
            "tep": marker["tep"],
            "marker": marker["marker"],
            "tu_dong": marker["tu_dong"],
            "den_dong": marker["den_dong"],
            "sha256": marker["sha256"],
        })
    ma_sk = "SK-DONG-{}-{}".format(time.strftime("%Y%m%d-%H%M%S"), os.getpid())
    ban_ghi = {
        "kind": "dong-moc",
        "gio_dong": du_lieu["thoi_gian"]["gio_dia_phuong"],
        "epoch_dong": du_lieu["thoi_gian"]["epoch"],
        "phien": du_lieu["phien"]["phien_cli"],
        "ma_moc": du_lieu["phien"]["ma_moc_tu_sinh"],
        "ma_su_kien": ma_sk,
        "nguon": nguon,
        "pid": du_lieu["phien"]["pid"],
        "may": "{}/{}".format(du_lieu["may"]["uid"], du_lieu["may"]["abi"]),
        "cwd": du_lieu["may"]["cwd"],
        "git_head": du_lieu["git"].get("head") if du_lieu["git"].get("co_git") else None,
        "git_dirty": du_lieu["git"].get("dirty") if du_lieu["git"].get("co_git") else None,
        "so_file_thay_doi": du_lieu["git"].get("so_file_thay_doi") if du_lieu["git"].get("co_git") else None,
        "viec": du_lieu.get("viec", ""),
        "li_do": li_do,
        "neo_chot": tat_ca_tep,
    }
    _giu_khoa(SO_CAP_NHAT)
    with open(SO_CAP_NHAT, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ban_ghi, ensure_ascii=False) + "\n")

    try:
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        su_kien_rec = {
            "ma_su_kien": ma_sk,
            "ma_moc": du_lieu["phien"]["ma_moc_tu_sinh"],
            "loai_su_kien": "dong_moc_phien",
            "tep": "outputs/anchor/ledger.jsonl",
            "sha256_truoc": None,
            "sha256_sau": None,
            "kich_thuoc_byte": os.path.getsize(SO_CAP_NHAT),
            "nguon": nguon,
            "gio": du_lieu["thoi_gian"]["gio_dia_phuong"],
            "epoch": du_lieu["thoi_gian"]["epoch"],
            "phien": du_lieu["phien"]["phien_cli"],
            "git_head": ban_ghi["git_head"],
            "git_dirty": ban_ghi["git_dirty"],
            "li_do": li_do,
            "meta": {"so_neo_chot": len(tat_ca_tep)}
        }
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh_ev:
            fh_ev.write(json.dumps(su_kien_rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return ban_ghi


def nen_so(du_lieu: dict, giu_lai: int = GIU_LAI_SO) -> dict:
    """Nén sổ neo: lưu trữ phần cũ ra ledger-archive-<mã mốc>.jsonl, giữ lại phần mới nhất."""
    if not os.path.isfile(SO_CAP_NHAT):
        return {"hanh_dong": "không có sổ để nén", "so_dong": 0}
    return nen_tep(SO_CAP_NHAT, du_lieu["phien"]["ma_moc_tu_sinh"], giu_lai=giu_lai)


def nen_tep(duong_dan: str, ma_moc: str, giu_lai: int = GIU_LAI_SO) -> dict:
    """Nén một tệp sổ append-only bất kỳ: lưu trữ phần cũ, giữ lại phần mới nhất."""
    if not os.path.isfile(duong_dan):
        return {"hanh_dong": "không có sổ để nén", "so_dong": 0}
    with open(duong_dan, encoding="utf-8") as fh:
        dong = [d for d in fh.read().splitlines() if d.strip()]
    if len(dong) <= giu_lai:
        return {"hanh_dong": "không cần nén", "so_dong": len(dong)}
    cu, moi = dong[:-giu_lai], dong[-giu_lai:]
    luu_tru = os.path.join(os.path.dirname(duong_dan),
                           "{}-archive-{}.jsonl".format(
                               os.path.basename(duong_dan).replace(".jsonl", ""), ma_moc))
    with open(luu_tru, "w", encoding="utf-8") as fh:
        fh.write("\n".join(cu) + "\n")
    with open(duong_dan, "w", encoding="utf-8") as fh:
        fh.write("\n".join(moi) + "\n")
    return {"hanh_dong": "đã nén", "so_dong_truoc": len(dong), "so_dong_sau": len(moi),
            "luu_tru": luu_tru, "so_dong_luu_tru": len(cu)}


def nen_tu_dong() -> dict:
    """Nén tự động khi sổ vượt ngưỡng — gọi sau mỗi lần ghi sổ."""
    if not os.path.isfile(SO_CAP_NHAT):
        return {}
    try:
        with open(SO_CAP_NHAT, encoding="utf-8") as fh:
            so_dong = len([d for d in fh.read().splitlines() if d.strip()])
    except Exception:
        return {}
    if so_dong <= GIOI_HAN_SO:
        return {}
    ma_moc = "PX-{}-{}".format(time.strftime("%Y%m%d-%H%M%S"), os.getpid())
    return nen_tep(SO_CAP_NHAT, ma_moc)


def neo_so_sanh(ds_cap: list[str]) -> list[dict]:
    """So sánh neo 2 tệp: TEP_A:TEP_B — bằng hash, kèm số dòng khác nhau."""
    ket_qua: list[dict] = []
    for cap in ds_cap:
        if ":" not in cap:
            ket_qua.append({"cap": cap, "loi": "định dạng đúng: TỆP_A:TỆP_B"})
            continue
        tep_a, _, tep_b = cap.rpartition(":")
        a = bam_tep(tep_a)
        b = bam_tep(tep_b)
        if "loi" in a or "loi" in b:
            ket_qua.append({"cap": cap, "loi": "không đọc được tệp", "a": a, "b": b})
            continue
        muc = {
            "cap": cap,
            "tep_a": tep_a,
            "tep_b": tep_b,
            "sha256_a": a["sha256"],
            "sha256_b": b["sha256"],
            "byte_a": a["byte"],
            "byte_b": b["byte"],
            "giong_nhau": a["sha256"] == b["sha256"],
        }
        try:
            with open(tep_a, encoding="utf-8", errors="replace") as fh_a:
                dong_a = fh_a.read().splitlines()
            with open(tep_b, encoding="utf-8", errors="replace") as fh_b:
                dong_b = fh_b.read().splitlines()
            khac = [d for d in difflib.unified_diff(dong_a, dong_b, lineterm="", n=0)
                    if d[:1] in "+-" and not d.startswith(("+++", "---"))]
            muc["so_dong_khac"] = len(khac)
            muc["vi_du_khac"] = khac[:3]
        except Exception:
            muc["so_dong_khac"] = None
        ket_qua.append(muc)
    return ket_qua


def dong_bo_neo(nguon: str, ds_dich: list[str], sao_luu: bool, du_lieu: dict, li_do: str) -> list[dict]:
    """Đồng bộ nguồn → đích CÓ XÁC MINH NEO: bỏ qua nếu giống, sao lưu rồi mới ghi, kiểm lại hash."""
    ket_qua: list[dict] = []
    nguon_hash = bam_tep(nguon)
    if "loi" in nguon_hash:
        return [{"nguon": nguon, "loi": nguon_hash["loi"]}]
    for dich in ds_dich:
        muc: dict = {"nguon": nguon, "dich": dich, "sha256_nguon": nguon_hash["sha256"]}
        dich_hash = bam_tep(dich) if os.path.exists(dich) else None
        muc["sha256_dich_truoc"] = dich_hash["sha256"] if dich_hash and "loi" not in dich_hash else None
        if dich_hash and "loi" not in dich_hash and dich_hash["sha256"] == nguon_hash["sha256"]:
            muc["hanh_dong"] = "bỏ qua"
            muc["ly_do"] = "neo nguồn trùng neo đích (đã đồng bộ)"
            ket_qua.append(muc)
            continue
        try:
            if dich_hash and "loi" not in dich_hash and sao_luu:
                duong_sao_luu = "{}.bak.{}".format(dich, du_lieu["phien"]["ma_moc_tu_sinh"])
                shutil.copy2(dich, duong_sao_luu)
                muc["sao_luu"] = duong_sao_luu
            os.makedirs(os.path.dirname(os.path.abspath(dich)), exist_ok=True)
            shutil.copy2(nguon, dich)
        except Exception as loi:
            muc["hanh_dong"] = "loi"
            muc["loi"] = str(loi)
            ket_qua.append(muc)
            continue
        kiem_tra = bam_tep(dich)
        muc["hanh_dong"] = "da_dong_bo"
        muc["sha256_dich_sau"] = kiem_tra.get("sha256")
        muc["xac_minh"] = kiem_tra.get("sha256") == nguon_hash["sha256"]
        muc["ban_nguon"] = ghi_so_cap_nhat(du_lieu, nguon, li_do or "dong-bo")
        muc["ban_dich"] = ghi_so_cap_nhat(du_lieu, dich, li_do or "dong-bo")
        ket_qua.append(muc)
    return ket_qua


def in_nguoi_doc(du_lieu: dict) -> None:
    tg = du_lieu["thoi_gian"]
    ph = du_lieu["phien"]
    may = du_lieu["may"]
    git = du_lieu["git"]
    print("=== NEO ĐỊNH DANH (tối thiểu 3 neo) ===")
    print("1. [Thời gian] {} · epoch {} · TZ {} {}".format(
        tg["gio_dia_phuong"], tg["epoch"], tg["tz"], tg["offset"]))
    print("2. [Phiên] {} · mã mốc {} · pid {}".format(
        ph["phien_cli"], ph["ma_moc_tu_sinh"], ph["pid"]))
    print("3. [Máy] người dùng={} uid={} · kiến trúc={} · python={} · termux={} · shell={}".format(
        may["user"], may["uid"], may["abi"], may["python"], may["termux"], may["shell"]))
    print("   [Thư mục] {}".format(may["cwd"]))
    if git.get("co_git"):
        print("4. [Mã nguồn] nhánh={} · HEAD={} · có {} file chưa lưu".format(
            git["nhanh"], git["head"], git["so_file_thay_doi"]))
    else:
        print("4. [Mã nguồn] (không phải kho git)")
    if du_lieu["van_tay"]:
        for vt in du_lieu["van_tay"]:
            if "loi" in vt:
                print("5. [Mã băm] {} → lỗi: {}".format(vt["ten"], vt["loi"]))
            else:
                print("5. [Mã băm] {} · {} byte · sha256={}".format(vt["ten"], vt["byte"], vt["sha256"]))
    else:
        print("5. [Mã băm] (chưa truyền --file/--text)")
    for neo in du_lieu.get("dong", []):
        if "loi" in neo:
            print("6. [Dòng] {} → lỗi: {}".format(neo["muc"], neo["loi"]))
        else:
            print("6. [Dòng] {}:{} · sha256={} · \"{}\"".format(
                neo["tep"], neo["dong"], neo["sha256"], neo["trich"]))
    for neo in du_lieu.get("khoi", []):
        if "loi" in neo:
            print("7. [Khối] {} → lỗi: {}".format(neo["muc"], neo["loi"]))
        else:
            print("7. [Khối] {}:{}-{} ({} dòng) · sha256={}".format(
                neo["tep"], neo["tu_dong"], neo["den_dong"], neo["so_dong"], neo["sha256"]))
    for neo in du_lieu.get("markers", []):
        if "loi" in neo:
            print("8. [Khối quy tắc] {} → lỗi: {}".format(neo["tep"], neo["loi"]))
        else:
            print("8. [Khối quy tắc] {} · {} dòng {}-{} · sha256={}".format(
                neo["marker"], neo["tep"], neo["tu_dong"], neo["den_dong"], neo["sha256"]))
    for ban in du_lieu.get("so_cap_nhat", []):
        if "loi" in ban:
            print("9. [Bản cập nhật] {} → lỗi: {}".format(ban["tep"], ban["loi"]))
        else:
            print("9. [Bản cập nhật] {} · bản #{} · {} → {} · thay đổi: {}".format(
                ban["tep"], ban["ban"],
                str(ban.get("sha256_truoc"))[:12], str(ban["sha256"])[:12],
                ban.get("thay_doi_so_voi_ban_truoc")))
    dong_moc = du_lieu.get("dong_moc")
    if dong_moc:
        print("=== ĐÓNG MỐC ===")
        print("Giờ đóng: {} · epoch {} · mã mốc {} · phiên {}".format(
            dong_moc["gio_dong"], dong_moc["epoch_dong"], dong_moc["ma_moc"], dong_moc["phien"]))
        print("Mã nguồn: {} · có {} file chưa lưu · số neo đã chốt: {}".format(
            dong_moc["git_head"], dong_moc["so_file_thay_doi"], len(dong_moc["neo_chot"])))
        for neo in dong_moc["neo_chot"]:
            if "marker" in neo:
                print("  - {} {} dòng {}-{} sha256={}".format(
                    neo["marker"], neo["tep"], neo["tu_dong"], neo["den_dong"], neo["sha256"][:16]))
            else:
                print("  - {} ban #{} sha256={} (trước: {})".format(
                    neo["tep"], neo["ban"], neo["sha256"][:16], str(neo.get("sha256_truoc"))[:16]))
    for muc in du_lieu.get("so_sanh", []):
        if "loi" in muc:
            print("10. [So sánh] {} → lỗi: {}".format(muc.get("cap"), muc["loi"]))
        else:
            print("10. [So sánh] {} vs {} · giống nhau: {} · số dòng khác: {} · sha {} / {}".format(
                muc["tep_a"], muc["tep_b"], muc["giong_nhau"], muc.get("so_dong_khac"),
                muc["sha256_a"][:12], muc["sha256_b"][:12]))
            for vi_du in muc.get("vi_du_khac", []):
                print("     | {}".format(vi_du[:100]))
    for muc in du_lieu.get("dong_bo", []):
        if muc.get("hanh_dong") == "loi":
            print("11. [Đồng bộ] {} → lỗi: {}".format(muc.get("dich"), muc.get("loi")))
            continue
        if muc["hanh_dong"] == "bỏ qua":
            print("11. [Đồng bộ] {} → BỎ QUA ({})".format(muc["dich"], muc["ly_do"]))
            continue
        print("11. [Đồng bộ] {} -> đã đồng bộ · xác minh: {} · bản đích #{} · sha={}".format(
            muc["dich"], muc.get("xac_minh"),
            (muc.get("ban_dich") or {}).get("ban"), str(muc.get("sha256_dich_sau"))[:12]))
        if muc.get("sao_luu"):
            print("     | sao luu: {}".format(muc["sao_luu"]))
    if du_lieu["viec"]:
        print("[Việc] {}".format(du_lieu["viec"]))
    if "nen_so" in du_lieu:
        nn = du_lieu["nen_so"]
        print("[SỔ NEO] {} · {} dòng".format(nn.get("hanh_dong"), nn.get("so_dong_sau", nn.get("so_dong", 0))))
        if nn.get("luu_tru"):
            print("         lưu trữ {} dòng cũ vào {}".format(nn["so_dong_luu_tru"], nn["luu_tru"]))
    elif os.path.isfile(SO_CAP_NHAT) and du_lieu.get("so_dong_so") and du_lieu["so_dong_so"] > GIOI_HAN_SO:
        print("[SỔ NEO] {} dòng (>{}), nên chạy --nen-so".format(du_lieu["so_dong_so"], GIOI_HAN_SO))
    print("MÃ MỐC: {}".format(ph["ma_moc_tu_sinh"]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="In bo neo dinh danh da chieu (>=3 neo) de doi chieu moi moc log/bao cao.",
    )
    ap.add_argument("--phien", default=os.environ.get("CODEX_SESSION_ID")
                    or os.environ.get("CODEX_THREAD_ID") or os.environ.get("CLAUDE_SESSION_ID") or "",
                    help="ma phien CLI (neu co)")
    ap.add_argument("--viec", default="", help="ma/ten cong viec dang lam")
    ap.add_argument("--file", action="append", default=[], help="tep can bam SHA-256 (lap lai duoc)")
    ap.add_argument("--text", action="append", default=[], help="chuoi can bam SHA-256 (lap lai duoc)")
    ap.add_argument("--line", action="append", default=[], help="neo 1 dong: TEP:SO_DONG (lap lai duoc)")
    ap.add_argument("--block", action="append", default=[], help="neo 1 khoi: TEP:A:B (lap lai duoc)")
    ap.add_argument("--markers", action="append", default=[], help="liet ke moi khoi marker trong TEP (lap lai duoc)")
    ap.add_argument("--ledger", action="store_true", help="ghi so ban cap nhat cho moi --file")
    ap.add_argument("--dong", action="store_true", help="chốt ĐÓNG MỐC/ĐÓNG PHIÊN và ghi sổ")
    ap.add_argument("--nen-so", action="store_true", help="nén sổ neo: lưu trữ phần cũ, giữ số dòng mới nhất")
    ap.add_argument("--nguong", type=int, default=GIOI_HAN_SO, help="ngưỡng số dòng kích hoạt nén (mặc định %d)" % GIOI_HAN_SO)
    ap.add_argument("--giu-lai", type=int, default=GIU_LAI_SO, help="số dòng giữ lại sau khi nén (mặc định %d)" % GIU_LAI_SO)
    ap.add_argument("--so", action="append", default=[], help="so sanh neo 2 tep: TEP_A:TEP_B (lap lai duoc)")
    ap.add_argument("--dong-bo", default="", help="dong bo tu tep nguon nay sang các --dich (có xác minh neo)")
    ap.add_argument("--dich", action="append", default=[], help="tep dich cho --dong-bo (lap lai duoc)")
    ap.add_argument("--khong-sao-luu", action="store_true", help="không tạo .bak khi đồng bộ")
    ap.add_argument("--li-do", default="", help="ly do cap nhat/dong moc")
    ap.add_argument("--nguon", default="Codex_va_User", help="danh tính nguồn/agent sửa đổi (TC-06)")
    ap.add_argument("--ma-su-kien", default="", help="khóa nối mã sự kiện SK-... sang events.jsonl (TC-06)")
    ap.add_argument("--cwd", default=os.getcwd(), help="thu muc lam viec dung de lay neo git")
    ap.add_argument("--json", action="store_true", help="xuat JSON thay vi van ban")
    args = ap.parse_args(argv)

    gio = time.localtime()
    du_lieu = {
        "thoi_gian": neo_thoi_gian(),
        "phien": neo_phien(args.phien, os.getpid(), gio),
        "may": neo_may(args.cwd),
        "git": neo_git(args.cwd),
        "van_tay": neo_van_tay(args.file, args.text),
        "dong": neo_dong(args.line),
        "khoi": neo_khoi(args.block),
        "markers": neo_markers(args.markers),
        "so_sanh": neo_so_sanh(args.so),
        "viec": args.viec,
    }
    if os.path.isfile(SO_CAP_NHAT):
        try:
            with open(SO_CAP_NHAT, encoding="utf-8") as fh:
                du_lieu["so_dong_so"] = len([d for d in fh.read().splitlines() if d.strip()])
        except Exception:
            du_lieu["so_dong_so"] = 0
    if args.nen_so:
        du_lieu["nen_so"] = nen_so(du_lieu, giu_lai=args.giu_lai)
    elif du_lieu.get("so_dong_so", 0) > args.nguong:
        # tự nén khi vượt ngưỡng (không cần chờ gọi --nen-so)
        tu_dong = nen_tu_dong()
        if tu_dong:
            du_lieu["nen_so"] = tu_dong
    if args.dong_bo:
        if not args.dich:
            du_lieu["dong_bo"] = [{"nguon": args.dong_bo, "loi": "thieu --dich"}]
        else:
            du_lieu["dong_bo"] = dong_bo_neo(
                args.dong_bo, args.dich, not args.khong_sao_luu, du_lieu, args.li_do)
    if args.ledger or args.dong:
        du_lieu["so_cap_nhat"] = [ghi_so_cap_nhat(du_lieu, tep, args.li_do, nguon=args.nguon, ma_su_kien=args.ma_su_kien) for tep in args.file]
        if args.dong:
            du_lieu["dong_moc"] = ghi_dong_moc(du_lieu, du_lieu["so_cap_nhat"], args.li_do, nguon=args.nguon)
    if args.json:
        print(json.dumps(du_lieu, ensure_ascii=False, indent=2))
    else:
        in_nguoi_doc(du_lieu)
    return 0


if __name__ == "__main__":
    sys.exit(main())
