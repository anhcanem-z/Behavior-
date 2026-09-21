#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/audit_toolkit.py — quét kiểm tra toàn diện toolkit.

Kiểm tra theo từng lớp: lệnh CLI, nhãn hiển thị, khối quy tắc, đồng bộ giữa các bản sao,
neo (anchor), tài liệu bắt buộc, và công cụ nội bộ trong `tools/`.

Chỉ ĐỌC — không sửa tệp, không gọi mạng.

Cách dùng:
    python3 tools/audit_toolkit.py              # bản tóm tắt
    python3 tools/audit_toolkit.py --day-du     # liệt kê đầy đủ
    python3 tools/audit_toolkit.py --json       # xuất JSON cho máy đọc
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import time

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(TOOLKIT_DIR, "tools")

CLI_FILES = (
    os.path.join(TOOLKIT_DIR, "patchx_core", "cli.py"),
    os.path.join(TOOLKIT_DIR, "patchx_toolkit.py"),
)
DOC_FILES = (
    "HUONG_DAN_LENH.txt",
    "HUONG_DAN_BEHAVIOR_FRIDA.txt",
    "HUONG_DAN_GADGET.txt",
)
BAT_BUOC = (
    "toolkit.md",
    "apk.md",
    "AGENTS.md",
    "QUY_TAC_NGUOI_DUNG.md",
    "KINH_NGHIEM_HOC_HOI.md",
    "AGENTS_TRANG_THAI.md",
    "HUONG_DAN_LENH.txt",
    "HUONG_DAN_BEHAVIOR_FRIDA.txt",
    "HUONG_DAN_GADGET.txt",
)
BAT_BUOC_LITE = ("AGENTS.md", "QUY_TAC_NGUOI_DUNG.md", "AGENTS_TRANG_THAI.md", "HUONG_DAN_LENH.txt")
GOI_CLI_MAC_DINH = ("AGENTS.md", "CLAUDE.md", "GEMINI.md")
NOI_SAO_MAC_DINH = ("/storage/emulated/0/patchx", "/storage/emulated/0/toolkit")
CAU_HINH = os.path.join(TOOLKIT_DIR, "quy_tac_khoi", "dich.json")
MOC_CHAT_LUONG = os.path.join(TOOLKIT_DIR, "outputs", "anchor", "audit-snapshot.jsonl")


def _doc_cau_hinh() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Đọc danh sách bản sao + tệp quy tắc từ quy_tac_khoi/dich.json (một chỗ duy nhất)."""
    try:
        with open(CAU_HINH, encoding="utf-8") as fh:
            du_lieu = json.load(fh)
        bien = du_lieu.get("bien", {})

        def thay(duong_dan: str) -> str:
            for ten, gia_tri in bien.items():
                duong_dan = duong_dan.replace(ten, gia_tri)
            return duong_dan

        noi_sao = tuple(thay(x) for x in du_lieu.get("noi_sao", [])) or NOI_SAO_MAC_DINH
        goi_cli = tuple(du_lieu.get("goi_cli", [])) or GOI_CLI_MAC_DINH
        return noi_sao, goi_cli
    except Exception:
        return NOI_SAO_MAC_DINH, GOI_CLI_MAC_DINH


NOI_SAO, GOI_CLI = _doc_cau_hinh()


def bam_tep(duong_dan: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(duong_dan, "rb") as fh:
            for khoi in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(khoi)
        return h.hexdigest()
    except Exception:
        return None


def doc_dong(duong_dan: str) -> list[str]:
    try:
        with open(duong_dan, encoding="utf-8", errors="replace") as fh:
            return fh.read().split("\n")
    except Exception:
        return []


# ---------------------------------------------------------------- lớp 1: lệnh CLI
def quet_lenh() -> dict:
    theo_tep: dict[str, list[str]] = {}
    for tep in CLI_FILES:
        ten = os.path.relpath(tep, TOOLKIT_DIR)
        noi_dung = "\n".join(doc_dong(tep))
        theo_tep[ten] = sorted(set(re.findall(r'add_parser\(\s*"([^"]+)"', noi_dung)))
    tat_ca = [lenh for ds in theo_tep.values() for lenh in ds]
    trung = sorted({lenh for lenh in tat_ca if tat_ca.count(lenh) > 1})
    # lệnh thiếu mô tả: add_parser("x") không kèm help=
    thieu_mo_ta: list[str] = []
    for tep in CLI_FILES:
        noi_dung = "\n".join(doc_dong(tep))
        for khop in re.finditer(r'add_parser\(\s*"([^"]+)"\s*\)', noi_dung):
            thieu_mo_ta.append(khop.group(1))
    # đối chiếu tài liệu
    tai_lieu = "\n".join(
        "\n".join(doc_dong(os.path.join(TOOLKIT_DIR, d))) for d in DOC_FILES
    )
    chua_ghi_tai_lieu = sorted({lenh for lenh in tat_ca if lenh not in tai_lieu})
    return {
        "theo_tep": theo_tep,
        "tong": len(tat_ca),
        "trung": trung,
        "thieu_mo_ta": sorted(set(thieu_mo_ta)),
        "chua_ghi_tai_lieu": chua_ghi_tai_lieu,
    }


# ------------------------------------------------------- lớp 2: nhãn hiển thị
def quet_nhan() -> dict:
    nhan: dict[str, list[str]] = {}
    mau = re.compile(r"\[[A-Z][A-Z0-9-]{1,}\]")
    for tep in sorted(glob.glob(os.path.join(TOOLS_DIR, "*.py"))):
        # bỏ qua dòng định nghĩa regex (tránh tự bắt chính mẫu tìm nhãn)
        noi_dung = "\n".join(d for d in doc_dong(tep) if "re.compile" not in d)
        for nhan_muc in set(mau.findall(noi_dung)):
            nhan.setdefault(os.path.basename(tep), []).append(nhan_muc)
    tong = sum(len(v) for v in nhan.values())
    return {"theo_tep": {k: sorted(v) for k, v in nhan.items()}, "tong": tong}


# --------------------------------------------------------- lớp 3: khối quy tắc
def quet_khoi(duong_dan: str) -> list[dict]:
    dong = doc_dong(duong_dan)
    ket_qua: list[dict] = []
    dang_mo: tuple[str, int] | None = None
    for i, noi_dung in enumerate(dong, start=1):
        if ":BEGIN -->" in noi_dung and dang_mo is None:
            ten = noi_dung.split("<!--")[-1].split(":BEGIN")[0].strip()
            dang_mo = (ten, i)
        elif ":END -->" in noi_dung and dang_mo is not None:
            ten, bat_dau = dang_mo
            khoi = "\n".join(dong[bat_dau - 1:i])
            ket_qua.append({
                "khoi": ten,
                "tu_dong": bat_dau,
                "den_dong": i,
                "ma_bam": hashlib.sha256(khoi.encode("utf-8")).hexdigest(),
            })
            dang_mo = None
    return ket_qua


# ------------------------------------------------------ lớp 4: đồng bộ bản sao
def quet_dong_bo() -> dict:
    goc = os.path.join(TOOLKIT_DIR, "QUY_TAC_NGUOI_DUNG.md")
    ma_goc = bam_tep(goc)
    ket_qua: list[dict] = []
    for noi in NOI_SAO:
        tep = os.path.join(noi, "QUY_TAC_NGUOI_DUNG.md")
        ma = bam_tep(tep)
        if ma is None:
            ket_qua.append({"noi": noi, "trang_thai": "thiếu tệp"})
        elif ma == ma_goc:
            ket_qua.append({"noi": noi, "trang_thai": "giống bản gốc", "ma_bam": ma[:12]})
        else:
            ket_qua.append({"noi": noi, "trang_thai": "KHÁC bản gốc", "ma_bam": ma[:12],
                            "ma_bam_goc": (ma_goc or "")[:12]})
    # khối quy tắc lệch giữa các bản sao
    lech: list[dict] = []
    for ten in GOI_CLI:
        goc_khoi = {k["khoi"]: k["ma_bam"] for k in quet_khoi(os.path.join(TOOLKIT_DIR, ten))}
        for noi in NOI_SAO:
            tep = os.path.join(noi, ten)
            if not os.path.isfile(tep):
                continue
            for k in quet_khoi(tep):
                if k["khoi"] in goc_khoi and goc_khoi[k["khoi"]] != k["ma_bam"]:
                    lech.append({"tep": os.path.relpath(tep, "/"), "khoi": k["khoi"]})
    return {"quy_tac": ket_qua, "khoi_lech": lech}


# ------------------------------------------------------------------ lớp 5: neo
def quet_neo() -> dict:
    anchor = os.path.join(TOOLS_DIR, "anchor.py")
    ket_qua: dict = {"co_tep": os.path.isfile(anchor)}
    if not ket_qua["co_tep"]:
        return ket_qua
    ket_qua["ma_bam"] = (bam_tep(anchor) or "")[:12]
    try:
        proc = subprocess.run([sys.executable, anchor, "--json"], capture_output=True,
                              text=True, timeout=60, cwd=TOOLKIT_DIR)
        du_lieu = json.loads(proc.stdout)
        ket_qua["chay_duoc"] = True
        ket_qua["ma_moc"] = du_lieu.get("phien", {}).get("ma_moc_tu_sinh")
        ket_qua["git_head"] = (du_lieu.get("git") or {}).get("head")
    except Exception as loi:
        ket_qua["chay_duoc"] = False
        ket_qua["loi"] = str(loi)
    so = os.path.join(TOOLKIT_DIR, "outputs", "anchor", "ledger.jsonl")
    if os.path.isfile(so):
        dong = [d for d in doc_dong(so) if d.strip()]
        ket_qua["so_dong"] = len(dong)
        try:
            cuoi = json.loads(dong[-1])
            ket_qua["ban_ghi_cuoi"] = cuoi.get("kind")
            ket_qua["ma_moc_cuoi"] = cuoi.get("ma_moc")
        except Exception:
            pass
    else:
        ket_qua["so_dong"] = 0
    return ket_qua


# ------------------------------------------------------------ lớp 6: tài liệu
def quet_tai_lieu(ds_ten=BAT_BUOC) -> list[dict]:
    ket_qua: list[dict] = []
    for ten in ds_ten:
        tep = os.path.join(TOOLKIT_DIR, ten)
        if os.path.isfile(tep):
            ket_qua.append({"ten": ten, "co": True, "byte": os.path.getsize(tep)})
        else:
            ket_qua.append({"ten": ten, "co": False})
    return ket_qua


# -------------------------------------------------------- lớp 7: công cụ nội bộ
def quet_cong_cu() -> dict:
    tep = sorted(glob.glob(os.path.join(TOOLS_DIR, "*.py")))
    loi: list[dict] = []
    for duong_dan in tep:
        try:
            compile("\n".join(doc_dong(duong_dan)), duong_dan, "exec")
        except SyntaxError as exc:
            loi.append({"tep": os.path.basename(duong_dan), "loi": "cú pháp: %s" % exc})
        except Exception as exc:
            loi.append({"tep": os.path.basename(duong_dan), "loi": str(exc)})
    return {"tong": len(tep), "loi": loi}


def quet_tat_ca(lite: bool = False) -> dict:
    return {
        "neo_thieu": quet_neo_thieu(),
        "lenh": quet_lenh(),
        "nhan": quet_nhan(),
        "khoi": {ten: quet_khoi(os.path.join(TOOLKIT_DIR, ten))
                 for ten in ("AGENTS.md", "QUY_TAC_NGUOI_DUNG.md", "CLAUDE.md", "GEMINI.md")},
        "dong_bo": quet_dong_bo(),
        "neo": quet_neo(),
        "tai_lieu": quet_tai_lieu(BAT_BUOC_LITE if lite else BAT_BUOC),
        "cong_cu": quet_cong_cu(),
    }


def quet_neo_thieu() -> list[str]:
    """TC-01/TC-12: liệt kê tệp thay đổi (git) chưa có bản ghi neo hoặc sự kiện."""
    try:
        kq = subprocess.run(["git", "status", "--porcelain"], capture_output=True,
                            text=True, timeout=60, cwd=TOOLKIT_DIR)
    except Exception:
        return []
    ten: list[str] = []
    for dong in (kq.stdout or "").splitlines():
        duong_dan = dong[3:].strip()
        if not duong_dan or ".bak" in duong_dan or "backup" in duong_dan:
            continue
        if duong_dan.endswith("/"):
            continue  # bỏ qua thư mục, chỉ xét tệp
        ten.append(duong_dan)
    da_co: set[str] = set()
    for so in (os.path.join(TOOLKIT_DIR, "outputs", "anchor", "ledger.jsonl"),
               os.path.join(TOOLKIT_DIR, "outputs", "su_kien", "events.jsonl")):
        if not os.path.isfile(so):
            continue
        with open(so, encoding="utf-8", errors="replace") as fh:
            for dong in fh:
                try:
                    d = json.loads(dong)
                except Exception:
                    continue
                p = d.get("tep")
                if p:
                    da_co.add(os.path.basename(p))
    return [t for t in ten if os.path.basename(t) not in da_co]


def theo_doi_chat_luong(kq: dict, nghiem_trong: list[str], canh_bao: list[str]) -> dict:
    """Ghi mốc chất lượng và so với lần quét trước để phát hiện thoái hoá."""
    os.makedirs(os.path.dirname(MOC_CHAT_LUONG), exist_ok=True)
    truoc = None
    if os.path.isfile(MOC_CHAT_LUONG):
        try:
            with open(MOC_CHAT_LUONG, encoding="utf-8") as fh:
                dong = [d for d in fh.read().splitlines() if d.strip()]
            if dong:
                truoc = json.loads(dong[-1])
        except Exception:
            truoc = None
    hien_tai = {
        "gio": time.strftime("%F %T %Z"),
        "epoch": int(time.time()),
        "ma_moc": "PX-{}-{}".format(time.strftime("%Y%m%d-%H%M%S"), os.getpid()),
        "git_head": kq["neo"].get("git_head"),
        "so_lenh": kq["lenh"]["tong"],
        "lenh_thieu_mo_ta": len(kq["lenh"]["thieu_mo_ta"]),
        "lenh_chua_tai_lieu": len(kq["lenh"]["chua_ghi_tai_lieu"]),
        "nhan_khong_dau": kq["nhan"]["tong"],
        "tai_lieu_thieu": sum(1 for m in kq["tai_lieu"] if not m["co"]),
        "cong_cu_loi": len(kq["cong_cu"]["loi"]),
        "khoi_lech": len(kq["dong_bo"]["khoi_lech"]),
        "nghiem_trong": len(nghiem_trong),
        "canh_bao": len(canh_bao),
    }
    with open(MOC_CHAT_LUONG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(hien_tai, ensure_ascii=False) + "\n")
    return {"truoc": truoc, "hien_tai": hien_tai}


def in_theo_doi(kq_theo_doi: dict) -> None:
    truoc, nay = kq_theo_doi["truoc"], kq_theo_doi["hien_tai"]
    print("\n=== THEO DÕI CHẤT LƯỢNG (so với lần quét trước) ===")
    if not truoc:
        print("  Lần quét đầu tiên · cảnh báo %d · nghiêm trọng %d · mã mốc %s" % (
            nay["canh_bao"], nay["nghiem_trong"], nay["ma_moc"]))
        return
    print("  Lần trước: %s · cảnh báo %d · nghiêm trọng %d" % (
        truoc.get("gio"), truoc.get("canh_bao", 0), truoc.get("nghiem_trong", 0)))
    print("  Lần này:   %s · cảnh báo %d · nghiêm trọng %d" % (
        nay["gio"], nay["canh_bao"], nay["nghiem_trong"]))
    for khoa, nhan in (("canh_bao", "cảnh báo"), ("nghiem_trong", "nghiêm trọng"),
                       ("nhan_khong_dau", "nhãn không dấu"),
                       ("lenh_chua_tai_lieu", "lệnh chưa có tài liệu")):
        cu, moi = truoc.get(khoa, 0), nay.get(khoa, 0)
        if cu != moi:
            chieu = "tốt hơn" if moi < cu else "xấu đi"
            print("  Thay đổi %s: %+d (%s)" % (nhan, moi - cu, chieu))


def danh_gia(kq: dict) -> tuple[list[str], list[str]]:
    """Nguồn duy nhất quyết định mức độ: (vấn đề nghiêm trọng, cảnh báo không chặn)."""
    nghiem_trong: list[str] = []
    canh_bao: list[str] = []
    lenh = kq["lenh"]
    if lenh["trung"]:
        canh_bao.append("có %d lệnh trùng tên giữa 2 CLI" % len(lenh["trung"]))
    if lenh["thieu_mo_ta"]:
        canh_bao.append("%d lệnh thiếu mô tả" % len(lenh["thieu_mo_ta"]))
    if lenh["chua_ghi_tai_lieu"]:
        canh_bao.append("%d lệnh chưa có trong tài liệu" % len(lenh["chua_ghi_tai_lieu"]))
    if kq["nhan"]["tong"]:
        canh_bao.append("%d nhãn hiển thị viết không dấu" % kq["nhan"]["tong"])
    if kq.get("neo_thieu"):
        canh_bao.append("%d tệp thay đổi chưa có neo/sự kiện (TC-01)" % len(kq["neo_thieu"]))
    for muc in kq["dong_bo"]["quy_tac"]:
        if muc["trang_thai"].startswith("KHÁC"):
            nghiem_trong.append("bản sao lệch nội dung: %s" % muc["noi"])
    if kq["dong_bo"]["khoi_lech"]:
        nghiem_trong.append("%d khối quy tắc lệch giữa các bản sao" % len(kq["dong_bo"]["khoi_lech"]))
    neo = kq["neo"]
    if not neo.get("co_tep"):
        nghiem_trong.append("thiếu tools/anchor.py")
    elif not neo.get("chay_duoc"):
        nghiem_trong.append("anchor.py không chạy được")
    for muc in kq["tai_lieu"]:
        if not muc["co"]:
            nghiem_trong.append("thiếu tài liệu %s" % muc["ten"])
    for muc in kq["cong_cu"]["loi"]:
        nghiem_trong.append("lỗi ở %s" % muc["tep"])
    sync = os.path.join(TOOLS_DIR, "sync_rules.py")
    if os.path.isfile(sync):
        try:
            kq_sync = subprocess.run([sys.executable, sync], capture_output=True,
                                     text=True, timeout=120, cwd=TOOLKIT_DIR)
            if kq_sync.returncode != 0:
                nghiem_trong.append("khối quy tắc lệch nguồn chuẩn quy_tac_khoi/")
        except Exception:
            canh_bao.append("không chạy được sync_rules.py")
    return nghiem_trong, canh_bao


def in_tom_tat(kq: dict, nghiem_trong: list[str], canh_bao: list[str]) -> None:
    """Bản tóm tắt 7 dòng cho doctor mặc định."""
    lenh, neo = kq["lenh"], kq["neo"]
    so_tai_lieu = sum(1 for m in kq["tai_lieu"] if m["co"])
    so_khoi = sum(len(v) for v in kq["khoi"].values())
    so_giong = sum(1 for m in kq["dong_bo"]["quy_tac"] if m["trang_thai"] == "giống bản gốc")
    print("=== KIỂM TRA TOÀN DIỆN TOOLKIT (tóm tắt) ===")
    print("  Lệnh CLI: %d · thiếu mô tả: %d · chưa có tài liệu: %d" % (
        lenh["tong"], len(lenh["thieu_mo_ta"]), len(lenh["chua_ghi_tai_lieu"])))
    print("  Nhãn không dấu: %d · Khối quy tắc: %d khối trong %d tệp" % (
        kq["nhan"]["tong"], so_khoi, len(kq["khoi"])))
    print("  Đồng bộ bản sao: %d/%d giống bản gốc · Neo: %s (sổ %d dòng)" % (
        so_giong, len(kq["dong_bo"]["quy_tac"]),
        "đạt" if neo.get("chay_duoc") else "LỖI", neo.get("so_dong", 0)))
    print("  Tài liệu bắt buộc: %d/%d · Cú pháp công cụ nội bộ: %d/%d đạt" % (
        so_tai_lieu, len(kq["tai_lieu"]),
        kq["cong_cu"]["tong"] - len(kq["cong_cu"]["loi"]), kq["cong_cu"]["tong"]))
    if nghiem_trong:
        print("  KẾT LUẬN: %d vấn đề NGHIÊM TRỌNG" % len(nghiem_trong))
        for muc in nghiem_trong:
            print("    - %s" % muc)
    elif canh_bao:
        print("  KẾT LUẬN: đạt · %d cảnh báo (%s)" % (len(canh_bao), "; ".join(canh_bao)))
    else:
        print("  KẾT LUẬN: đạt, không có vấn đề")


def in_bao_cao(kq: dict, day_du: bool) -> int:
    nghiem_trong, canh_bao = danh_gia(kq)
    print("=== KIỂM TRA TOÀN DIỆN TOOLKIT ===")

    lenh = kq["lenh"]
    print("\n--- 1. Lệnh CLI ---")
    for ten, ds in lenh["theo_tep"].items():
        print("  %-28s %d lệnh" % (ten, len(ds)))
    print("  Tổng: %d lệnh" % lenh["tong"])
    if lenh["trung"]:
        print("  [CẢNH BÁO] lệnh trùng: %s" % ", ".join(lenh["trung"]))
    if lenh["thieu_mo_ta"]:
        print("  [CẢNH BÁO] thiếu mô tả: %s" % ", ".join(lenh["thieu_mo_ta"][:8]))
    if lenh["chua_ghi_tai_lieu"]:
        print("  [THIẾU] %d lệnh chưa có trong tài liệu hướng dẫn" % len(lenh["chua_ghi_tai_lieu"]))
        if day_du:
            print("           %s" % ", ".join(lenh["chua_ghi_tai_lieu"]))

    nhan = kq["nhan"]
    print("\n--- 2. Nhãn hiển thị không dấu ---")
    print("  Tổng nhãn ASCII: %d" % nhan["tong"])
    if day_du:
        for ten, ds in nhan["theo_tep"].items():
            print("    %-18s %s" % (ten, " ".join(ds)))
    if nhan["tong"]:
        pass

    print("\n--- 3. Khối quy tắc ---")
    for ten, ds in kq["khoi"].items():
        for k in ds:
            print("  %-22s %-26s dòng %d-%d · mã %s" % (
                ten, k["khoi"], k["tu_dong"], k["den_dong"], k["ma_bam"][:12]))

    dong_bo = kq["dong_bo"]
    print("\n--- 4. Đồng bộ bản sao ---")
    for muc in dong_bo["quy_tac"]:
        print("  %-34s %s" % (muc["noi"], muc["trang_thai"]))
        if muc["trang_thai"].startswith("KHÁC"):
            pass
    if dong_bo["khoi_lech"]:
        pass
        for muc in dong_bo["khoi_lech"][:5]:
            print("  [LỆCH] %s · khối %s" % (muc["tep"], muc["khoi"]))

    neo = kq["neo"]
    print("\n--- 5. Neo ---")
    if not neo.get("co_tep"):
        print("  [THIẾU] tools/anchor.py")
    else:
        print("  anchor.py: %s · mã băm %s" % (
            "chạy được" if neo.get("chay_duoc") else "LỖI", neo.get("ma_bam")))
        if neo.get("ma_moc"):
            print("  Mã mốc kiểm tra: %s · git %s" % (neo["ma_moc"], neo.get("git_head")))
        print("  Sổ bản cập nhật: %d dòng (bản ghi cuối: %s)" % (
            neo.get("so_dong", 0), neo.get("ban_ghi_cuoi", "?")))
        if not neo.get("chay_duoc"):
            pass

    print("\n--- 6. Tài liệu bắt buộc ---")
    for muc in kq["tai_lieu"]:
        if muc["co"]:
            print("  [ĐẠT]   %-32s %d byte" % (muc["ten"], muc["byte"]))
        else:
            print("  [THIẾU] %s" % muc["ten"])

    cong_cu = kq["cong_cu"]
    print("\n--- 7. Công cụ nội bộ ---")
    print("  Cú pháp: %d/%d đạt" % (cong_cu["tong"] - len(cong_cu["loi"]), cong_cu["tong"]))
    for muc in cong_cu["loi"]:
        print("  [LỖI]   %s: %s" % (muc["tep"], muc["loi"]))

    if nghiem_trong:
        print("\n=== VẤN ĐỀ NGHIÊM TRỌNG (%d) ===" % len(nghiem_trong))
        for muc in nghiem_trong:
            print("  - %s" % muc)
    if canh_bao:
        print("\n=== CẢNH BÁO, KHÔNG CHẶN (%d) ===" % len(canh_bao))
        for muc in canh_bao:
            print("  - %s" % muc)
    if not nghiem_trong and not canh_bao:
        print("\n=== KẾT LUẬN: không phát hiện vấn đề ===")
    elif not nghiem_trong:
        print("\n=== KẾT LUẬN: đạt, còn %d cảnh báo hình thức ===" % len(canh_bao))
    return 1 if nghiem_trong else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Quét kiểm tra toàn diện toolkit (lệnh, nhãn, khối, neo, đồng bộ).")
    ap.add_argument("--day-du", action="store_true", help="liệt kê đầy đủ thay vì tóm tắt")
    ap.add_argument("--tom-tat", action="store_true", help="chỉ in bản tóm tắt (dùng cho doctor mặc định)")
    ap.add_argument("--theo-doi", action="store_true",
                    help="ghi mốc chất lượng vào outputs/anchor/audit-snapshot.jsonl và so lần trước")
    ap.add_argument("--lite", action="store_true",
                    help="chế độ toolkit rút gọn: chỉ yêu cầu 4 tài liệu tối thiểu")
    ap.add_argument("--json", action="store_true", help="xuất JSON")
    args = ap.parse_args(argv)
    kq = quet_tat_ca(lite=args.lite)
    nghiem_trong, canh_bao = danh_gia(kq)
    if args.theo_doi:
        kq["theo_doi"] = theo_doi_chat_luong(kq, nghiem_trong, canh_bao)
    if args.json:
        kq["nghiem_trong"] = nghiem_trong
        kq["canh_bao"] = canh_bao
        print(json.dumps(kq, ensure_ascii=False, indent=2))
        return 1 if nghiem_trong else 0
    if args.tom_tat:
        in_tom_tat(kq, nghiem_trong, canh_bao)
        if args.theo_doi:
            in_theo_doi(kq["theo_doi"])
        return 1 if nghiem_trong else 0
    ma = in_bao_cao(kq, args.day_du)
    if args.theo_doi:
        in_theo_doi(kq["theo_doi"])
    return ma


if __name__ == "__main__":
    sys.exit(main())
