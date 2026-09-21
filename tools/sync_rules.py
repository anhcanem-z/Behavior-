#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/sync_rules.py — đồng bộ các KHỐI QUY TẮC từ MỘT NGUỒN DUY NHẤT.

Nguồn chuẩn: `quy_tac_khoi/<TÊN-KHỐI>.md` (mỗi tệp chứa trọn khối kèm cặp marker
BEGIN/END). Công cụ này thay khối trong từng tệp đích bằng đúng nội dung nguồn, nên
không còn chuyện chép tay 13 nơi rồi lệch nhau.

Chỉ ĐỌC khi không có `--apply`. Khi có `--apply`: sao lưu `*.bak.<mã mốc>` trước khi ghi,
ghi xong kiểm lại mã băm từng khối, rồi ghi sổ neo cho các tệp đã đổi.

Cách dùng:
    python3 tools/sync_rules.py                 # kiểm tra lệch (dry-run), exit 1 nếu lệch
    python3 tools/sync_rules.py --apply         # ghi thật (có sao lưu + xác minh)
    python3 tools/sync_rules.py --json          # xuất JSON
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGUON_DIR = os.path.join(TOOLKIT_DIR, "quy_tac_khoi")
HOME = os.path.expanduser("~")
CAU_HINH = os.path.join(NGUON_DIR, "dich.json")

SAO = "/storage/emulated/0"

KHOI_CO_BAN = (
    "PATCHX-SCOPE-RULE",
    "PATCHX-MANDATORY-RULES",
    "PATCHX-ALL-TOOLKITS-RULE",
    "PATCHX-CONFLICT-CHECK-RULE",
    "PATCHX-MULTI-ANCHOR-RULE",
)
KHOI_KHONG_MARKER = ("PATCHX-ALL-TOOLKITS-RULE", "PATCHX-CONFLICT-CHECK-RULE",
                     "PATCHX-MULTI-ANCHOR-RULE")


def _thay_bien(duong_dan: str, bien: dict) -> str:
    for ten, gia_tri in bien.items():
        duong_dan = duong_dan.replace(ten, gia_tri)
    return duong_dan


def doc_cau_hinh() -> tuple[tuple[tuple[str, tuple[str, ...]], ...], bool]:
    """Đọc danh sách đích từ quy_tac_khoi/dich.json. Trả (danh sách đích, có cấu hình hay không)."""
    try:
        with open(CAU_HINH, encoding="utf-8") as fh:
            du_lieu = json.load(fh)
    except Exception:
        return (), False
    bien = du_lieu.get("bien", {})
    # nạp ĐỘNG mọi danh sách khối (key có giá trị là list các tên bắt đầu bằng PATCHX-)
    bang_khoi = {
        "khoi_co_ban": tuple(du_lieu.get("khoi_co_ban", KHOI_CO_BAN)),
        "khoi_khong_marker": tuple(du_lieu.get("khoi_khong_marker", KHOI_KHONG_MARKER)),
    }
    for ten, gia_tri in du_lieu.items():
        if (isinstance(gia_tri, list) and gia_tri
                and all(isinstance(x, str) and x.startswith("PATCHX-") for x in gia_tri)):
            bang_khoi.setdefault(ten, tuple(gia_tri))
    ket_qua = []
    for muc in du_lieu.get("dich", []):
        ten_khoi = muc.get("khoi", "khoi_co_ban")
        ds_khoi = bang_khoi.get(ten_khoi, tuple(ten_khoi) if isinstance(ten_khoi, list) else KHOI_CO_BAN)
        ket_qua.append((_thay_bien(muc["tep"], bien), ds_khoi))
    return tuple(ket_qua), bool(ket_qua)

# (đường dẫn đích, danh sách khối phải có)
DICH_MAC_DINH: tuple[tuple[str, tuple[str, ...]], ...] = (
    (os.path.join(TOOLKIT_DIR, "AGENTS.md"), KHOI_KHONG_MARKER),
    (os.path.join(TOOLKIT_DIR, "CLAUDE.md"), KHOI_CO_BAN),
    (os.path.join(TOOLKIT_DIR, "GEMINI.md"), KHOI_CO_BAN),
    (os.path.join(HOME, ".codex", "AGENTS.md"), KHOI_CO_BAN),
    (os.path.join(HOME, ".claude", "CLAUDE.md"), KHOI_CO_BAN),
    (os.path.join(HOME, ".gemini", "GEMINI.md"), KHOI_CO_BAN),
    (os.path.join(HOME, ".config", "opencode", "AGENTS.md"), KHOI_CO_BAN),
    (os.path.join(SAO, "patchx", "AGENTS.md"), KHOI_KHONG_MARKER),
    (os.path.join(SAO, "patchx", "CLAUDE.md"), KHOI_CO_BAN),
    (os.path.join(SAO, "patchx", "GEMINI.md"), KHOI_CO_BAN),
    (os.path.join(SAO, "toolkit", "AGENTS.md"), KHOI_CO_BAN),
    (os.path.join(SAO, "toolkit", "CLAUDE.md"), KHOI_CO_BAN),
    (os.path.join(SAO, "toolkit", "GEMINI.md"), KHOI_CO_BAN),
)

DICH, _CO_CAU_HINH = doc_cau_hinh()
if not DICH:
    DICH = DICH_MAC_DINH


def bam(chuoi: str) -> str:
    return hashlib.sha256(chuoi.encode("utf-8")).hexdigest()


def doc(duong_dan: str) -> str:
    try:
        with open(duong_dan, encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""


def khoi_nguon(ten: str) -> str:
    duong_dan = os.path.join(NGUON_DIR, ten + ".md")
    return doc(duong_dan).rstrip("\n")


def khoi_trong_tep(noi_dung: str, ten: str) -> str | None:
    b = "<!-- {}:BEGIN -->".format(ten)
    e = "<!-- {}:END -->".format(ten)
    i, j = noi_dung.find(b), noi_dung.find(e)
    if i == -1 or j == -1:
        return None
    return noi_dung[i:j + len(e)]


def kiem_tra() -> tuple[list[dict], bool]:
    ket_qua: list[dict] = []
    co_loi = False
    for duong_dan, ds_khoi in DICH:
        noi_dung = doc(duong_dan)
        if not noi_dung:
            ket_qua.append({"tep": duong_dan, "trang_thai": "không đọc được"})
            co_loi = True
            continue
        for ten in ds_khoi:
            nguon = khoi_nguon(ten)
            if not nguon:
                ket_qua.append({"tep": duong_dan, "khoi": ten, "trang_thai": "thiếu nguồn chuẩn"})
                co_loi = True
                continue
            hien_tai = khoi_trong_tep(noi_dung, ten)
            if hien_tai is None:
                ket_qua.append({"tep": duong_dan, "khoi": ten, "trang_thai": "thiếu khối"})
                co_loi = True
            elif bam(hien_tai.rstrip("\n")) != bam(nguon):
                ket_qua.append({"tep": duong_dan, "khoi": ten, "trang_thai": "lệch nội dung",
                                "ma_hien_tai": bam(hien_tai.rstrip("\n"))[:12],
                                "ma_chuan": bam(nguon)[:12]})
                co_loi = True
            else:
                ket_qua.append({"tep": duong_dan, "khoi": ten, "trang_thai": "đủ"})
    return ket_qua, co_loi


def ap_dung(ma_moc: str) -> tuple[list[dict], list[str]]:
    ket_qua: list[dict] = []
    da_doi: list[str] = []
    for duong_dan, ds_khoi in DICH:
        noi_dung = doc(duong_dan)
        if not noi_dung:
            ket_qua.append({"tep": duong_dan, "trang_thai": "không đọc được"})
            continue
        goc = noi_dung
        thay: list[str] = []
        for ten in ds_khoi:
            nguon = khoi_nguon(ten)
            if not nguon:
                continue
            hien_tai = khoi_trong_tep(noi_dung, ten)
            if hien_tai is None or bam(hien_tai.rstrip("\n")) != bam(nguon):
                if hien_tai is None:
                    noi_dung = noi_dung.rstrip("\n") + "\n\n" + nguon + "\n"
                else:
                    noi_dung = noi_dung.replace(hien_tai, nguon)
                thay.append(ten)
        if noi_dung == goc:
            ket_qua.append({"tep": duong_dan, "trang_thai": "không cần đổi"})
            continue
        try:
            shutil.copy2(duong_dan, "{}.bak.{}".format(duong_dan, ma_moc))
            with open(duong_dan, "w", encoding="utf-8") as fh:
                fh.write(noi_dung)
        except Exception as loi:
            ket_qua.append({"tep": duong_dan, "trang_thai": "lỗi ghi: %s" % loi})
            continue
        # xác minh lại bằng neo
        kiem = doc(duong_dan)
        xac_minh = all(
            (khoi_trong_tep(kiem, ten) or "").rstrip("\n") == khoi_nguon(ten)
            for ten in ds_khoi if khoi_nguon(ten)
        )
        ket_qua.append({"tep": duong_dan, "trang_thai": "đã ghi", "khoi_da_doi": thay,
                        "xac_minh": xac_minh})
        if xac_minh:
            da_doi.append(duong_dan)
    return ket_qua, da_doi


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Đồng bộ các khối quy tắc từ một nguồn chuẩn duy nhất.")
    ap.add_argument("--apply", action="store_true", help="ghi thật (mặc định chỉ kiểm tra)")
    ap.add_argument("--json", action="store_true", help="xuất JSON")
    args = ap.parse_args(argv)

    if not os.path.isdir(NGUON_DIR):
        print("THIẾU thư mục nguồn chuẩn: %s" % NGUON_DIR)
        return 1

    ma_moc = "PX-{}-{}".format(__import__("time").strftime("%Y%m%d-%H%M%S"), os.getpid())
    da_doi: list[str] = []
    if args.apply:
        ket_qua, da_doi = ap_dung(ma_moc)
    else:
        ket_qua, co_loi = kiem_tra()
        if args.json:
            print(json.dumps({"kenh": "kiem-tra", "ket_qua": ket_qua}, ensure_ascii=False, indent=2))
            return 1 if co_loi else 0
        print("=== ĐỒNG BỘ KHỐI QUY TẮC (kiểm tra) ===")
        for muc in ket_qua:
            if muc["trang_thai"] == "đủ":
                continue
            print("  [LỆCH] %s · %s · %s" % (muc["tep"], muc.get("khoi", "-"), muc["trang_thai"]))
        print("Kết luận: %s" % ("có khối lệch/thiếu — chạy --apply để đồng bộ" if co_loi
                                else "mọi khối quy tắc đã khớp nguồn chuẩn"))
        return 1 if co_loi else 0

    if args.json:
        print(json.dumps({"kenh": "ap-dung", "ma_moc": ma_moc, "ket_qua": ket_qua},
                         ensure_ascii=False, indent=2))
    else:
        print("=== ĐỒNG BỘ KHỐI QUY TẮC (đã ghi) · mã mốc %s ===" % ma_moc)
        for muc in ket_qua:
            if muc["trang_thai"] == "đã ghi":
                print("  [ĐÃ GHI] %s · xác minh=%s · %s" % (
                    muc["tep"], muc.get("xac_minh"), ", ".join(muc.get("khoi_da_doi", []))))
            elif muc["trang_thai"].startswith("lỗi") or muc["trang_thai"] == "không đọc được":
                print("  [LỖI]    %s · %s" % (muc["tep"], muc["trang_thai"]))
        print("Tệp đã đổi: %d" % len(da_doi))

    if da_doi:
        anchor = os.path.join(TOOLKIT_DIR, "tools", "anchor.py")
        lenh = [sys.executable, anchor, "--viec", "dong-bo-khoi-quy-tac",
                "--li-do", "sync_rules --apply", "--ledger"]
        for tep in da_doi:
            lenh += ["--file", tep]
        try:
            subprocess.run(lenh, capture_output=True, text=True, timeout=300)
            print("Đã ghi sổ neo cho %d tệp đã đổi." % len(da_doi))
        except Exception as loi:
            print("Không ghi được sổ neo: %s" % loi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
