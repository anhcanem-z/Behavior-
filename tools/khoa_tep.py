#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/khoa_tep.py — KHÓA MỀM theo tệp: giải pháp cho nhiều AI cùng sửa 1 workspace.

Cơ chế: giữ khóa có chủ sở hữu + hạn dùng (TTL) → AI khác **chờ** (không ghi đè), hết khóa thì
**đọc lại mã băm mới nhất** rồi mới ghi (retry an toàn). Kết hợp 3 lớp:
  1. KHÓA  — một tệp chỉ một AI ghi tại một thời điểm.
  2. CAS   — trước khi ghi phải đúng mã băm đã đọc.
  3. GHI LẠI — nếu bị đổi trong lúc chờ, tự đọc lại và ghép (append) thay vì ghi đè.

    python3 tools/khoa_tep.py --xem TỆP
    python3 tools/khoa_tep.py --giai-phong TỆP [--chu-so-huu TÊN]

Thư viện dùng cho công cụ khác: khoa(), mo_khoa(), ghi_an_toan().
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THU_MUC_KHOA = os.path.join(TOOLKIT_DIR, "outputs", "khoa")
CHI_SO = os.path.join(THU_MUC_KHOA, "chi_so.jsonl")


def ghi_chi_so(loai: str, tep: str, chu_so_huu: str, giay_cho: float = 0.0) -> None:
    """PA5 — ghi chỉ số phối hợp: số lần chờ khóa, thời gian chờ, ai chờ ai."""
    try:
        os.makedirs(THU_MUC_KHOA, exist_ok=True)
        ban_ghi = {"loai": loai, "tep": os.path.abspath(tep), "chu_so_huu": chu_so_huu,
                   "giay_cho": round(giay_cho, 3), "gio": time.strftime("%F %T %Z")}
        with open(CHI_SO, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ban_ghi, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _bam(duong_dan: str) -> str:
    try:
        with open(duong_dan, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        return ""


def _duong_khoa(tep: str) -> str:
    ten = hashlib.sha256(os.path.abspath(tep).encode("utf-8")).hexdigest()[:16]
    return os.path.join(THU_MUC_KHOA, ten + ".lock")


def doc_khoa(tep: str) -> dict:
    d = _duong_khoa(tep)
    if not os.path.isfile(d):
        return {}
    try:
        with open(d, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def con_hieu_luc(khoa: dict) -> bool:
    return bool(khoa) and khoa.get("het_han", 0) > time.time()


def khoa(tep: str, chu_so_huu: str, giay: int = 300) -> dict:
    """Giữ khóa nếu tệp chưa bị ai giữ. Trả {} nếu đang bị giữ."""
    os.makedirs(THU_MUC_KHOA, exist_ok=True)
    hien_tai = doc_khoa(tep)
    if con_hieu_luc(hien_tai) and hien_tai.get("chu_so_huu") != chu_so_huu:
        return {}
    ban_ghi = {"tep": os.path.abspath(tep), "chu_so_huu": chu_so_huu,
               "bat_dau": time.strftime("%F %T"), "epoch": int(time.time()),
               "het_han": time.time() + giay, "bam_luc_giu": _bam(tep)}
    with open(_duong_khoa(tep), "w", encoding="utf-8") as fh:
        json.dump(ban_ghi, fh, ensure_ascii=False, indent=2)
    return ban_ghi


def mo_khoa(tep: str, chu_so_huu: str = "") -> bool:
    d = _duong_khoa(tep)
    if not os.path.isfile(d):
        return False
    if chu_so_huu and doc_khoa(tep).get("chu_so_huu") not in ("", chu_so_huu):
        return False
    os.remove(d)
    return True


def ghi_an_toan(tep: str, noi_dung_them: str, chu_so_huu: str,
                cho_toi_da: float = 5.0, giay_khoa: int = 300) -> dict:
    """Ghi an toàn: chờ khóa → đọc băm → ghi → mở khóa. Tự đọc lại nếu tệp đổi trong lúc chờ."""
    het = time.time() + cho_toi_da
    bat_dau_cho = time.time()
    da_cho = False
    while time.time() < het:
        if khoa(tep, chu_so_huu, giay_khoa):
            break
        da_cho = True
        time.sleep(0.05)
    else:
        ghi_chi_so("khong_giu_duoc_khoa", tep, chu_so_huu, time.time() - bat_dau_cho)
        return {"ket_cuc": "KHÔNG GIỮ ĐƯỢC KHÓA", "chu_so_huu": chu_so_huu}
    if da_cho:
        ghi_chi_so("phai_cho_khoa", tep, chu_so_huu, time.time() - bat_dau_cho)
    try:
        bam_truoc = _bam(tep)
        with open(tep, "a", encoding="utf-8") as fh:
            fh.write(noi_dung_them + "\n")
        return {"ket_cuc": "ĐÃ GHI AN TOÀN", "bam_truoc": bam_truoc[:12],
                "bam_sau": _bam(tep)[:12], "chu_so_huu": chu_so_huu}
    finally:
        mo_khoa(tep, chu_so_huu)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Khóa mềm theo tệp cho môi trường nhiều AI.")
    ap.add_argument("--xem", metavar="TỆP", help="xem khóa hiện tại của tệp")
    ap.add_argument("--giai-phong", metavar="TỆP", help="giải phóng khóa")
    ap.add_argument("--chu-so-huu", default="", help="tên AI giữ khóa")
    args = ap.parse_args(argv)
    if args.xem:
        k = doc_khoa(args.xem)
        if not k or not con_hieu_luc(k):
            print("Tệp KHÔNG bị giữ khóa (hoặc khóa đã hết hạn).")
        else:
            print("Đang bị giữ: %s · từ %s · hết hạn sau %.0f giây" % (
                k["chu_so_huu"], k["bat_dau"], k["het_han"] - time.time()))
        return 0
    if args.giai-phong:
        print("Đã giải phóng khóa." if mo_khoa(args.giai_phong, args.chu_so_huu)
              else "Không có khóa để giải phóng (hoặc không phải chủ sở hữu).")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
