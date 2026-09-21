#!/usr/bin/env python3
"""Cổng kiểm PHẠM VI (mục A/B của quy tắc giới hạn phạm vi quyền).

Mọi đường dẫn phải nằm TRONG cây được phép:
  1. thư mục làm việc (cwd) + mọi thư mục con của nó;
  2. (các) cây do User gọi tên — truyền qua --cho-phep;
  3. thư mục có TÊN GẦN GIỐNG >= 90% (difflib) với tên của một cây ở mục 1/2.

Ngoài các mục trên: r=0, w=0 (trừ hạ tầng đọc /data/data/com.termux/files/usr).

Dùng:
  python3 tools/kiem_pham_vi.py --cwd . /data/.../home/tmp/x outputs/tmp_chan_doan
  python3 tools/kiem_pham_vi.py --tu-kiem          # tự kiểm chiều dương + chiều âm
"""

from __future__ import annotations

import argparse
import difflib
import os
import sys

HA_TANG_DOC = "/data/data/com.termux/files/usr"
NGUONG_GAN_GIONG = 0.90


def chuan_ten(duong_dan: str) -> str:
    """Tên thư mục đã chuẩn hoá: bỏ tiền tố . _ và hậu tố số thứ tự, viết thường."""
    ten = os.path.basename(os.path.normpath(duong_dan)).strip().lower()
    while ten[:1] in (".", "_"):
        ten = ten[1:]
    while ten and ten[-1].isdigit():
        ten = ten[:-1]
    return ten.rstrip("._-")


def ti_le_ten(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, chuan_ten(a), chuan_ten(b)).ratio()


def nam_trong(con: str, cha: str) -> bool:
    con = os.path.realpath(con)
    cha = os.path.realpath(cha)
    return con == cha or con.startswith(cha.rstrip("/") + "/")


def kiem_mot(duong_dan: str, cho_phep: list[str], cwd: str) -> tuple[bool, str]:
    """Trả (hợp_lệ, lý_do)."""
    for cay in cho_phep:
        if nam_trong(duong_dan, cay):
            return True, f"nằm trong cây được phép {os.path.realpath(cay)}"
    if nam_trong(duong_dan, HA_TANG_DOC):
        return True, "hạ tầng chạy CLI (chỉ ĐỌC được phép theo ngoại lệ C.1)"
    cao_nhat, ten_cay = 0.0, ""
    for cay in cho_phep:
        r = ti_le_ten(duong_dan, cay)
        if r > cao_nhat:
            cao_nhat, ten_cay = r, cay
    if cao_nhat >= NGUONG_GAN_GIONG:
        return True, f"tên gần giống {cao_nhat:.3f} (>= 0,90) với {ten_cay}"
    return False, f"gần giống cao nhất chỉ {cao_nhat:.3f} với {ten_cay or '(không có cây cho phép)'}"


def chay(duong_dan_list: list[str], cho_phep: list[str], cwd: str) -> int:
    so_sai = 0
    print("=== CỔNG KIỂM PHẠM VI ===")
    print(f"  cây cho phép: {', '.join(os.path.realpath(c) for c in cho_phep)}")
    for d in duong_dan_list:
        hop_le, ly_do = kiem_mot(d, cho_phep, cwd)
        nhan = "[TRONG PHẠM VI]" if hop_le else "[NGOÀI PHẠM VI - CẤM]"
        print(f"  {nhan} {d} — {ly_do}")
        if not hop_le:
            so_sai += 1
    print(f"Kết luận: {so_sai} đường dẫn NGOÀI phạm vi / {len(duong_dan_list)} đường dẫn kiểm.")
    return 1 if so_sai else 0


def tu_kiem() -> int:
    """Chiều dương (phải cho qua) + chiều âm (phải chặn)."""
    cwd = os.path.realpath(".")
    cho_phep = [cwd]
    goc = os.path.dirname(cwd)
    ca_thu = [
        (os.path.join(cwd, "Apks/2"), True, "thư mục con của cwd"),
        (cwd, True, "chính cwd"),
        (os.path.join(goc, os.path.basename(cwd).lstrip("_")), True, "tên gần giống (vd _patchx ↔ patchx)"),
        ("/data/data/com.termux/files/usr/bin/python3", True, "hạ tầng chỉ đọc"),
        (os.path.join(goc, "smartkit"), False, "cây khác, tên không gần giống"),
        ("/storage/emulated/0/toolkit", False, "cây khác, tên không gần giống"),
        ("/storage/emulated/0/patchx", True, "bản sao tên gần giống 0,923 với _patchx (được phép)"),
    ]
    so_loi = 0
    for duong_dan, mong_doi, mo_ta in ca_thu:
        hop_le, ly_do = kiem_mot(duong_dan, cho_phep, cwd)
        dat = hop_le == mong_doi
        if not dat:
            so_loi += 1
        print(f"  [{'ĐẠT' if dat else 'SAI'}] mong đợi {'cho qua' if mong_doi else 'chặn'} — {mo_ta} ({ly_do})")
    print(f"Kết luận tự kiểm: {'ĐẠT' if not so_loi else 'SAI ' + str(so_loi) + ' ca'}")
    return 1 if so_loi else 0


def main() -> int:
    p = argparse.ArgumentParser(description="Cổng kiểm phạm vi đường dẫn theo quy tắc của User.")
    p.add_argument("duong_dan", nargs="*", help="đường dẫn cần kiểm")
    p.add_argument("--cwd", default=".", help="thư mục làm việc (cây mặc định được phép)")
    p.add_argument("--cho-phep", action="append", default=[], help="cây do User gọi tên (lặp lại được)")
    p.add_argument("--tu-kiem", action="store_true", help="tự kiểm chiều dương + chiều âm")
    a = p.parse_args()
    if a.tu_kiem:
        return tu_kiem()
    cho_phep = [os.path.realpath(a.cwd)] + [os.path.realpath(x) for x in a.cho_phep]
    if not a.duong_dan:
        p.print_help()
        return 2
    return chay(a.duong_dan, cho_phep, os.path.realpath(a.cwd))


if __name__ == "__main__":
    sys.exit(main())
