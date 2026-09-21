#!/usr/bin/env python3
"""Sinh danh sách ngôn ngữ Google -> chuỗi smali cho `MainActivity` của APK `Apks/2`.

Nguồn: `outputs/ngon_ngu_google/google_languages_vi.json` (tải từ chính endpoint Google
Translate dùng: https://translate.googleapis.com/translate_a/l?client=gtx&alpha=1&hl=vi).

Quy ước của APP (giữ nguyên để không phá các bảng ánh xạ sẵn có):
  - mã nội bộ `zh-Hans` / `zh-Hant` (app tự đổi sang `zh-CN` / `zh-TW` khi gọi Google,
    và đổi sang `zh` khi gọi ML Kit) => thay `zh-CN`/`zh-TW` của Google bằng 2 mã này.
  - nhãn hiển thị: "Tiếng <tên tiếng Việt> (<mã nội bộ>)".

Dùng:
  python3 tools/sinh_danh_sach_ngon_ngu.py            # in thống kê + ghi tệp trong outputs/
  python3 tools/sinh_danh_sach_ngon_ngu.py --json     # in JSON cho máy đọc
"""

from __future__ import annotations

import argparse
import json
import os
import sys

GOC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGUON = os.path.join(GOC, "outputs", "ngon_ngu_google", "google_languages_vi.json")
RA = os.path.join(GOC, "outputs", "ngon_ngu_google")

# Mã Google -> mã nội bộ của app (app đã có sẵn 2 nhánh đổi mã này)
DOI_MA = {"zh-CN": "zh-Hans", "zh-TW": "zh-Hant"}


def smali_chuoi(s: str) -> str:
    """Bọc 1 chuỗi thành literal smali, escape mọi ký tự ngoài ASCII thành \\uXXXX."""
    ra = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            ra.append('\\"')
        elif ch == "\\":
            ra.append("\\\\")
        elif 32 <= o < 127:
            ra.append(ch)
        elif o > 0xFFFF:  # ngoài BMP -> cặp surrogate như Java/máy ảo Android
            o -= 0x10000
            ra.append("\\u%04x\\u%04x" % (0xD800 + (o >> 10), 0xDC00 + (o & 0x3FF)))
        else:
            ra.append("\\u%04x" % o)
    return '"' + "".join(ra) + '"'


def doc_nguon() -> list[tuple[str, str]]:
    d = json.load(open(NGUON, encoding="utf-8"))["tl"]
    ds = []
    for ma, ten in d.items():
        noi_bo = DOI_MA.get(ma, ma)
        ds.append((noi_bo, ten))
    # sắp theo tên tiếng Việt cho dễ tìm trong spinner
    ds.sort(key=lambda x: (x[1].lower(), x[0]))
    return ds


def main() -> int:
    ap = argparse.ArgumentParser(description="Sinh danh sách ngôn ngữ Google cho smali.")
    ap.add_argument("--json", action="store_true", help="in JSON thay vì văn bản")
    a = ap.parse_args()
    if not os.path.isfile(NGUON):
        print("THIẾU nguồn: %s" % NGUON, file=sys.stderr)
        return 2
    ds = doc_nguon()
    ma = "|".join(["auto"] + [m for m, _ in ds])
    nhan = "|".join(["Tự động (auto)"] + ["Tiếng %s (%s)" % (t, m) for m, t in ds])
    nhan_nguon = "|".join(["Tự động (auto)"] + ["Tiếng %s (%s)" % (t, m) for m, t in ds])
    ma_nguon = "|".join(["auto"] + [m for m, _ in ds])
    kq = {
        "so_ngon_ngu": len(ds),
        "nguon": NGUON,
        "ma_dich": smali_chuoi(ma),
        "nhan_dich": smali_chuoi(nhan),
        "ma_nguon": smali_chuoi(ma_nguon),
        "nhan_nguon": smali_chuoi(nhan_nguon),
        "danh_sach": [{"ma": m, "ten_vi": t} for m, t in ds],
    }
    os.makedirs(RA, exist_ok=True)
    with open(os.path.join(RA, "danh_sach_ngon_ngu.json"), "w", encoding="utf-8") as f:
        json.dump(kq, f, ensure_ascii=False, indent=1)
    with open(os.path.join(RA, "smali_nguon.txt"), "w", encoding="utf-8") as f:
        f.write("const-string v1, %s\n\nconst-string v2, %s\n" % (kq["ma_nguon"], kq["nhan_nguon"]))
    with open(os.path.join(RA, "smali_dich.txt"), "w", encoding="utf-8") as f:
        f.write("const-string v1, %s\n\nconst-string v2, %s\n" % (kq["ma_dich"], kq["nhan_dich"]))
    if a.json:
        print(json.dumps({k: v for k, v in kq.items() if k != "danh_sach"}, ensure_ascii=False, indent=1))
        return 0
    print("=== DANH SÁCH NGÔN NGỮ GOOGLE ===")
    print("  nguồn        : %s" % NGUON)
    print("  số ngôn ngữ  : %d (nguồn có thêm mục 'Tự động (auto)')" % len(ds))
    print("  độ dài chuỗi mã  : %d ký tự" % len(ma_nguon))
    print("  độ dài chuỗi nhãn: %d ký tự" % len(nhan_nguon))
    print("  đã ghi: outputs/ngon_ngu_google/{danh_sach_ngon_ngu.json, smali_nguon.txt, smali_dich.txt}")
    print("  10 mục đầu (nguồn): %s" % ", ".join("%s=%s" % (m, t) for m, t in ds[:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
