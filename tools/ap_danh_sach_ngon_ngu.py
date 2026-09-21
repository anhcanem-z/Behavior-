#!/usr/bin/env python3
"""Áp danh sách ngôn ngữ Google vào `MainActivity.<init>` của cây APK `Apks/2`.

Chèn 2 khối gán bằng `String.split` (gọn hơn ~1000 dòng `aput-object`):
  - sourceOptions / sourceLabels  (có mục "Tự động (auto)")
  - languageOptions / languageLabels (ngôn ngữ đích, không có "auto")

Nguyên tắc an toàn:
  - mỗi neo phải xuất hiện ĐÚNG 1 lần trong tệp, nếu không thì DỪNG (không sửa);
  - chạy lại nhiều lần không nhân đôi (nhận diện dấu `# PATCHX-DS-NGON-NGU`);
  - in mã băm trước/sau; KHÔNG tự sao lưu (việc sao lưu do phiên gọi thực hiện).

Dùng: python3 tools/ap_danh_sach_ngon_ngu.py [--cay Apks/2] [--kho]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

GOC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.join(GOC, "outputs", "ngon_ngu_google")
DAU = "# PATCHX-DS-NGON-NGU"


def bam(p: str) -> str:
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def doc_snippet(ten: str) -> tuple[str, str]:
    """Trả (chuỗi mã, chuỗi nhãn) đã ở dạng literal smali."""
    khoi = open(os.path.join(DS, ten), encoding="utf-8").read().strip().splitlines()
    ma = khoi[0].split(", ", 1)[1]
    nhan = khoi[2].split(", ", 1)[1]
    return ma, nhan


def khoi_ngon_ngu(ma: str, nhan: str, truong_ma: str, truong_nhan: str) -> str:
    return f"""    {DAU}: danh sách đầy đủ theo Google Translate — sinh bởi tools/sinh_danh_sach_ngon_ngu.py
    const-string v5, {ma}

    const-string v6, "\\\\|"

    invoke-virtual {{v5, v6}}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v5

    iput-object v5, v0, Lvn/smartdubbing/live/MainActivity;->{truong_ma}:[Ljava/lang/String;

    const-string v5, {nhan}

    invoke-virtual {{v5, v6}}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v5

    iput-object v5, v0, Lvn/smartdubbing/live/MainActivity;->{truong_nhan}:[Ljava/lang/String;
"""


def chen(noi_dung: str, neo: str, khoi: str, ten_neo: str) -> str:
    so = noi_dung.count(neo)
    if so != 1:
        raise SystemExit("DỪNG: neo '%s' xuất hiện %d lần (cần đúng 1)." % (ten_neo, so))
    return noi_dung.replace(neo, neo + "\n" + khoi, 1)


def main() -> int:
    ap = argparse.ArgumentParser(description="Chèn danh sách ngôn ngữ Google vào MainActivity.smali")
    ap.add_argument("--cay", default=os.path.join(GOC, "Apks", "2"))
    ap.add_argument("--kho", action="store_true", help="chỉ kiểm tra, không ghi")
    a = ap.parse_args()
    tep = os.path.join(a.cay, "smali_classes2/vn/smartdubbing/live/MainActivity.smali")
    if not os.path.isfile(tep):
        print("THIẾU tệp: %s" % tep, file=sys.stderr)
        return 2
    truoc = bam(tep)
    t = open(tep, encoding="utf-8").read()
    if DAU in t:
        print("Đã áp trước đó (thấy dấu %s) — không làm gì. sha256=%s" % (DAU, truoc))
        return 0
    ma_nguon, nhan_nguon = doc_snippet("smali_nguon.txt")
    ma_dich, nhan_dich = doc_snippet("smali_dich.txt")
    neo_nguon = "    iput-object v5, v0, Lvn/smartdubbing/live/MainActivity;->sourceLabels:[Ljava/lang/String;"
    neo_dich = "    iput-object v5, v0, Lvn/smartdubbing/live/MainActivity;->languageLabels:[Ljava/lang/String;"
    t2 = chen(t, neo_nguon, khoi_ngon_ngu(ma_nguon, nhan_nguon, "sourceOptions", "sourceLabels"), "sourceLabels(v5)")
    t2 = chen(t2, neo_dich, khoi_ngon_ngu(ma_dich, nhan_dich, "languageOptions", "languageLabels"), "languageLabels(v5)")
    dem = t2.count("Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;")
    if dem != 4:
        raise SystemExit("DỪNG: số lần gọi split = %d (cần 4) — không ghi." % dem)
    if a.kho:
        print("CHẠY KHÔ: sẽ chèn 2 khối (4 lần split). sha256 trước=%s" % truoc)
        return 0
    with open(tep, "w", encoding="utf-8") as f:
        f.write(t2)
    print("ĐÃ ÁP danh sách ngôn ngữ vào %s" % tep)
    print("  sha256 trước: %s" % truoc)
    print("  sha256 sau  : %s" % bam(tep))
    print("  số mục nguồn : %d mã / %d nhãn" % (ma_nguon.count("|") + 1, nhan_nguon.count("|") + 1))
    print("  số mục đích  : %d mã / %d nhãn" % (ma_dich.count("|") + 1, nhan_dich.count("|") + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
