#!/usr/bin/env python3
"""Phan tich log chan doan tu xa va xuat file JSON cau hinh sua.

Dung:
    python3 tools/phan_tich_log.py
    python3 tools/phan_tich_log.py --file <jsonl>

Ket qua:
    outputs/behavior/remote_analysis/chan_doan.json
    outputs/behavior/remote_analysis/de_xuat_sua.json
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(ROOT, "outputs", "behavior", "remote_logs")
OUT_DIR = os.path.join(ROOT, "outputs", "behavior", "remote_analysis")

QUY_TAC = [
    {
        "mau": r"VerifyError",
        "nghi_van": "Smali sai kieu thanh ghi tai diem hoi tu nhan hoac sai so .locals",
        "hanh_dong": "Doi chieu tep trong 'message' voi ban sach 2_src; kiem kieu thanh ghi tai moi nhan gop",
        "do_tin_cay": 0.9,
    },
    {
        "mau": r"NoSuchMethodError|NoSuchFieldError|NoClassDefFoundError|ClassNotFoundException",
        "nghi_van": "Thieu lop / thieu ham / thieu truong do ban chen goi vao thu khong ton tai",
        "hanh_dong": "Bo sung lop-ham-truong con thieu hoac go loi goi tuong ung trong tep bi neu",
        "do_tin_cay": 0.9,
    },
    {
        "mau": r"NullPointerException",
        "nghi_van": "Truy cap doi tuong chua khoi tao (thuong gap o cong tac AI hoac dich vu am thanh)",
        "hanh_dong": "Them kiem tra null truoc khi dung, hoac khoi tao som doi tuong bi null",
        "do_tin_cay": 0.7,
    },
    {
        "mau": r"NetworkOnMainThreadException|NetworkSecurityPolicy|Cleartext",
        "nghi_van": "Goi mang tren luong giao dien",
        "hanh_dong": "Chuyen loi goi mang sang luong rieng",
        "do_tin_cay": 0.6,
    },
    {
        "mau": r"OutOfMemoryError",
        "nghi_van": "Thieu bo nho khi giai ma anh hoac giu du lieu lon",
        "hanh_dong": "Giai phong anh, dat ti le thu nho, tranh giu tham chieu dai han",
        "do_tin_cay": 0.7,
    },
    {
        "mau": r"IndexOutOfBoundsException",
        "nghi_van": "Chon muc vuot qua so phan tu cua danh sach",
        "hanh_dong": "Kiem so muc truoc khi chon, hoac dat lai vi tri mac dinh",
        "do_tin_cay": 0.7,
    },
    {
        "mau": r"UnsatisfiedLinkError|dlopen|page-aligned",
        "nghi_van": "Thu vien ma may khong nap duoc",
        "hanh_dong": "Kiem ABI, can trang, ten tep .so",
        "do_tin_cay": 0.8,
    },
]


def doc(path):
    ra = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ra.append(json.loads(line))
            except Exception:
                ra.append({"kind": "raw", "data": line})
    return ra


def tach_vi_tri(stack):
    ra = []
    for m in re.finditer(r"\bat ([a-zA-Z0-9_.$]+)\.([a-zA-Z0-9_$<>]+)", stack or ""):
        ra.append("%s.%s" % (m.group(1), m.group(2)))
    return ra


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="")
    args = ap.parse_args()

    path = args.file
    if not path:
        ung = sorted(glob.glob(os.path.join(LOG_DIR, "*.jsonl")))
        if not ung:
            print("Khong tim thay log trong %s" % LOG_DIR)
            return 1
        path = ung[-1]

    su_kien = doc(path)
    crash = [e for e in su_kien if e.get("kind") == "crash"]
    loi = [e for e in su_kien if e.get("kind") == "error"]
    su_kien_thuong = [e for e in su_kien if e.get("kind") not in ("crash", "error")]

    de_xuat = []
    for c in crash:
        text = "%s %s %s" % (c.get("type", ""), c.get("message", ""), c.get("stack", ""))
        for q in QUY_TAC:
            if re.search(q["mau"], text, re.I):
                de_xuat.append(
                    {
                        "ma": "FIX-" + re.sub(r"\W+", "-", (c.get("type") or "loi"))[:24],
                        "loai_loi": c.get("type"),
                        "thong_diep": c.get("message"),
                        "nghi_van": q["nghi_van"],
                        "hanh_dong": q["hanh_dong"],
                        "do_tin_cay": q["do_tin_cay"],
                        "vi_tri_nghi": tach_vi_tri(c.get("stack", ""))[:12],
                    }
                )
                break
        else:
            de_xuat.append(
                {
                    "ma": "FIX-KHAC",
                    "loai_loi": c.get("type"),
                    "thong_diep": c.get("message"),
                    "nghi_van": "Chua khop mau da biet",
                    "hanh_dong": "Doc ky stack trong chan_doan.json de xac dinh lop-ham gay loi",
                    "do_tin_cay": 0.3,
                    "vi_tri_nghi": tach_vi_tri(c.get("stack", ""))[:12],
                }
            )

    os.makedirs(OUT_DIR, exist_ok=True)
    chan_doan = {
        "tao_luc": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nguon_log": path,
        "so_su_kien": len(su_kien),
        "so_su_kien_thuong": len(su_kien_thuong),
        "so_loi": len(loi),
        "so_crash": len(crash),
        "danh_sach_crash": crash,
        "danh_sach_loi": loi,
        "su_kien_gan_nhat": su_kien_thuong[-30:],
    }
    with open(os.path.join(OUT_DIR, "chan_doan.json"), "w", encoding="utf-8") as f:
        json.dump(chan_doan, f, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT_DIR, "de_xuat_sua.json"), "w", encoding="utf-8") as f:
        json.dump(
            {"tao_luc": chan_doan["tao_luc"], "so_de_xuat": len(de_xuat), "de_xuat": de_xuat},
            f,
            ensure_ascii=False,
            indent=2,
        )

    print("== PHAN TICH LOG ==")
    print("  tep log  : %s" % path)
    print("  su kien  : %d (crash %d, loi %d)" % (len(su_kien), len(crash), len(loi)))
    for d in de_xuat:
        print("  - %s | %s" % (d["loai_loi"], d["nghi_van"]))
        print("    viec: %s" % d["hanh_dong"])
        if d["vi_tri_nghi"]:
            print("    vi tri: %s" % ", ".join(d["vi_tri_nghi"][:4]))
    print("  da ghi: %s" % OUT_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
