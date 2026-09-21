#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/ky_luat.py — Hồ sơ kỷ luật theo LUẬT QUY TẮC CỦA USER (khối PATCHX-USER-WARNING).

Chỉ ĐỌC khi không truyền --ghi. Khi --ghi: nối thêm 1 bản ghi vào
`outputs/ky_luat/ho_so.jsonl` (append-only, không sửa/xóa).

    python3 tools/ky_luat.py --ghi --muc M2 --dieu "Điều 2" \
        --mo-ta "sửa tệp ngoài phạm vi" --ly-do "thiếu thông tin" \
        --khac-phuc "hoàn tác + báo User" --kiem-tra-moi "audit quét đường dẫn"
    python3 tools/ky_luat.py --bao-cao          # tổng hợp + mức đang mở
    python3 tools/ky_luat.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HO_SO = os.path.join(TOOLKIT_DIR, "outputs", "ky_luat", "ho_so.jsonl")
MUC = ("M0", "M1", "M2", "M3", "M4")


def doc_ho_so() -> list[dict]:
    if not os.path.isfile(HO_SO):
        return []
    ket_qua = []
    with open(HO_SO, encoding="utf-8", errors="replace") as fh:
        for dong in fh:
            try:
                ket_qua.append(json.loads(dong))
            except Exception:
                continue
    return ket_qua


def ma_ho_so(so_thu_tu: int) -> str:
    return "KL-{}-{:03d}".format(time.strftime("%Y%m%d-%H%M%S"), so_thu_tu)


def ghi(muc: str, dieu: str, mo_ta: str, ly_do: str, khac_phuc: str,
        kiem_tra_moi: str, tu_khai: bool, nguon: str,
        nguon_bao_cao: str = "", bang_chung: str = "",
        diem_ly_do: str = "", phan_quyet_user: str = "") -> dict:
    os.makedirs(os.path.dirname(HO_SO), exist_ok=True)
    cu = doc_ho_so()
    so_lan_dieu = sum(1 for d in cu if d.get("dieu") == dieu)
    muc_goc = muc
    if tu_khai and muc in ("M2", "M3", "M4"):
        muc = MUC[max(0, MUC.index(muc) - 1)]
    elif so_lan_dieu >= 1 and muc in ("M1", "M2"):
        muc = MUC[min(3, MUC.index(muc) + 1)]
    ban_ghi = {
        "ma_ho_so": ma_ho_so(len(cu) + 1),
        "muc": muc,
        "muc_de_xuat": muc_goc,
        "dieu": dieu,
        "mo_ta": mo_ta,
        "ly_do_ai_dua_ra": ly_do or "(không nêu — lý do KHÔNG được dùng để miễn trừ)",
        "khac_phuc": khac_phuc,
        "kiem_tra_moi": kiem_tra_moi,
        "tu_khai": bool(tu_khai),
        "so_lan_dieu_nay_truoc_do": so_lan_dieu,
        "gio": time.strftime("%F %T %Z"),
        "epoch": int(time.time()),
        "nguon": nguon,
        "nguon_bao_cao": nguon_bao_cao or nguon,
        "bang_chung": bang_chung,
        "diem_ly_do_10": diem_ly_do or "(chưa chấm)",
        "phan_quyet_user": phan_quyet_user or "(chờ User phán quyết)",
        "trang_thai": "moi",
    }
    with open(HO_SO, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ban_ghi, ensure_ascii=False) + "\n")
    return ban_ghi


def bao_cao() -> dict:
    ds = doc_ho_so()
    dem = {m: 0 for m in MUC}
    for d in ds:
        if d.get("muc") in dem:
            dem[d["muc"]] += 1
    mo = [d for d in ds if d.get("trang_thai") == "moi" and d.get("muc") in ("M3", "M4")]
    return {"tong": len(ds), "theo_muc": dem, "dang_mo_nang": mo, "ho_so": HO_SO}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Hồ sơ kỷ luật theo luật quy tắc của User.")
    ap.add_argument("--ghi", action="store_true", help="ghi 1 vi phạm mới")
    ap.add_argument("--muc", default="M1", choices=MUC, help="mức chế tài đề xuất")
    ap.add_argument("--dieu", default="", help="điều luật / mã tiêu chí bị vi phạm")
    ap.add_argument("--mo-ta", default="", help="mô tả việc sai")
    ap.add_argument("--ly-do", default="", help="lý do AI đưa ra (ghi để biết, không để miễn trừ)")
    ap.add_argument("--khac-phuc", default="", help="biện pháp khắc phục")
    ap.add_argument("--kiem-tra-moi", default="", help="kiểm tra tự động mới đã thêm")
    ap.add_argument("--tu-khai", action="store_true", help="AI tự khai báo trước khi bị phát hiện (giảm 1 mức)")
    ap.add_argument("--nguon", default="Codex", help="nguồn: Codex / Claude / Gemini / User / khong_xac_dinh")
    ap.add_argument("--nguon-bao-cao", default="", help="AI báo cáo vi phạm này (giám sát chéo)")
    ap.add_argument("--bang-chung", default="", help="bằng chứng kèm theo (đường dẫn, hash, mốc)")
    ap.add_argument("--diem-ly-do", default="", help="điểm lý do 0-10 theo Điều 2")
    ap.add_argument("--phan-quyet", default="", help="phán quyết của User (chấp nhận / không chấp nhận / chờ)")
    ap.add_argument("--bao-cao", action="store_true", help="tổng hợp hồ sơ")
    ap.add_argument("--json", action="store_true", help="xuất JSON")
    args = ap.parse_args(argv)

    if args.ghi:
        ban_ghi = ghi(args.muc, args.dieu, args.mo_ta, args.ly_do, args.khac_phuc,
                      args.kiem_tra_moi, args.tu_khai, args.nguon,
                      nguon_bao_cao=args.nguon_bao_cao, bang_chung=args.bang_chung,
                      diem_ly_do=args.diem_ly_do, phan_quyet_user=args.phan_quyet)
        if args.json:
            print(json.dumps(ban_ghi, ensure_ascii=False, indent=2))
        else:
            print("=== ĐÃ GHI HỒ SƠ KỶ LUẬT ===")
            print("  Mã: %s · mức: %s (đề xuất %s) · điều: %s" % (
                ban_ghi["ma_ho_so"], ban_ghi["muc"], ban_ghi["muc_de_xuat"], ban_ghi["dieu"]))
            print("  Lý do (không miễn trừ): %s" % ban_ghi["ly_do_ai_dua_ra"])
            print("  Khắc phục: %s · kiểm tra mới: %s" % (ban_ghi["khac_phuc"], ban_ghi["kiem_tra_moi"]))
            print("  Hồ sơ: %s" % HO_SO)
        return 0

    kq = bao_cao()
    if args.json:
        print(json.dumps(kq, ensure_ascii=False, indent=2))
        return 1 if kq["dang_mo_nang"] else 0
    print("=== HỒ SƠ KỶ LUẬT (LUẬT QUY TẮC CỦA USER) ===")
    print("  Tổng vi phạm đã ghi: %d" % kq["tong"])
    for m in MUC:
        print("  %s: %d" % (m, kq["theo_muc"][m]))
    if kq["dang_mo_nang"]:
        print("  [CẢNH BÁO] %d hồ sơ mức M3/M4 chưa xử lý:" % len(kq["dang_mo_nang"]))
        for d in kq["dang_mo_nang"]:
            print("    - %s · %s · %s" % (d["ma_ho_so"], d["muc"], d["dieu"]))
    else:
        print("  Không có hồ sơ mức M3/M4 đang mở.")
    print("  Sổ: %s" % kq["ho_so"])
    return 1 if kq["dang_mo_nang"] else 0


if __name__ == "__main__":
    sys.exit(main())
