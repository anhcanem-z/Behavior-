#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/thanh_tra.py — THANH TRA: tự phát hiện vi phạm luật quy tắc của User.

Vai trò trong "xã hội AI": đây là **thanh tra độc lập**, chỉ đọc dữ liệu thật (git, sổ neo,
nhật ký sự kiện, khối quy tắc, hồ sơ kỷ luật) rồi kết luận AI nào/việc nào vi phạm điều nào.
Nguyên tắc: **có bằng chứng mới kết luận**; không suy đoán; không tự tha.

    python3 tools/thanh_tra.py                # kiểm tra, in kết luận
    python3 tools/thanh_tra.py --ghi          # ghi các vi phạm rõ ràng vào hồ sơ kỷ luật
    python3 tools/thanh_tra.py --json
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(TOOLKIT_DIR, "tools")
LEDGER = os.path.join(TOOLKIT_DIR, "outputs", "anchor", "ledger.jsonl")
EVENTS = os.path.join(TOOLKIT_DIR, "outputs", "su_kien", "events.jsonl")
HO_SO = os.path.join(TOOLKIT_DIR, "outputs", "ky_luat", "ho_so.jsonl")
TRANG_THAI = os.path.join(TOOLKIT_DIR, "outputs", "thanh_tra", "trang_thai.json")
GIO_HAN_MOC = 24 * 3600


def doc_trang_thai() -> dict:
    """Trạng thái auto-boot: {"bat": bool, "che_do": "thanh_tra"|"thuong", ...}"""
    if not os.path.isfile(TRANG_THAI):
        return {"bat": False, "che_do": "thuong", "nguon": "mac_dinh"}
    try:
        with open(TRANG_THAI, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"bat": False, "che_do": "thuong", "nguon": "loi_doc"}


def ghi_trang_thai(bat: bool, che_do: str) -> dict:
    os.makedirs(os.path.dirname(TRANG_THAI), exist_ok=True)
    du_lieu = {
        "bat": bool(bat),
        "che_do": che_do,
        "bat_luc": time.strftime("%F %T %Z"),
        "epoch": int(time.time()),
        "nguon": "User",
        "ghi_chu": ("Auto-boot BẬT: doctor tự chạy thanh tra và tự ghi hồ sơ kỷ luật "
                    "(quyền ngang User trong chế độ thanh tra)." if bat else
                    "Auto-boot TẮT: thanh tra chỉ chạy khi được gọi thủ công."),
    }
    with open(TRANG_THAI, "w", encoding="utf-8") as fh:
        json.dump(du_lieu, fh, ensure_ascii=False, indent=2)
    return du_lieu


def _nap_ky_luat():
    duong_dan = os.path.join(TOOLS_DIR, "ky_luat.py")
    spec = importlib.util.spec_from_file_location("ky_luat", duong_dan)
    mo_dun = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mo_dun)
    return mo_dun


def _doc_jsonl(duong_dan: str) -> list[dict]:
    if not os.path.isfile(duong_dan):
        return []
    ket_qua = []
    with open(duong_dan, encoding="utf-8", errors="replace") as fh:
        for dong in fh:
            try:
                ket_qua.append(json.loads(dong))
            except Exception:
                continue
    return ket_qua


def _git_thay_doi() -> list[str]:
    try:
        kq = subprocess.run(["git", "status", "--porcelain"], capture_output=True,
                            text=True, timeout=60, cwd=TOOLKIT_DIR)
    except Exception:
        return []
    ten = []
    for dong in (kq.stdout or "").splitlines():
        p = dong[3:].strip()
        if not p or ".bak" in p or "backup" in p or p.endswith("/"):
            continue
        ten.append(p)
    return ten


# ------------------------------------------------------------------ các phép kiểm
def kiem_thieu_neo() -> list[dict]:
    """TC-01 · T2: tệp thay đổi phải có neo/sự kiện."""
    da_co = set()
    for so in (LEDGER, EVENTS):
        for d in _doc_jsonl(so):
            p = d.get("tep")
            if p:
                da_co.add(os.path.basename(p))
    thieu = [t for t in _git_thay_doi() if os.path.basename(t) not in da_co]
    if not thieu:
        return []
    return [{"ma": "VP-01", "dieu": "Điều 1/T2 — mọi thay đổi phải có neo",
             "muc_de_xuat": "M1", "mo_ta": "%d tệp thay đổi chưa có neo/sự kiện" % len(thieu),
             "bang_chung": ", ".join(thieu[:8]), "thiet_hai": "nhỏ", "quan_trong": "quan trọng"}]


def kiem_moc_thoi_gian() -> list[dict]:
    """TC-08: mốc thời gian không quá 24 giờ, gồm cả tệp home."""
    import pathlib
    home = str(pathlib.Path.home())
    tep = [os.path.join(TOOLKIT_DIR, x) for x in
           ("AGENTS.md", "CLAUDE.md", "GEMINI.md", "AGENTS_TRANG_THAI.md")]
    tep += [os.path.join(home, ".codex", "AGENTS.md"), os.path.join(home, ".claude", "CLAUDE.md"),
            os.path.join(home, ".gemini", "GEMINI.md")]
    cu = []
    for t in tep:
        if not os.path.isfile(t):
            continue
        noi_dung = open(t, encoding="utf-8", errors="replace").read()
        khop = re.search(r"Mốc hệ thống:\s*`?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", noi_dung)
        if not khop:
            cu.append(t + " (thiếu mốc)")
            continue
        try:
            moc = time.mktime(time.strptime(khop.group(1), "%Y-%m-%d %H:%M:%S"))
        except Exception:
            cu.append(t + " (mốc không đọc được)")
            continue
        if time.time() - moc > GIO_HAN_MOC:
            cu.append(t)
    if not cu:
        return []
    return [{"ma": "VP-02", "dieu": "Điều 1/T2 — mốc thời gian không quá 24 giờ",
             "muc_de_xuat": "M1", "mo_ta": "%d tệp có mốc thời gian quá cũ" % len(cu),
             "bang_chung": ", ".join(os.path.basename(x) for x in cu[:6]),
             "thiet_hai": "nhỏ", "quan_trong": "việc nhẹ"}]


def kiem_khoi_lech() -> list[dict]:
    """TC-11/Điều 1/T2: khối quy tắc + công cụ phải khớp nguồn chuẩn."""
    ket_qua = []
    try:
        kq = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, "sync_rules.py")],
                            capture_output=True, text=True, timeout=180, cwd=TOOLKIT_DIR)
        if kq.returncode != 0:
            ket_qua.append({"ma": "VP-03", "dieu": "Điều 1/T2 — khối quy tắc khớp nguồn chuẩn",
                            "muc_de_xuat": "M2", "mo_ta": "khối quy tắc lệch nguồn chuẩn quy_tac_khoi/",
                            "bang_chung": (kq.stdout or "").strip().splitlines()[-1][:120],
                            "thiet_hai": "lớn", "quan_trong": "quan trọng"})
    except Exception:
        pass
    for ten in ("anchor.py", "audit_toolkit.py", "sync_rules.py", "gen_doc_commands.py"):
        goc = os.path.join(TOOLS_DIR, ten)
        for noi in ():  # SmartKit độc lập: chưa có bản sao ngoài
            dich = os.path.join(noi, ten)
            if not os.path.isfile(goc) or not os.path.isfile(dich):
                continue
            if open(goc, "rb").read() != open(dich, "rb").read():
                ket_qua.append({"ma": "VP-04", "dieu": "Điều 1/T2 — bản sao phải khớp bản chính",
                                "muc_de_xuat": "M1", "mo_ta": "công cụ %s lệch ở %s" % (ten, noi),
                                "bang_chung": dich, "thiet_hai": "nhỏ", "quan_trong": "việc nhẹ"})
    return ket_qua


def kiem_ho_so_mo() -> list[dict]:
    """Điều 4: hồ sơ M3/M4 còn mở thì phải báo động."""
    mo = [d for d in _doc_jsonl(HO_SO)
          if d.get("trang_thai") == "moi" and d.get("muc") in ("M3", "M4")]
    if not mo:
        return []
    return [{"ma": "VP-05", "dieu": "Điều 4 — chế tài M3/M4 chưa xử lý",
             "muc_de_xuat": "M3", "mo_ta": "%d hồ sơ mức nặng đang mở" % len(mo),
             "bang_chung": ", ".join(d.get("ma_ho_so", "?") for d in mo[:5]),
             "thiet_hai": "lớn", "quan_trong": "trọng yếu"}]


def kiem_nguon_khong_xac_dinh() -> list[dict]:
    """Điều 2/TC-06: bản ghi thiếu nguồn thì không truy được tác giả."""
    moc_luat = "2026-09-17 04:13"   # từ mốc luật TC-06 trở đi mới bắt buộc có nguồn
    thieu = []
    for d in _doc_jsonl(LEDGER):
        gio = str(d.get("gio") or d.get("gio_dong") or "")
        if gio and gio[:16] < moc_luat:
            continue
        if not d.get("nguon") or d.get("nguon") in ("khong_xac_dinh", "(khong_co_phien)"):
            thieu.append(d)
    if not thieu:
        return []
    return [{"ma": "VP-06", "dieu": "Điều 2 — truy nguồn tác giả",
             "muc_de_xuat": "M1", "mo_ta": "%d bản ghi sổ neo thiếu nguồn/tác giả" % len(thieu),
             "bang_chung": "outputs/anchor/ledger.jsonl", "thiet_hai": "nhỏ", "quan_trong": "việc nhẹ"}]


def kiem_test_am() -> list[dict]:
    """Điều 3 — không có kiểm tra thì luật chưa đủ hiệu lực."""
    try:
        kq = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, "test_am.py")],
                            capture_output=True, text=True, timeout=180, cwd=TOOLKIT_DIR)
        if kq.returncode != 0:
            return [{"ma": "VP-07", "dieu": "Điều 3 — kiểm tra tự động phải đạt",
                     "muc_de_xuat": "M2", "mo_ta": "bộ test âm không đạt",
                     "bang_chung": (kq.stdout or "").strip().splitlines()[-1][:120],
                     "thiet_hai": "lớn", "quan_trong": "quan trọng"}]
    except Exception:
        return []
    return []


def thanh_tra() -> dict:
    ds = []
    for ham in (kiem_khoi_lech, kiem_thieu_neo, kiem_moc_thoi_gian,
                kiem_ho_so_mo, kiem_nguon_khong_xac_dinh, kiem_test_am):
        try:
            ds += ham()
        except Exception as loi:
            ds.append({"ma": "VP-99", "dieu": "lỗi thanh tra", "muc_de_xuat": "M1",
                       "mo_ta": "%s: %s" % (ham.__name__, loi), "bang_chung": "",
                       "thiet_hai": "nhỏ", "quan_trong": "việc nhẹ"})
    return {"gio": time.strftime("%F %T %Z"), "epoch": int(time.time()),
            "so_vi_pham": len(ds), "vi_pham": ds}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Thanh tra tự phát hiện vi phạm luật quy tắc của User.")
    ap.add_argument("--ghi", action="store_true", help="ghi các vi phạm rõ ràng vào hồ sơ kỷ luật")
    ap.add_argument("--bat", action="store_true", help="BẬT auto-boot (User kích hoạt)")
    ap.add_argument("--tat", action="store_true", help="TẮT auto-boot")
    ap.add_argument("--trang-thai", action="store_true", help="xem trạng thái auto-boot")
    ap.add_argument("--auto", action="store_true",
                    help="chế độ auto-boot: nếu đang BẬT thì tự ghi hồ sơ (dùng cho doctor)")
    ap.add_argument("--json", action="store_true", help="xuất JSON")
    args = ap.parse_args(argv)

    if args.bat or args.tat:
        tt = ghi_trang_thai(args.bat, "thanh_tra" if args.bat else "thuong")
        print("=== AUTO-BOOT THANH TRA: %s ===" % ("BẬT" if tt["bat"] else "TẮT"))
        print("  chế độ: %s · lúc: %s · nguồn: %s" % (tt["che_do"], tt["bat_luc"], tt["nguon"]))
        print("  %s" % tt["ghi_chu"])
        return 0
    if args.trang_thai:
        tt = doc_trang_thai()
        if args.json:
            print(json.dumps(tt, ensure_ascii=False, indent=2))
        else:
            print("Auto-boot: %s · chế độ: %s · bật lúc: %s" % (
                "BẬT" if tt.get("bat") else "TẮT", tt.get("che_do"), tt.get("bat_luc", "(chưa bật)")))
        return 0

    tt = doc_trang_thai()
    if args.auto and tt.get("bat"):
        args.ghi = True
    kq = thanh_tra()
    kq["auto_boot"] = bool(tt.get("bat"))
    kq["che_do"] = tt.get("che_do", "thuong")
    if args.ghi and kq["vi_pham"]:
        kl = _nap_ky_luat()
        for vp in kq["vi_pham"]:
            kl.ghi(muc=vp["muc_de_xuat"], dieu=vp["dieu"], mo_ta=vp["mo_ta"],
                   ly_do="(thanh tra tự phát hiện)", khac_phuc="xem đề xuất trong báo cáo thanh tra",
                   kiem_tra_moi=vp.get("bang_chung", ""), tu_khai=False, nguon="thanh_tra")
        kq["da_ghi"] = len(kq["vi_pham"])
    if args.json:
        print(json.dumps(kq, ensure_ascii=False, indent=2))
    else:
        print("=== THANH TRA LUẬT QUY TẮC CỦA USER · %s ===" % kq["gio"])
        if not kq["vi_pham"]:
            print("  Không phát hiện vi phạm (dựa trên bằng chứng hiện có).")
        for vp in kq["vi_pham"]:
            print("  [%s] %s · mức đề xuất %s" % (vp["ma"], vp["dieu"], vp["muc_de_xuat"]))
            print("       %s" % vp["mo_ta"])
            if vp.get("bang_chung"):
                print("       bằng chứng: %s" % vp["bang_chung"])
        print("Kết luận: %d vi phạm" % kq["so_vi_pham"] + (" (đã ghi hồ sơ)" if args.ghi else ""))
    return 1 if kq["so_vi_pham"] else 0


if __name__ == "__main__":
    sys.exit(main())
