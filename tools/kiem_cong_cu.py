#!/usr/bin/env python3
"""Cong tu kiem cong cu — chan dung loai sai lam 2026-09-20 (ban giao cong cu chua tu chung minh).

Vi sao can: phien 01a0be94 ban giao `tools/kiem_tra_verify.py` nhu san pham dat dot pha nhung
cong cu do (a) khong co ban ghi neo, (b) chua chung minh phan biet duoc dung/sai, (c) co 1 loi
BAO SACH SAI (aput bi coi la lenh ghi) co the che mat loi that. Neu dem moc vao duong build
ngay thi se chan build oan; neu tin vao ket qua "sach" thi se lot APK loi. Cong nay khien
dieu do khong the xay ra nua: cong cu nao muon duoc quyen CHAN build thi phai tu chung minh
duoc ngay tai thoi diem dung.

Ba che do:
  chua_kiem : moi the hien trong so, chua co gi
  da_kiem   : da chay tu kiem dat (co the dung o che do CANH BAO)
  tin_dung  : duoc quyen CHAN build — CHI User duoc nang (--dat-tin-dung --nguon User)

Dung:
    python3 tools/kiem_cong_cu.py                 # quet + cap nhat so + in bang (mac dinh)
    python3 tools/kiem_cong_cu.py --quet --ghi-so
    python3 tools/kiem_cong_cu.py --dat-tin-dung kiem_tra_verify.py --nguon User
    python3 tools/kiem_cong_cu.py --dat-canh-bao kiem_tra_verify.py --ly-do "..."
    python3 tools/kiem_cong_cu.py --kiem-cong-dang-chan
    python3 tools/kiem_cong_cu.py --json

Thoat ma: 0 khi moi cong dang CHAN deu da tu kiem dat; 1 khi co cong dang chan ma khong dat.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(TOOLKIT_DIR, "tools")
SO_DIR = os.path.join(TOOLKIT_DIR, "outputs", "cong_cu")
SO_TEP = os.path.join(SO_DIR, "trang_thai.json")

# Cong cu duoc theo doi: ten tep -> mo ta ngan
# Tu khoa BAT BUOC phai co trong nguyen van lenh User thi moi duoc nang len quyen CHAN.
TU_KHOA_NANG_CHAN = ("chặn", "chan", "block", "cấm", "cam")


THEO_DOI = {
    "kiem_tra_verify.py": "Cổng kiểm tra NGỮ NGHĨA smali (bắt lỗi thanh ghi trước khi build)",
    "anchor.py": "Sổ neo đa chiều (ledger + events)",
    "thanh_tra.py": "Thanh tra độc lập theo LUẬT của User",
    "sync_modules.py": "Kiểm tra đồng bộ lệnh ↔ tài liệu ↔ test",
    "sync_rules.py": "Đồng bộ khối quy tắc từ quy_tac_khoi/",
    "status_report.py": "Báo cáo trạng thái tổng hợp đầu phiên",
    "ky_luat.py": "Hồ sơ kỷ luật (append-only)",
    "audit_toolkit.py": "Kiểm tra nội bộ toolkit",
    "khoa_tep.py": "Khóa mềm ghi tệp dùng chung (điều phối đa AI)",
    "ai_router.py": "Định tuyến AI an toàn",
    "remote_log_server.py": "Máy thu log runtime từ app",
    "phan_tich_log.py": "Phân tích log runtime",
    "doc_dex.py": "Đọc trực tiếp method trong .dex (kiểm chứng bản vá trong APK)",
    "song_thanh_ghi.py": "Đo thanh ghi còn sống (live-in/live-out)",
    "speak.py": "Phát âm báo cáo (TTS)",
    "external/codex_gemini_proxy.py": "Cổng AI cục bộ — ĐÚNG 2 mô hình Gemini + DeepSeek (không có GPT)",
    "kiem_pham_vi.py": "Cổng kiểm PHẠM VI đường dẫn (cây được phép + tên gần giống >= 90%)",
}


def _sha256(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for k in iter(lambda: f.read(65536), b""):
                h.update(k)
    except OSError:
        return None
    return h.hexdigest()


def doc_so():
    try:
        with open(SO_TEP, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {"cap_nhat": None, "cong_cu": {}}
    d.setdefault("cong_cu", {})
    return d


def ghi_so(so):
    os.makedirs(SO_DIR, exist_ok=True)
    so["cap_nhat"] = time.strftime("%Y-%m-%d %H:%M:%S")
    tmp = SO_TEP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(so, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SO_TEP)
    return SO_TEP


def co_tu_kiem(duong_dan):
    try:
        with open(duong_dan, encoding="utf-8", errors="ignore") as f:
            return "--tu-kiem" in f.read()
    except OSError:
        return False


def chay_tu_kiem(duong_dan, giay_toi_da=120):
    """Chay --tu-kiem, tra (dat, giay, ghi_chu)."""
    t = time.monotonic()
    try:
        r = subprocess.run([sys.executable, duong_dan, "--tu-kiem"],
                           capture_output=True, text=True, timeout=giay_toi_da)
    except subprocess.TimeoutExpired:
        return False, round(time.monotonic() - t, 1), "qua thoi gian tu kiem"
    except OSError as e:
        return False, round(time.monotonic() - t, 1), "khong chay duoc: %s" % e
    giay = round(time.monotonic() - t, 1)
    if r.returncode == 0:
        return True, giay, ""
    cuoi = (r.stdout or "").strip().splitlines()
    return False, giay, (cuoi[-1] if cuoi else "tu kiem that bai (exit %d)" % r.returncode)


def quet(so, chay=False):
    """Cap nhat trang thai tung cong cu: ma bam, co tu kiem, ket qua tu kiem."""
    for ten, mo_ta in sorted(THEO_DOI.items()):
        p = os.path.join(TOOLS_DIR, ten)
        muc = so["cong_cu"].setdefault(ten, {})
        muc["mo_ta"] = mo_ta
        muc.setdefault("trang_thai", "chua_kiem")
        muc.setdefault("che_do", "canh_bao")
        muc.setdefault("nguon_nang", None)
        if not os.path.isfile(p):
            muc["ton_tai"] = False
            muc["sha256"] = None
            muc["tu_kiem_dat"] = None
            muc["ghi_chu"] = "khong thay tep"
            continue
        muc["ton_tai"] = True
        h = _sha256(p)
        cu = muc.get("sha256")
        muc["sha256"] = h
        muc["byte"] = os.path.getsize(p)
        muc["co_tu_kiem"] = co_tu_kiem(p)
        if cu and cu != h:
            # Cong cu bi sua -> tu ha xuong chua_kiem (khong giu quyen chan cu)
            if muc["trang_thai"] == "tin_dung":
                muc["trang_thai"] = "da_kiem"
            muc["ghi_chu"] = "ma bam doi (tep bi sua) — phai tu kiem lai"
            muc["tu_kiem_dat"] = None
        if chay and muc.get("co_tu_kiem"):
            dat, giay, ghi_chu = chay_tu_kiem(p)
            muc["tu_kiem_dat"] = dat
            muc["tu_kiem_giay"] = giay
            muc["tu_kiem_luc"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if dat:
                if muc["trang_thai"] == "chua_kiem":
                    muc["trang_thai"] = "da_kiem"
                muc.pop("ghi_chu", None)
            else:
                muc["trang_thai"] = "chua_kiem"
                muc["che_do"] = "canh_bao"
                muc["ghi_chu"] = "TU KIEM THAT BAI: %s" % ghi_chu
    so["cap_nhat"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return so


def kiem_cong_dang_chan(so):
    """Tra danh sach VI PHAM: cong dang CHAN nhung chua duoc tu kiem dat."""
    loi = []
    for ten, muc in sorted(so["cong_cu"].items()):
        if muc.get("che_do") != "chan":
            continue
        if not muc.get("ton_tai"):
            loi.append((ten, "dang chan build nhung KHONG thay tep"))
            continue
        if not muc.get("co_tu_kiem"):
            loi.append((ten, "dang chan build nhung KHONG co --tu-kiem"))
        elif muc.get("tu_kiem_dat") is not True:
            loi.append((ten, "dang chan build nhung tu kiem chua dat/chua chay"))
        if muc.get("trang_thai") != "tin_dung":
            loi.append((ten, "dang chan build nhung chua duoc User nang tin_dung"))
    return loi


def main():
    ap = argparse.ArgumentParser(description="Cổng tự kiểm công cụ + sổ 'tin dùng'.")
    ap.add_argument("--quet", action="store_true", help="quét lại (chay tu kiem khi co)")
    ap.add_argument("--ghi-so", action="store_true", help="ghi so trang thai")
    ap.add_argument("--dat-tin-dung", default=None, help="nang 1 cong cu len tin_dung")
    ap.add_argument("--dat-canh-bao", default=None, help="ha 1 cong cu xuong che do canh bao")
    ap.add_argument("--ly-do", default="", help="ly do cho --dat-tin-dung/--dat-canh-bao")
    ap.add_argument("--bang-chung", default="",
                    help="NGUYEN VAN lenh User khi nang 'tin_dung' (phai co tu khoa nang quyen CHAN)")
    ap.add_argument("--nguon", default="khong_xac_dinh", help="nguon: User / Codex / ...")
    ap.add_argument("--kiem-cong-dang-chan", action="store_true",
                    help="chi kiem cac cong dang o che do chan")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    so = doc_so()
    if not so["cong_cu"]:
        so = quet(so, chay=True)
    if args.quet or args.dat_tin_dung or args.dat_canh_bao:
        so = quet(so, chay=True)

    if args.dat_canh_bao:
        ten = args.dat_canh_bao
        muc = so["cong_cu"].setdefault(ten, {})
        muc["che_do"] = "canh_bao"
        muc["trang_thai"] = "da_kiem"
        muc["ghi_chu"] = "ha xuong canh bao: %s" % (args.ly_do or "khong ghi ly do")
        muc["ha_luc"] = time.strftime("%Y-%m-%d %H:%M:%S")

    if args.dat_tin_dung:
        ten = args.dat_tin_dung
        muc = so["cong_cu"].setdefault(ten, {})
        if args.nguon != "User":
            print("TU CHOI: chi User duoc nang 'tin_dung' (dang la nguon=%s)."
                  % args.nguon)
            print("Ly do: mot cong cu co quyen CHAN build thi chi nguoi dung duoc quyet.")
            return 1
        if muc.get("tu_kiem_dat") is not True:
            print("TU CHOI: %s chua dat tu kiem (--tu-kiem) nen khong duoc nang." % ten)
            return 1
        # Chan viec "suy dien" lenh User: phai co NGUYEN VAN co tu khoa nang quyen CHAN.
        bc = (args.bang_chung or "").lower()
        if not any(k in bc for k in TU_KHOA_NANG_CHAN):
            print("TU CHOI: thieu bang chung NGUYEN VAN lenh User co tu khoa nang quyen CHAN.")
            print("  Can mot trong: %s" % ", ".join(TU_KHOA_NANG_CHAN))
            print("  Luu y: 'nang muc do quan sat' KHONG phai lenh bat chan.")
            return 1
        muc["trang_thai"] = "tin_dung"
        muc["che_do"] = "chan"
        muc["nguon_nang"] = args.nguon
        muc["nang_luc"] = time.strftime("%Y-%m-%d %H:%M:%S")
        muc["ghi_chu"] = args.ly_do or "User cho phep chan build"
        muc["bang_chung_user"] = args.bang_chung

    if args.ghi_so or args.quet or args.dat_tin_dung or args.dat_canh_bao:
        duong = ghi_so(so)
    else:
        duong = SO_TEP

    loi = kiem_cong_dang_chan(so)

    if args.json:
        print(json.dumps({"so": duong, "cong_cu": so["cong_cu"],
                          "vi_pham": [{"cong_cu": t, "ly_do": l} for t, l in loi]},
                         ensure_ascii=False, indent=2))
    else:
        print("=== CONG TU KIEM CONG CU · so: %s ===" % duong)
        print("  %-26s %-10s %-9s %-6s %s" % ("cong cu", "trang thai", "che do",
                                              "tu kiem", "ghi chu"))
        for ten, muc in sorted(so["cong_cu"].items()):
            tk = muc.get("tu_kiem_dat")
            tk_txt = "dat" if tk is True else ("hong" if tk is False else "—")
            print("  %-26s %-10s %-9s %-6s %s"
                  % (ten, muc.get("trang_thai", "?"), muc.get("che_do", "?"), tk_txt,
                     (muc.get("ghi_chu") or "")[:60]))
        if loi:
            print("\nVI PHAM (cong dang chan ma chua duoc tu kiem dat): %d" % len(loi))
            for t, l in loi:
                print("  - %s: %s" % (t, l))
        else:
            print("\nKhong co vi pham: moi cong dang CHAN deu da tu kiem dat.")
    return 1 if loi else 0


if __name__ == "__main__":
    sys.exit(main())
