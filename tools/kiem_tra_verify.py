#!/usr/bin/env python3
"""Cong kiem tra NGU NGHIA smali truoc khi build — chan loi VerifyError cua may ao ART.

Vi sao can: `patchx_core/smali_validate.py` chi kiem HINH DANG (can doi .method/.end method,
cu phap tung lenh). Ngay 2026-09-20 no bao "12.196/12.196 tep dat, 0 loi" nhung app van crash
vi may ao ART tu choi lop MainActivity. Cong nay kiem 2 nhom loi NGU NGHIA ma ART that su tu choi:

  N1 (LOI, chan build) — doc thanh ghi CHUA GAN tren mot duong di nao do:
       args to if-eq/if-ne (Integer,Undefined) must both be references or integral
  N2 (CANH BAO) — vung va `# PATCHX` ghi de thanh ghi ma doan ma NGOAI vung va con doc:
       register vN has type X but expected Y

Dung:
    python3 tools/kiem_tra_verify.py --tree Apks/2            # quet cac tep co dau va # PATCHX
    python3 tools/kiem_tra_verify.py --tree Apks/2 --all      # quet toan bo cay (cham hon)
    python3 tools/kiem_tra_verify.py --file <tep.smali> [--file ...]
    python3 tools/kiem_tra_verify.py --file tep.smali --json
    python3 tools/kiem_tra_verify.py --do-lech <tep.smali> --ham startTranslation --pc 0x8E
    python3 tools/kiem_tra_verify.py --tu-kiem                # tu kiem chieu duong + chieu am

Thoat ma: 1 khi co loi N1 (dung de chan build), 0 khi chi co canh bao hoac sach.

Cach kiem N1 (sua 2026-09-20 21:40): phan tich "GAN CHAC CHAN" dung chuan —
IN[n] = giao OUT cua MOI duong vao, OUT[n] = IN[n] hop {thanh ghi lenh n gan}.
Khoi tao bang TOP (coi nhu da gan) roi ha dan den diem bat dong LON NHAT, dung bang
"gan tren moi duong di". Ban cu khoi tao bang RONG nen diem gop co canh quay lui bi ket
o gia tri 0 => bao loi GIA (do that 2026-09-20: dong 2596 ham requestPermissionsIfNeeded).

Gioi han da biet (khong mo hinh hoa, ghi ro de khong bao dam): cạnh NGOAI LE (.catch/
.catchall) va bang nhay packed-switch/sparse-switch moi lenh chi tinh theo duong tuan tu
+ re nhanh if-*/goto — vi vay cong nay bat dung nhom loi da gap, khong thay the ART verifier.
"""

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Bang kich thuoc lenh (code-unit) theo ten lenh smali
# ---------------------------------------------------------------------------
KICH_THUOC = {
    "nop": 1, "move": 1, "move/from16": 2, "move/16": 3, "move-wide": 1,
    "move-wide/from16": 2, "move-wide/16": 3, "move-object": 1,
    "move-object/from16": 2, "move-object/16": 3, "move-result": 1,
    "move-result-wide": 1, "move-result-object": 1, "move-exception": 1,
    "return-void": 1, "return": 1, "return-wide": 1, "return-object": 1,
    "const/4": 1, "const/16": 2, "const": 3, "const/high16": 2,
    "const-wide/16": 2, "const-wide/32": 3, "const-wide": 5,
    "const-wide/high16": 2, "const-string": 2, "const-string/jumbo": 3,
    "const-class": 2, "monitor-enter": 1, "monitor-exit": 1, "check-cast": 2,
    "instance-of": 2, "array-length": 1, "new-instance": 2, "new-array": 2,
    "filled-new-array": 3, "filled-new-array/range": 3, "fill-array-data": 3,
    "throw": 1, "goto": 1, "goto/16": 2, "goto/32": 3, "packed-switch": 3,
    "sparse-switch": 3, "cmpl-float": 2, "cmpg-float": 2, "cmpl-double": 2,
    "cmpg-double": 2, "cmp-long": 2,
    "if-eq": 2, "if-ne": 2, "if-lt": 2, "if-ge": 2, "if-gt": 2, "if-le": 2,
    "if-eqz": 2, "if-nez": 2, "if-ltz": 2, "if-gez": 2, "if-gtz": 2, "if-lez": 2,
    "aget": 2, "aget-wide": 2, "aget-object": 2, "aget-boolean": 2, "aget-byte": 2,
    "aget-char": 2, "aget-short": 2, "aput": 2, "aput-wide": 2, "aput-object": 2,
    "aput-boolean": 2, "aput-byte": 2, "aput-char": 2, "aput-short": 2,
    "iget": 2, "iget-wide": 2, "iget-object": 2, "iget-boolean": 2, "iget-byte": 2,
    "iget-char": 2, "iget-short": 2,
    "iput": 2, "iput-wide": 2, "iput-object": 2, "iput-boolean": 2, "iput-byte": 2,
    "iput-char": 2, "iput-short": 2,
    "sget": 2, "sget-wide": 2, "sget-object": 2, "sget-boolean": 2, "sget-byte": 2,
    "sget-char": 2, "sget-short": 2,
    "sput": 2, "sput-wide": 2, "sput-object": 2, "sput-boolean": 2, "sput-byte": 2,
    "sput-char": 2, "sput-short": 2,
    "invoke-virtual": 3, "invoke-super": 3, "invoke-direct": 3, "invoke-static": 3,
    "invoke-interface": 3, "invoke-virtual/range": 3, "invoke-super/range": 3,
    "invoke-direct/range": 3, "invoke-static/range": 3, "invoke-interface/range": 3,
    "neg-int": 1, "not-int": 1, "neg-long": 1, "not-long": 1, "neg-float": 1,
    "neg-double": 1, "int-to-long": 1, "int-to-float": 1, "int-to-double": 1,
    "long-to-int": 1, "long-to-float": 1, "long-to-double": 1, "float-to-int": 1,
    "float-to-long": 1, "float-to-double": 1, "double-to-int": 1, "double-to-long": 1,
    "double-to-float": 1, "int-to-byte": 1, "int-to-char": 1, "int-to-short": 1,
}
for _t in ("add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"):
    for _k in ("-int", "-long", "-float", "-double"):
        KICH_THUOC[_t + _k] = 2
        KICH_THUOC[_t + _k + "/2addr"] = 1
    KICH_THUOC[_t + "-int/lit16"] = 2
    KICH_THUOC[_t + "-int/lit8"] = 2

KHONG_GHI = ("invoke-", "iput", "sput", "if-", "goto", "return", "throw", "monitor-",
             "check-cast", "packed-switch", "sparse-switch", "filled-new-array",
             "fill-array-data", "nop", "aput")
GHI_DAU = ("move", "const", "new-", "aget", "iget", "sget", "instance-of",
           "array-length", "cmp", "neg-", "not-", "int-to-", "long-to-", "float-to-",
           "double-to-", "add-", "sub-", "mul-", "div-", "rem-", "and-", "or-",
           "xor-", "shl-", "shr-", "ushr-", "rsub-")
BO_QUA_DONG = (".method", ".end method", ".locals", ".registers", ".param", ".line",
               ".prologue", ".catch", ".catchall", ".annotation", ".end annotation",
               ".source", ".field", ".class", ".super", ".implements")


def _ghi_dau(ma):
    if ma.startswith(KHONG_GHI):
        return False
    if ma.startswith(GHI_DAU):
        return True
    return ma in KICH_THUOC


def _rong_dich(ma):
    """True neu lenh GAN vao mot CAP thanh ghi rong (long/double chiem 2 thanh ghi).

    Do that 2026-09-20: `div-long/2addr v4, v6` gan ca v4 LAN v5; `const-wide/16 v2, 0x0`
    gan ca v2 lan v3. Cong cu cu chi tinh 1 thanh ghi => ve sau doc v5/v3 bi bao loi GIA.
    """
    if ma.startswith(("cmp", "array-length", "instance-of", "new-", "const-string",
                      "const-class", "move-result-object", "move-object", "check-cast")):
        return False
    if ma in ("size",) or ma.startswith("fill-"):
        return False
    if ma.startswith(("const-wide", "move-wide", "move-result-wide", "aget-wide",
                      "iget-wide", "sget-wide")):
        return True
    # So hoc / chuyen doi: "-long" hoac "-double" trong ten lenh = ket qua rong.
    return "-long" in ma or "-double" in ma


def _chi_so(ten):
    """'v3' -> 3 ; 'p2' -> None (tham so luon duoc coi la da co gia tri)."""
    if ten.startswith("v"):
        return int(ten[1:])
    return None


def _mo_rong_thanh_ghi(text):
    """Lay danh sach thanh ghi trong 1 dong lenh, mo rong ca dang {v0 .. v5}."""
    ra = []
    for phan in text.replace("{", " ").replace("}", " ").split():
        phan = phan.strip("{},")
        if phan == "..":
            continue
        if phan.startswith(("v", "p")) and phan[1:].isdigit():
            ra.append(phan)
    if ".." in text:
        dau = [x for x in ra]
        if len(dau) >= 2 and dau[0][0] == dau[1][0] == "v":
            ra = ["v%d" % i for i in range(int(dau[0][1:]), int(dau[1][1:]) + 1)]
    return ra


def doc_tep(duong_dan):
    """Tra ve danh sach ham: {ten, dong, lenh:[...], nhan:{ten: chi_so_lenh}}"""
    dong = open(duong_dan, encoding="utf-8", errors="replace").read().splitlines()
    ham = []
    i = 0
    while i < len(dong):
        l = dong[i]
        if l.startswith(".method"):
            ten = l.split()[-1].split("(")[0]
            if "->" in ten:
                ten = ten.split("->")[-1]
            h = {"ten": ten, "dong": i + 1, "lenh": [], "nhan": {}, "patchx": set()}
            i += 1
            dang_patchx = False
            while i < len(dong) and not dong[i].startswith(".end method"):
                s = dong[i].strip()
                if s.startswith("# PATCHX"):
                    dang_patchx = True
                    i += 1
                    continue
                if s.startswith(".array-data") or s.startswith(".packed-switch") or \
                        s.startswith(".sparse-switch"):
                    while i < len(dong) and not dong[i].strip().startswith((".end array-data",
                                                                            ".end packed-switch",
                                                                            ".end sparse-switch")):
                        if dong[i].strip().startswith(":"):
                            h["nhan"].setdefault(dong[i].strip()[1:].split()[0], len(h["lenh"]))
                        i += 1
                    i += 1
                    continue
                if s.startswith(":"):
                    h["nhan"].setdefault(s[1:].split()[0], len(h["lenh"]))
                    i += 1
                    continue
                if not s or s.startswith(BO_QUA_DONG) or s.startswith("#"):
                    if s.startswith(".line"):
                        dang_patchx = False
                    i += 1
                    continue
                ma = s.split()[0]
                thanh_ghi = _mo_rong_thanh_ghi(s[len(ma):])
                ghi = _ghi_dau(ma)
                muc = {"dong": i + 1, "text": s, "ma": ma,
                       "gan": thanh_ghi[0] if (ghi and thanh_ghi) else None,
                       "doc": thanh_ghi[1:] if (ghi and thanh_ghi) else thanh_ghi,
                       "dich": None, "kich": KICH_THUOC.get(ma, 1)}
                for phan in s.replace(",", " ").split():
                    if phan.startswith(":"):
                        muc["dich"] = phan[1:]
                        break
                k = len(h["lenh"])
                h["lenh"].append(muc)
                if dang_patchx:
                    h["patchx"].add(k)
                i += 1
            ham.append(h)
        i += 1
    # Do lech (code-unit, tinh tu dau ham) cua tung lenh — dung de doi chieu con so
    # ma may ao bao, vi du [0x8E] = code-unit 142.
    for h in ham:
        off = 0
        for L in h["lenh"]:
            L["pc"] = off
            off += L["kich"]
    return ham


def _ke_tiep(h):
    """Danh sach chi so lenh ke tiep (do thi luong)."""
    lenh = h["lenh"]
    n = len(lenh)
    ra = []
    for i, L in enumerate(lenh):
        ma = L["ma"]
        if ma.startswith(("goto", "return", "throw")):
            ra.append([h["nhan"][L["dich"]]] if L["dich"] in h["nhan"] else [])
        elif ma.startswith("if-"):
            ds = [i + 1] if i + 1 < n else []
            if L["dich"] in h["nhan"]:
                ds.append(h["nhan"][L["dich"]])
            ra.append(sorted(set(ds)))
        else:
            ra.append([i + 1] if i + 1 < n else [])
    return ra


def _do_thi(h):
    """Do thi luong: (kich thuoc, danh sach lenh ke tiep, danh sach lenh truoc, toi duoc)."""
    lenh = h["lenh"]
    n = len(lenh)
    ke = _ke_tiep(h) if n else []
    toi_duoc = [False] * n
    if not n:
        return n, ke, [[] for _ in range(n)], toi_duoc
    # Chi phan tich lenh THAT SU toi duoc tu dau ham (tranh chu trinh chet lam treo).
    toi_duoc[0] = True
    ngan_xep = [0]
    while ngan_xep:
        i = ngan_xep.pop()
        for s in ke[i]:
            if s < n and not toi_duoc[s]:
                toi_duoc[s] = True
                ngan_xep.append(s)
    truoc = [[] for _ in range(n)]
    for i, ds in enumerate(ke):
        if not toi_duoc[i]:
            continue
        for s in ds:
            if s < n and toi_duoc[s]:
                truoc[s].append(i)
    return n, ke, truoc, toi_duoc


def _duong_di_thieu_gan(lenh, truoc, ra, i, c, gioi_han=6):
    """Mot duong di that su tu dau ham toi lenh loi ma tren do thanh ghi c chua duoc gan."""
    duong = [i]
    cur = i
    dem = 0
    while cur != 0 and dem < 64:
        dem += 1
        chon = None
        for p in truoc[cur]:
            if not (ra[p] >> c) & 1:
                chon = p
                break
        if chon is None:
            break
        duong.append(chon)
        cur = chon
    duong.reverse()
    return [{"dong": lenh[k]["dong"], "text": lenh[k]["text"]} for k in duong[-gioi_han:]]


def kiem_doc_truoc_gan(h):
    """N1: loi 'doc thanh ghi CHUA GAN tren mot duong di nao do'.

    Phan tich "gan chac chan" (must-analysis) dung chuan:
      IN[n]  = giao OUT cua MOI duong vao  (diem gop: chi tinh la da gan khi moi duong deu gan)
      OUT[n] = IN[n] hop {thanh ghi ma lenh n gan}
    Khoi tao OUT = TOP (coi nhu da gan het) roi ha dan den diem bat dong LON NHAT —
    dung bang "gan tren moi duong di" (khung nay co tinh phan bo, nen diem bat dong lon
    nhat = nghiem MOP). Khoi tao bang RONG (ban cu) lam diem gop co canh quay lui ket o 0
    => bao loi GIA.
    """
    lenh = h["lenh"]
    if not lenh:
        return []
    n, ke, truoc, toi_duoc = _do_thi(h)
    co_gan = [0] * n
    vu_tru = 0
    for i, L in enumerate(lenh):
        c = _chi_so(L["gan"]) if L["gan"] else None
        if c is not None:
            co_gan[i] = 1 << c
            vu_tru |= 1 << c
            if _rong_dich(L["ma"]):
                co_gan[i] |= 1 << (c + 1)     # lenh rong (long/double) gan ca thanh ghi ke tiep
                vu_tru |= 1 << (c + 1)
        for r in L["doc"]:
            c2 = _chi_so(r)
            if c2 is not None:
                vu_tru |= 1 << c2
    # Duyet toi diem bat dong bang hang doi (gia tri chi GIAM dan => chac chan dung).
    ra = [vu_tru] * n                      # OUT[n], khoi tao TOP
    ra[0] = co_gan[0]                      # diem vao ham: chua co gi duoc gan (tru lenh dau)
    hang_doi = collections.deque(i for i in range(n) if toi_duoc[i])
    trong_doi = [True] * n
    while hang_doi:
        i = hang_doi.popleft()
        trong_doi[i] = False
        if i == 0:
            vao = 0
        else:
            ds = truoc[i]
            if not ds:
                vao = 0                        # khong co duong vao -> coi nhu dau ham
            else:
                vao = ra[ds[0]]
                for p in ds[1:]:
                    vao &= ra[p]
        moi_ra = vao | co_gan[i]
        if moi_ra != ra[i]:
            ra[i] = moi_ra
            for s in ke[i]:
                if s < n and toi_duoc[s] and not trong_doi[s]:
                    trong_doi[s] = True
                    hang_doi.append(s)
    # IN cua tung lenh (dung de xet 'doc truoc khi gan')
    vao_lenh = [0] * n
    for i in range(n):
        if not toi_duoc[i]:
            continue
        if i == 0 or not truoc[i]:
            vao_lenh[i] = 0
        else:
            v = ra[truoc[i][0]]
            for p in truoc[i][1:]:
                v &= ra[p]
            vao_lenh[i] = v
    loi = []
    for i, L in enumerate(lenh):
        if not toi_duoc[i]:
            continue
        for r in L["doc"]:
            c = _chi_so(r)
            if c is None:
                continue
            if not (vao_lenh[i] >> c) & 1:
                loi.append({"ham": h["ten"], "dong": L["dong"], "pc": L.get("pc", 0),
                            "thanh_ghi": r, "kieu": "N1-doc-truoc-khi-gan", "text": L["text"],
                            "duong_di": _duong_di_thieu_gan(lenh, truoc, ra, i, c)})
    return loi


def kiem_vung_va(h):
    """N2: canh bao khi vung va # PATCHX ghi de thanh ghi ma doan ma ngoai vung van doc."""
    lenh = h["lenh"]
    if not h["patchx"]:
        return []
    canh_bao = []
    for k in sorted(h["patchx"]):
        L = lenh[k]
        if not L["gan"]:
            continue
        r = L["gan"]
        c = _chi_so(r)
        for j in range(k + 1, len(lenh)):
            L2 = lenh[j]
            if not (L2["ma"].startswith("# PATCHX")):
                if j not in h["patchx"] and r in L2["doc"]:
                    canh_bao.append({"ham": h["ten"], "dong_ghi": L["dong"], "thanh_ghi": r,
                                     "kieu_lenh_ghi": L["ma"], "dong_doc_lai": L2["dong"],
                                     "text_doc_lai": L2["text"], "kieu": "N2-vung-va-de-thanh-ghi-con-dung"})
                    break
            if r == L2["gan"]:
                break                            # da bi ghi lai -> het nguy hiem
    return canh_bao


def phan_tich_tep(duong_dan, ten_kieu=True):
    ham = doc_tep(duong_dan)
    loi, canh_bao = [], []
    for h in ham:
        if not h["lenh"]:
            continue
        loi.extend(kiem_doc_truoc_gan(h))
        canh_bao.extend(kiem_vung_va(h))
    return ham, loi, canh_bao


# ---------------------------------------------------------------------------
# TU KIEM: chieu duong (mau CO loi phai bi bat) + chieu am (mau DA sua phai sach)
# ---------------------------------------------------------------------------
MAU_LOI = """.class public LTuKiemLoi;
.super Ljava/lang/Object;

.method public static doPhep(ILjava/lang/String;)V
    .locals 3

    const/4 v1, 0x0

    if-eqz p1, :bo_qua

    const/4 v1, 0x5

    const/4 v2, 0x2

    :bo_qua
    if-eq p1, v2, :xong

    :xong
    return-void
.end method
"""

MAU_SUA = """.class public LTuKiemSua;
.super Ljava/lang/Object;

.method public static doPhep(ILjava/lang/String;)V
    .locals 3

    const/4 v1, 0x5

    const/4 v2, 0x2

    if-eqz p1, :bo_qua

    const/4 v1, 0x0

    :bo_qua
    if-eq p1, v2, :xong

    :xong
    return-void
.end method
"""

MAU_CHE_LOI = """.class public LTuKiemCheLoi;
.super Ljava/lang/Object;

.method public static doPhep(ILjava/lang/String;)V
    .locals 3

    const/4 v1, 0x0

    new-array v0, p1, [Ljava/lang/String;

    aput-object v2, v0, v1

    if-eqz v2, :xong

    :xong
    return-void
.end method
"""


def tu_kiem():
    """Chay 3 chieu tren mau nho do cong tu sinh.

    Chieu duong : mau CO loi            -> PHAI bat duoc.
    Chieu am    : mau DA sua            -> PHAI sach.
    Chieu che   : mau 'bao sach sai'    -> PHAI bat duoc, khoa vinh vien loi `aput*`
                  (ban 2026-09-20 20:57 coi aput la lenh GAN nen che mat loi that).
    """
    ok = True
    with tempfile.TemporaryDirectory(prefix="kt_ngu_nghia_") as thu_muc:
        duong_loi = os.path.join(thu_muc, "MauLoi.smali")
        duong_sua = os.path.join(thu_muc, "MauSua.smali")
        duong_che = os.path.join(thu_muc, "MauCheLoi.smali")
        with open(duong_loi, "w", encoding="utf-8") as f:
            f.write(MAU_LOI)
        with open(duong_sua, "w", encoding="utf-8") as f:
            f.write(MAU_SUA)
        with open(duong_che, "w", encoding="utf-8") as f:
            f.write(MAU_CHE_LOI)
        print("=== TU KIEM CONG KIEM TRA NGU NGHIA SMALI (3 chieu) ===")
        _, loi_duong, _ = phan_tich_tep(duong_loi)
        _, loi_am, _ = phan_tich_tep(duong_sua)
        _, loi_che, _ = phan_tich_tep(duong_che)
        bat = [x for x in loi_duong if x["thanh_ghi"] == "v2"]
        if bat:
            x = bat[0]
            print("  [DAT ] chieu duong: mau CO loi -> bat duoc %d loi, dung thanh ghi %s "
                  "tai dong %d (pc 0x%X) | %s"
                  % (len(bat), x["thanh_ghi"], x["dong"], x["pc"], x["text"]))
        else:
            ok = False
            print("  [HONG] chieu duong: mau CO loi nhung cong KHONG bat duoc (bao dat gia).")
        if loi_am:
            ok = False
            print("  [HONG] chieu am  : mau DA sua nhung cong con bao %d loi (bao loi gia):" % len(loi_am))
            for x in loi_am[:3]:
                print("         - dong %d (pc 0x%X) doc %s | %s"
                      % (x["dong"], x["pc"], x["thanh_ghi"], x["text"]))
        else:
            print("  [DAT ] chieu am  : mau DA sua -> sach, 0 loi.")
        che = [x for x in loi_che if "if-eqz v2" in x["text"]]
        if che:
            x = che[0]
            print("  [DAT ] chieu che : loi sau `aput-object` (ban cu bao sach sai) -> bat duoc "
                  "tai dong %d (pc 0x%X) | %s" % (x["dong"], x["pc"], x["text"]))
        else:
            ok = False
            print("  [HONG] chieu che : `aput-object` van bi coi la lenh GAN -> che mat loi that "
                  "(%d loi bat duoc, can bat dung dong `if-eqz v2`)." % len(loi_che))
        print("Ket luan tu kiem: %s" % ("DAT (cong phan biet duoc ban loi va ban da sua)"
                                        if ok else "HONG (cong chua dung)"))
    return 0 if ok else 1


def do_lech(duong_dan, ten_ham, pc):
    ham = doc_tep(duong_dan)
    for h in ham:
        if h["ten"] != ten_ham:
            continue
        off = 0
        for i, L in enumerate(h["lenh"]):
            if off == pc:
                print("=== %s() · do lech 0x%X (%d code-unit) ===" % (ten_ham, pc, pc))
                for j in range(max(0, i - 4), min(len(h["lenh"]), i + 5)):
                    L2 = h["lenh"][j]
                    print("%s  dong %5d  %s" % (">>" if j == i else "  ", L2["dong"], L2["text"]))
                return 0
            off += L["kich"]
        print("Ham %s() chi dai %d code-unit — khong co do lech 0x%X." % (ten_ham, off, pc))
        return 1
    print("Khong thay ham %s trong %s" % (ten_ham, duong_dan))
    return 1


def gom_tep(args):
    if args.file:
        return [os.path.abspath(p) for p in args.file]
    goc = os.path.abspath(args.tree or ".")
    if not args.all:
        ds = _tim_tep_da_va(goc)
        if ds is not None:
            return sorted(ds)
    ra = []
    for thu_muc, _ds, ten_tep in os.walk(goc):
        if "/build/" in thu_muc or "/original/" in thu_muc:
            continue
        for t in ten_tep:
            if not t.endswith(".smali"):
                continue
            p = os.path.join(thu_muc, t)
            if not args.all:
                try:
                    with open(p, encoding="utf-8", errors="ignore") as f:
                        if "# PATCHX" not in f.read():
                            continue
                except OSError:
                    continue
            ra.append(p)
    return sorted(ra)


def _tim_tep_da_va(goc):
    """Tim nhanh cac tep smali co dau `# PATCHX` — dung `grep -rl` khi co.

    Tra None neu khong dung duoc grep (khi do goi ham nay se tu doc tung tep).
    Cach nay van la DOC NOI DUNG chu khong tin mtime, nen khong bo sot tep da va.
    """
    if not shutil.which("grep"):
        return None
    try:
        r = subprocess.run(["grep", "-rl", "PATCHX", "--include=*.smali", goc],
                           capture_output=True, text=True)
    except OSError:
        return None
    if r.returncode not in (0, 1):
        return None
    ds = [p for p in r.stdout.splitlines() if p.endswith(".smali")]
    ds = [p for p in ds if "/build/" not in p and "/original/" not in p]
    return ds


def main():
    ap = argparse.ArgumentParser(
        description="Cong kiem tra ngu nghia smali (chan loi VerifyError cua ART).")
    ap.add_argument("--tree", default=None, help="cay APK da giai ma")
    ap.add_argument("--file", action="append", default=[], help="1 tep smali (lap lai duoc)")
    ap.add_argument("--all", action="store_true",
                    help="quet ca tep khong co dau va # PATCHX (mac dinh chi quet tep da va)")
    ap.add_argument("--json", action="store_true", help="xuat JSON")
    ap.add_argument("--im", action="store_true", help="khong in chi tiet")
    ap.add_argument("--do-lech", default=None, help="tep smali can do do lech")
    ap.add_argument("--ham", default=None, help="ten ham cho --do-lech")
    ap.add_argument("--pc", default=None, help="do lech dang 0x8E cho --do-lech")
    ap.add_argument("--tu-kiem", action="store_true",
                    help="tu kiem chieu duong + chieu am tren mau nho (khong cham vao APK)")
    args = ap.parse_args()

    if args.tu_kiem:
        return tu_kiem()

    if args.do_lech:
        if not args.ham or args.pc is None:
            print("Can --ham va --pc khi dung --do-lech.")
            return 2
        return do_lech(args.do_lech, args.ham, int(args.pc, 16))

    t_gom = time.monotonic()
    tep = gom_tep(args)
    giay_gom = round(time.monotonic() - t_gom, 2)
    t0 = time.monotonic()
    tat_ca_loi, tat_ca_canh_bao, so_ham = [], [], 0
    for p in tep:
        try:
            ham, loi, canh_bao = phan_tich_tep(p)
        except Exception as e:                    # 1 tep loi khong lam dung cong kiem
            tat_ca_loi.append({"tep": p, "kieu": "N0-khong-phan-tich-duoc",
                               "text": "%s: %s" % (type(e).__name__, e)})
            continue
        so_ham += len(ham)
        for v in loi:
            v["tep"] = p
        for v in canh_bao:
            v["tep"] = p
        tat_ca_loi.extend(loi)
        tat_ca_canh_bao.extend(canh_bao)
    giay = round(time.monotonic() - t0, 1)
    giay_tong = round(giay_gom + (time.monotonic() - t0), 2)

    if args.json:
        print(json.dumps({"tep": len(tep), "ham": so_ham, "giay": giay,
                          "giay_tim_tep": giay_gom, "giay_tong": giay_tong,
                          "loi": tat_ca_loi, "canh_bao": tat_ca_canh_bao},
                         ensure_ascii=False, indent=2))
    else:
        print("=== CONG KIEM TRA NGU NGHIA SMALI ===")
        print("  tep quet : %d | ham : %d" % (len(tep), so_ham))
        print("  thoi gian: tim tep %s giay + phan tich %s giay = tong %s giay"
              % (giay_gom, giay, giay_tong))
        if not args.im:
            for v in tat_ca_loi:
                if "dong" in v:
                    print("  [LOI ] %s :: %s() dong %d (pc 0x%X) — doc %s chua gan | %s"
                          % (os.path.basename(v["tep"]), v["ham"], v["dong"],
                             v.get("pc", 0), v["thanh_ghi"], v["text"]))
                    for b in (v.get("duong_di") or [])[:-1]:
                        print("         duong di thieu gan: dong %d | %s" % (b["dong"], b["text"]))
                else:
                    print("  [LOI ] %s :: %s" % (v.get("tep"), v.get("text")))
            for v in tat_ca_canh_bao:
                print("  [CANH] %s :: %s() vung va dong %d ghi %s (%s), nhung dong %d "
                      "van doc lai: %s"
                      % (os.path.basename(v["tep"]), v["ham"], v["dong_ghi"],
                         v["thanh_ghi"], v["kieu_lenh_ghi"], v["dong_doc_lai"],
                         v["text_doc_lai"]))
        print("Ket luan: %d loi (chan build) | %d canh bao" % (len(tat_ca_loi),
                                                               len(tat_ca_canh_bao)))
    return 1 if tat_ca_loi else 0


if __name__ == "__main__":
    sys.exit(main())
