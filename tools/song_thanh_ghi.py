"""Tinh tap thanh ghi CON SONG (live-in/live-out) cho tung lenh smali. CHI DOC.

Nguon goc: Codex viet trong phien 01a0be94 (2026-09-20 18:42) de do "thanh ghi con song"
truoc khi muon thanh ghi cua phuong thuc goc (nguyen nhan VerifyError 0x24B). Truoc do
nam o ~/tmp kem bo phan tich rieng; da dua vao toolkit 2026-09-20 22:30 (phien 01a0bf3b)
va dung lai bo phan tich cua tools/kiem_tra_verify.py — mot nguon duy nhat (TC-07).

Trang thai: chua_kiem — CONG CU DOC/PHAN TICH, KHONG duoc dung lam cong chan build.
    python3 tools/song_thanh_ghi.py <tep.smali> <ten_ham> <dong> [<dong> ...]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kiem_tra_verify import doc_tep


def doc_ham(tep, ten_ham):
    """Tim 1 ham trong tep smali bang bo phan tich chung cua cong ngu nghia."""
    for h in doc_tep(tep):
        if h["ten"] == ten_ham:
            return h["lenh"], h["nhan"], h.get("dau", [])
    raise SystemExit("khong thay ham %s trong %s" % (ten_ham, tep))


def song(tep, ten_ham):
    lenh, nhan, _dau = doc_ham(tep, ten_ham)
    n = len(lenh)
    ke_tiep = []
    for i, L in enumerate(lenh):
        ma = L["ma"]
        if ma.startswith(("goto", "return", "throw")):
            ke_tiep.append([nhan[L["dich"]]] if L["dich"] in nhan else [])
        elif ma.startswith("if-"):
            ds = [i + 1] if i + 1 < n else []
            if L["dich"] in nhan:
                ds.append(nhan[L["dich"]])
            ke_tiep.append(sorted(set(ds)))
        else:
            ke_tiep.append([i + 1] if i + 1 < n else [])
    truoc = [[] for _ in range(n)]
    for i, ds in enumerate(ke_tiep):
        for s in ds:
            if s < n:
                truoc[s].append(i)
    vao = [set() for _ in range(n)]
    ra = [set() for _ in range(n)]
    doi = True
    while doi:
        doi = False
        for i in range(n - 1, -1, -1):
            moi_ra = set()
            for s in ke_tiep[i]:
                if s < n:
                    moi_ra |= vao[s]
            moi_vao = set(moi_ra)
            if lenh[i]["gan"]:
                moi_vao.discard(lenh[i]["gan"])
            for r in lenh[i]["doc"]:
                moi_vao.add(r)
            if moi_ra != ra[i] or moi_vao != vao[i]:
                ra[i] = moi_ra
                vao[i] = moi_vao
                doi = True
    return lenh, vao, ra


if __name__ == "__main__":
    tep = sys.argv[1]
    ten_ham = sys.argv[2]
    lenh, vao, ra = song(tep, ten_ham)
    ds_dong = [int(x) for x in sys.argv[3:]]
    print("=== %s :: %s() ===" % (tep.split("/")[-1], ten_ham))
    for so_dong in ds_dong:
        for i, L in enumerate(lenh):
            if L["dong"] == so_dong:
                print("\nDong %d: %s" % (so_dong, L["text"]))
                print("   vao (con song):", sorted(vao[i]))
                print("   ra  (con song):", sorted(ra[i]))
                break
        else:
            print("khong thay dong %d" % so_dong)
