"""Doc truc tiep 1 method trong tep .dex de kiem chung ban va da vao APK. CHI DOC.

Nguon goc: Codex viet trong phien 01a0be94 (2026-09-20 18:53) de chung minh ban va nam
trong DEX cua APK da ky — truoc do nam o ~/tmp (de bi don mat). Da dua vao toolkit
2026-09-20 22:30 (phien 01a0bf3b) de tai su dung.

Trang thai: chua_kiem — CONG CU DOC/PHAN TICH, KHONG duoc dung lam cong chan build.
    python3 tools/doc_dex.py <tep.dex> <class> <method>
"""
import struct
import sys

OP = [None] * 0x100
_ten = ("nop move move/from16 move/16 move-wide move-wide/from16 move-wide/16 move-object "
        "move-object/from16 move-object/16 move-result move-result-wide move-result-object "
        "move-exception return-void return return-wide return-object const/4 const/16 const "
        "const/high16 const-wide/16 const-wide/32 const-wide const-wide/high16 const-string "
        "const-string/jumbo const-class monitor-enter monitor-exit check-cast instance-of "
        "array-length new-instance new-array filled-new-array filled-new-array/range "
        "fill-array-data throw goto goto/16 goto/32 packed-switch sparse-switch cmpl-float "
        "cmpg-float cmpl-double cmpg-double cmp-long if-eq if-ne if-lt if-ge if-gt if-le "
        "if-eqz if-nez if-ltz if-gez if-gtz if-lez x x x x x x aget aget-wide aget-object "
        "aget-boolean aget-byte aget-char aget-short aput aput-wide aput-object aput-boolean "
        "aput-byte aput-char aput-short iget iget-wide iget-object iget-boolean iget-byte "
        "iget-char iget-short iput iput-wide iput-object iput-boolean iput-byte iput-char "
        "iput-short sget sget-wide sget-object sget-boolean sget-byte sget-char sget-short "
        "sput sput-wide sput-object sput-boolean sput-byte sput-char sput-short invoke-virtual "
        "invoke-super invoke-direct invoke-static invoke-interface x invoke-virtual/range "
        "invoke-super/range invoke-direct/range invoke-static/range invoke-interface/range x x "
        "neg-int not-int neg-long not-long neg-float neg-double int-to-long int-to-float "
        "int-to-double long-to-int long-to-float long-to-double float-to-int float-to-long "
        "float-to-double double-to-int double-to-long double-to-float int-to-byte int-to-char "
        "int-to-short").split()
for _i, _t in enumerate(_ten):
    OP[_i] = _t
for _i in range(0x90, 0xB0):
    OP[_i] = "arith"
for _i in range(0xb0, 0xd0):
    OP[_i] = "arith/2addr"
for _i in range(0xd0, 0xe3):
    OP[_i] = "arith/lit"

KICH = {"nop": 1, "move": 1, "move/from16": 2, "move/16": 3, "move-wide": 1,
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
        "cmpg-double": 2, "cmp-long": 2, "if-eq": 2, "if-ne": 2, "if-lt": 2,
        "if-ge": 2, "if-gt": 2, "if-le": 2, "if-eqz": 2, "if-nez": 2, "if-ltz": 2,
        "if-gez": 2, "if-gtz": 2, "if-lez": 2, "x": 1, "aget": 2, "aget-wide": 2,
        "aget-object": 2, "aget-boolean": 2, "aget-byte": 2, "aget-char": 2,
        "aget-short": 2, "aput": 2, "aput-wide": 2, "aput-object": 2,
        "aput-boolean": 2, "aput-byte": 2, "aput-char": 2, "aput-short": 2,
        "iget": 2, "iget-wide": 2, "iget-object": 2, "iget-boolean": 2,
        "iget-byte": 2, "iget-char": 2, "iget-short": 2, "iput": 2, "iput-wide": 2,
        "iput-object": 2, "iput-boolean": 2, "iput-byte": 2, "iput-char": 2,
        "iput-short": 2, "sget": 2, "sget-wide": 2, "sget-object": 2,
        "sget-boolean": 2, "sget-byte": 2, "sget-char": 2, "sget-short": 2,
        "sput": 2, "sput-wide": 2, "sput-object": 2, "sput-boolean": 2,
        "sput-byte": 2, "sput-char": 2, "sput-short": 2, "invoke-virtual": 3,
        "invoke-super": 3, "invoke-direct": 3, "invoke-static": 3,
        "invoke-interface": 3, "invoke-virtual/range": 3, "invoke-super/range": 3,
        "invoke-direct/range": 3, "invoke-static/range": 3,
        "invoke-interface/range": 3, "neg-int": 1, "not-int": 1, "neg-long": 1,
        "not-long": 1, "neg-float": 1, "neg-double": 1, "int-to-long": 1,
        "int-to-float": 1, "int-to-double": 1, "long-to-int": 1, "long-to-float": 1,
        "long-to-double": 1, "float-to-int": 1, "float-to-long": 1,
        "float-to-double": 1, "double-to-int": 1, "double-to-long": 1,
        "double-to-float": 1, "int-to-byte": 1, "int-to-char": 1, "int-to-short": 1,
        "arith": 2, "arith/2addr": 1, "arith/lit": 2}


def uleb(d, i):
    kq = 0
    dich = 0
    while True:
        b = d[i]
        i += 1
        kq |= (b & 0x7F) << dich
        if b < 0x80:
            return kq, i
        dich += 7


class Dex:
    def __init__(self, duong_dan):
        self.d = open(duong_dan, "rb").read()
        d = self.d
        self.strings_size, self.strings_off = struct.unpack_from("<II", d, 0x38)
        self.types_size, self.types_off = struct.unpack_from("<II", d, 0x40)
        self.protos_size, self.protos_off = struct.unpack_from("<II", d, 0x48)
        self.fields_size, self.fields_off = struct.unpack_from("<II", d, 0x50)
        self.methods_size, self.methods_off = struct.unpack_from("<II", d, 0x58)
        self.classes_size, self.classes_off = struct.unpack_from("<II", d, 0x60)

    def chuoi(self, i):
        off = struct.unpack_from("<I", self.d, self.strings_off + 4 * i)[0]
        _n, j = uleb(self.d, off)
        ket = self.d.index(b"\x00", j)
        return self.d[j:ket].decode("utf-8", "replace")

    def tim_chuoi(self, ten):
        for i in range(self.strings_size):
            if self.chuoi(i) == ten:
                return i
        return None

    def tim_lop(self, ten_lop):
        chi_so_chuoi = self.tim_chuoi(ten_lop)
        if chi_so_chuoi is None:
            return None
        for i in range(self.types_size):
            if struct.unpack_from("<I", self.d, self.types_off + 4 * i)[0] == chi_so_chuoi:
                chi_so_lop = i
                break
        else:
            return None
        for i in range(self.classes_size):
            base = self.classes_off + 32 * i
            if struct.unpack_from("<I", self.d, base)[0] == chi_so_lop:
                return struct.unpack_from("<I", self.d, base + 24)[0]
        return None

    def ham(self, class_data_off, ten_ham):
        j = class_data_off
        so_tinh, j = uleb(self.d, j)
        so_thuong, j = uleb(self.d, j)
        so_truc_tiep, j = uleb(self.d, j)
        so_ao, j = uleb(self.d, j)
        for _ in range(so_tinh + so_thuong):
            _a, j = uleb(self.d, j)
            _b, j = uleb(self.d, j)
        ket = {}
        for nhom in (so_truc_tiep, so_ao):
            chi_so = 0
            for _ in range(nhom):
                hieu, j = uleb(self.d, j)
                _co, j = uleb(self.d, j)
                code_off, j = uleb(self.d, j)
                chi_so += hieu
                name_idx = struct.unpack_from("<I", self.d, self.methods_off + 8 * chi_so + 4)[0]
                ten = self.chuoi(name_idx)
                if ten == ten_ham:
                    ket.setdefault(ten, []).append(code_off)
        return ket

    def doc_lenh(self, code_off, gioi_han=0):
        regs, ins, outs, tries, dbg, insns_size = struct.unpack_from("<HHHHII", self.d, code_off)
        dau = code_off + 16
        ma = struct.unpack_from("<%dH" % insns_size, self.d, dau)
        ds = []
        i = 0
        while i < insns_size:
            ten = OP[ma[i] & 0xFF]
            kich = KICH.get(ten, 1)
            ds.append((i, ten, ma[i:i + kich]))
            i += kich
        return regs, ins, insns_size, ds


if __name__ == "__main__":
    duong_dan = sys.argv[1]
    ten_lop = sys.argv[2]
    ten_ham = sys.argv[3]
    so_lenh = int(sys.argv[4]) if len(sys.argv) > 4 else 8
    dx = Dex(duong_dan)
    cd = dx.tim_lop(ten_lop)
    print("lop %s -> class_data_off %s" % (ten_lop, cd))
    ds_ham = dx.ham(cd, ten_ham)
    print("ham %s -> code_off %s" % (ten_ham, ds_ham))
    for code_off in ds_ham.get(ten_ham, []):
        regs, ins, insns_size, ds = dx.doc_lenh(code_off)
        print("  code_off=%d registers=%d ins=%d insns_size=%d" % (code_off, regs, ins, insns_size))
        for i, ten, ma in ds[:so_lenh]:
            print("    [%4d] %-22s %s" % (i, ten, " ".join("0x%04x" % x for x in ma)))
