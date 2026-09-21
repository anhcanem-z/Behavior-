# -*- coding: utf-8 -*-
"""Direct DEX Bytecode & Header Inplace Patching (Kế thừa và nâng cấp từ Modder Hub).

Cho phép can thiệp trực tiếp file `.dex` ở mức nhị phân:
- Đọc và phân tích Header (DEX 035/037/038/039).
- Quét và thay thế chuỗi in-place trong bảng chuỗi / data pool.
- Quét và thay thế bytecode/opcode nhị phân (SET_BOOL, FORCE_TRUE, NOP, RETURN_VOID).
- Tự động tính lại SHA-1 Signature và Adler32 Checksum sau khi sửa đổi.
- Hỗ trợ Fast-Path không cần qua apktool decompile/rebuild.
"""

import hashlib
import os
import re
import shutil
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEX_MAGICS = (
    b"dex\n035\0",
    b"dex\n037\0",
    b"dex\n038\0",
    b"dex\n039\0",
)

# Các mẫu opcode Dalvik chuẩn (16-bit code unit)
OP_NOP = b"\x00\x00"
OP_RETURN_VOID = b"\x0e\x00"
OP_RETURN_V0 = b"\x0f\x00"
OP_CONST_4_V0_1 = b"\x12\x10"  # const/4 v0, 0x1
OP_CONST_4_V0_0 = b"\x12\x00"  # const/4 v0, 0x0
FORCE_TRUE_V0 = b"\x12\x10\x0f\x00"  # const/4 v0, 1; return v0 (4 bytes)
FORCE_FALSE_V0 = b"\x12\x00\x0f\x00"  # const/4 v0, 0; return v0 (4 bytes)
RETURN_VOID = b"\x0e\x00"  # return-void (2 bytes)


class DexHeader:
    """Đại diện cấu trúc DEX Header chuẩn (112 bytes)."""

    def __init__(self, raw_bytes):
        if len(raw_bytes) < 112:
            raise ValueError("Dữ liệu quá ngắn không đủ DEX header (cần >= 112 bytes)")
        self.magic = raw_bytes[0:8]
        if self.magic not in DEX_MAGICS:
            raise ValueError("Magic DEX không hợp lệ: %r" % self.magic)

        (
            self.checksum,
            self.signature,
            self.file_size,
            self.header_size,
            self.endian_tag,
            self.link_size,
            self.link_off,
            self.map_off,
            self.string_ids_size,
            self.string_ids_off,
            self.type_ids_size,
            self.type_ids_off,
            self.proto_ids_size,
            self.proto_ids_off,
            self.field_ids_size,
            self.field_ids_off,
            self.method_ids_size,
            self.method_ids_off,
            self.class_defs_size,
            self.class_defs_off,
            self.data_size,
            self.data_off,
        ) = struct.unpack("<I20s20I", raw_bytes[8:112])


def recalculate_dex_checksums(dex_data):
    """Tính lại SHA-1 (offset 12..32) và Adler32 (offset 8..12) cho DEX bytes."""
    data = bytearray(dex_data)
    if len(data) < 112:
        return bytes(data)

    # 1. SHA-1 signature từ offset 32 đến hết file
    sha1 = hashlib.sha1(data[32:]).digest()
    data[12:32] = sha1

    # 2. Adler32 checksum từ offset 12 đến hết file
    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    data[8:12] = struct.pack("<I", adler)

    return bytes(data)


def inspect_dex(dex_bytes):
    """Phân tích cấu trúc cơ bản của buffer DEX nhị phân."""
    hdr = DexHeader(dex_bytes)
    return {
        "magic": hdr.magic.decode("latin-1", errors="replace"),
        "file_size": hdr.file_size,
        "string_ids": hdr.string_ids_size,
        "type_ids": hdr.type_ids_size,
        "method_ids": hdr.method_ids_size,
        "class_defs": hdr.class_defs_size,
        "data_size": hdr.data_size,
    }


def replace_string_inline(dex_bytes, old_str, new_str):
    """Thay thế chuỗi UTF-8 in-place nếu độ dài chuỗi mới <= chuỗi cũ.

    Tự động đệm null bytes và cập nhật checksum/signature.
    """
    if isinstance(old_str, str):
        old_b = old_str.encode("utf-8")
    else:
        old_b = old_str

    if isinstance(new_str, str):
        new_b = new_str.encode("utf-8")
    else:
        new_b = new_str

    if not old_b:
        raise ValueError("Chuỗi cũ không được để trống")

    if len(new_b) > len(old_b):
        raise ValueError(
            "Chuỗi mới (%d bytes) dài hơn chuỗi cũ (%d bytes), không thể sửa in-place."
            % (len(new_b), len(old_b))
        )

    # Đệm byte null cho phần thừa
    padded_new_b = new_b + b"\x00" * (len(old_b) - len(new_b))
    count = dex_bytes.count(old_b)
    if count == 0:
        return dex_bytes, 0

    new_data = dex_bytes.replace(old_b, padded_new_b)
    updated = recalculate_dex_checksums(new_data)
    return updated, count


def _normalize_pattern(pat):
    """Chuyển đổi chuỗi hex hoặc bytes thành bytes."""
    if isinstance(pat, str):
        cleaned = pat.replace(" ", "").replace("0x", "")
        return bytes.fromhex(cleaned)
    return bytes(pat)


def replace_bytecode_pattern(dex_bytes, target_pattern, replacement_pattern, pad_nop=True):
    """Thay thế một chuỗi opcode/bytecode nhị phân in-place trong DEX.

    :param dex_bytes: buffer nhị phân file DEX
    :param target_pattern: chuỗi byte hoặc hex cần tìm
    :param replacement_pattern: chuỗi byte hoặc hex thay thế (phải có len <= target)
    :param pad_nop: nếu True, đệm các cặp byte thừa bằng NOP (0x00 0x00)
    :return: (updated_dex_bytes, hit_count)
    """
    target_b = _normalize_pattern(target_pattern)
    repl_b = _normalize_pattern(replacement_pattern)

    if not target_b:
        raise ValueError("Target pattern không được để trống")

    if len(repl_b) > len(target_b):
        raise ValueError(
            "Replacement (%d bytes) dài hơn target pattern (%d bytes), không thể sửa in-place."
            % (len(repl_b), len(target_b))
        )

    remainder = len(target_b) - len(repl_b)
    if pad_nop and remainder > 0:
        # Trong Dalvik bytecode, các lệnh là bội của 2 bytes (16-bit)
        nop_units = remainder // 2
        extra_bytes = remainder % 2
        padded_repl = repl_b + (OP_NOP * nop_units) + (b"\x00" * extra_bytes)
    else:
        padded_repl = repl_b + (b"\x00" * remainder)

    count = dex_bytes.count(target_b)
    if count == 0:
        return dex_bytes, 0

    new_data = dex_bytes.replace(target_b, padded_repl)
    updated = recalculate_dex_checksums(new_data)
    return updated, count


def patch_dex_file_strings(dex_path, replacements, backup_dir=None):
    """Áp dụng danh sách thay thế chuỗi lên file .dex và cập nhật checksum."""
    if not os.path.isfile(dex_path):
        raise FileNotFoundError("Không tìm thấy tệp DEX: %s" % dex_path)

    with open(dex_path, "rb") as fh:
        raw = fh.read()

    _ = DexHeader(raw)  # validate header

    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        bak = os.path.join(backup_dir, os.path.basename(dex_path) + ".bak")
        shutil.copy2(dex_path, bak)

    curr_bytes = raw
    total_replaced = 0
    details = []

    for old_s, new_s in replacements:
        curr_bytes, n = replace_string_inline(curr_bytes, old_s, new_s)
        total_replaced += n
        details.append({"old": str(old_s), "new": str(new_s), "hits": n})

    with open(dex_path, "wb") as fh:
        fh.write(curr_bytes)

    return {
        "dex_path": dex_path,
        "total_replaced": total_replaced,
        "details": details,
        "new_size": len(curr_bytes),
    }


def patch_dex_file_bytecode(dex_path, replacements, backup_dir=None):
    """Áp dụng danh sách thay thế bytecode/opcode lên file .dex và cập nhật checksum.

    replacements: list of (target_pattern, replacement_pattern)
    """
    if not os.path.isfile(dex_path):
        raise FileNotFoundError("Không tìm thấy tệp DEX: %s" % dex_path)

    with open(dex_path, "rb") as fh:
        raw = fh.read()

    _ = DexHeader(raw)

    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        bak = os.path.join(backup_dir, os.path.basename(dex_path) + ".bak")
        shutil.copy2(dex_path, bak)

    curr_bytes = raw
    total_replaced = 0
    details = []

    for item in replacements:
        target = item[0]
        repl = item[1]
        pad = item[2] if len(item) > 2 else True
        curr_bytes, n = replace_bytecode_pattern(curr_bytes, target, repl, pad_nop=pad)
        total_replaced += n
        details.append({
            "target": target.hex() if isinstance(target, (bytes, bytearray)) else str(target),
            "replacement": repl.hex() if isinstance(repl, (bytes, bytearray)) else str(repl),
            "hits": n,
        })

    with open(dex_path, "wb") as fh:
        fh.write(curr_bytes)

    return {
        "dex_path": dex_path,
        "total_replaced": total_replaced,
        "details": details,
        "new_size": len(curr_bytes),
    }


# =====================================================================
# NÂNG CẤP T2 (2026-09-19): sửa DEX ở MỨC PHƯƠNG THỨC trên cùng nền năng lực
# có sẵn (DexHeader + recalculate_dex_checksums + thay bytecode).
# =====================================================================

def read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    """Đọc số nguyên không dấu mã dài thay đổi (ULEB128) tại vị trí pos."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("ULEB128 cụt ngang tại offset %d" % pos)
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 70:
            raise ValueError("ULEB128 quá dài tại offset %d" % pos)
    return result, pos


class DexMethodMap:
    """Ánh xạ tên lớp + tên phương thức -> code_item (offset lệnh, số lệnh).

    Đi theo chuỗi quan hệ chuẩn của định dạng DEX:
    string_ids -> type_ids -> proto_ids -> method_ids -> class_defs
    -> class_data_item -> encoded_method -> code_item.
    """

    def __init__(self, dex_data: bytes):
        if len(dex_data) < 112:
            raise ValueError("Dữ liệu DEX quá ngắn")
        self.data = bytearray(dex_data)
        self.hdr = DexHeader(bytes(dex_data))
        self._str_off = self._build_string_offsets()

    def _build_string_offsets(self) -> List[int]:
        h = self.hdr
        base = h.string_ids_off
        out = []
        for i in range(h.string_ids_size):
            off = base + i * 4
            if off + 4 > len(self.data):
                raise ValueError("Bảng string_ids ngoài tệp")
            out.append(struct.unpack_from("<I", self.data, off)[0])
        return out

    def get_string(self, idx: int) -> str:
        if not (0 <= idx < len(self._str_off)):
            return ""
        pos = self._str_off[idx]
        if pos >= len(self.data):
            return ""
        try:
            _utf16_len, pos = read_uleb128(self.data, pos)
            end = self.data.find(b"\x00", pos)
            if end < 0:
                end = len(self.data)
            return bytes(self.data[pos:end]).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def get_type(self, type_idx: int) -> str:
        h = self.hdr
        off = h.type_ids_off + type_idx * 4
        if off + 4 > len(self.data) or not (0 <= type_idx < h.type_ids_size):
            return ""
        sidx = struct.unpack_from("<I", self.data, off)[0]
        return self.get_string(sidx)

    def method_id(self, idx: int) -> Dict[str, Any]:
        h = self.hdr
        off = h.method_ids_off + idx * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, off)
        return {"idx": idx, "class_idx": class_idx, "proto_idx": proto_idx,
                "name_idx": name_idx, "name": self.get_string(name_idx),
                "class_name": self.get_type(class_idx)}

    def _read_class_data(self, off: int) -> Dict[str, Any]:
        if off == 0:
            return {"direct": [], "virtual": []}
        pos = off
        sizes = []
        for _ in range(4):
            v, pos = read_uleb128(self.data, pos)
            sizes.append(v)
        for _ in range(sizes[0] + sizes[1]):
            for _ in range(2):
                _, pos = read_uleb128(self.data, pos)
        direct = []
        virtual = []
        method_idx = 0
        for bucket in (direct, virtual):
            for _ in range(sizes[2] if bucket is direct else sizes[3]):
                diff, pos = read_uleb128(self.data, pos)
                _, pos = read_uleb128(self.data, pos)
                code_off, pos = read_uleb128(self.data, pos)
                method_idx += diff
                bucket.append({"method_idx": method_idx, "code_off": code_off})
        return {"direct": direct, "virtual": virtual}

    def map_methods(self) -> List[Dict[str, Any]]:
        h = self.hdr
        out: List[Dict[str, Any]] = []
        for ci in range(h.class_defs_size):
            cd_off = h.class_defs_off + ci * 32
            if cd_off + 32 > len(self.data):
                break
            (class_idx, _access, _super, _ifaces, _src, _ann, class_data_off,
             _static_vals) = struct.unpack_from("<8I", self.data, cd_off)
            class_name = self.get_type(class_idx)
            cd = self._read_class_data(class_data_off)
            for is_direct, bucket in ((True, cd["direct"]), (False, cd["virtual"])):
                for enc in bucket:
                    mid = self.method_id(enc["method_idx"])
                    item = {"class_name": class_name, "name": mid["name"],
                            "method_idx": mid["idx"], "code_off": enc["code_off"],
                            "is_direct": is_direct}
                    self._fill_code_item(item)
                    out.append(item)
        return out

    def _fill_code_item(self, item: Dict[str, Any]) -> None:
        off = item["code_off"]
        if off == 0 or off + 16 > len(self.data):
            item["has_code"] = False
            return
        (regs, ins, outs, tries, _debug, insns_size) = struct.unpack_from(
            "<HHHHII", self.data, off)
        insns_off = off + 16
        insns_bytes = insns_size * 2
        end = insns_off + insns_bytes
        item.update({"has_code": True, "registers": regs, "ins": ins,
                     "outs": outs, "tries": tries, "insns_size": insns_size,
                     "insns_off": insns_off, "insns_end": min(end, len(self.data))})


def normalize_hex(s: str) -> bytes:
    """Chuyển chuỗi hex dạng '12 00' hoặc '1200' hoặc '0x12' thành bytes."""
    s = s.strip().replace("0x", "").replace(" ", "").replace(",", "")
    if len(s) % 2:
        raise ValueError("Chuỗi hex lẻ ký tự: %r" % s)
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError("Chuỗi hex không hợp lệ %r: %s" % (s, exc)) from exc


def patch_method_opcode(dex_data: bytes, method_regex: str,
                        target: str, replacement: str,
                        limit: int = 1) -> Dict[str, Any]:
    """Thay mẫu lệnh cùng độ dài byte CHỈ trong khoảng lệnh của phương thức khớp.

    Nâng cấp từ replace_bytecode_pattern: thêm ràng buộc phạm vi theo phương
    thức để không vô tình đụng dữ liệu ngoài mã; vẫn zero-drift + tính lại
    checksum/signature bằng nền đã có.
    """
    tgt = normalize_hex(target)
    repl = normalize_hex(replacement)
    if len(tgt) != len(repl):
        raise ValueError(
            "Mẫu mới (%d byte) phải bằng mẫu cũ (%d byte) để giữ nguyên cấu trúc"
            % (len(repl), len(tgt)))
    if not tgt:
        raise ValueError("Mẫu cũ không được trống")
    try:
        rx = re.compile(method_regex)
    except re.error as exc:
        raise ValueError("Regex tên phương thức sai: %s" % exc) from exc

    mmap = DexMethodMap(dex_data)
    data = bytearray(dex_data)
    hits = []
    for item in mmap.map_methods():
        if not item.get("has_code") or not rx.search(item["name"]):
            continue
        window = bytes(data[item["insns_off"]:item["insns_end"]])
        pos = 0
        while limit <= 0 or len(hits) < limit:
            found = window.find(tgt, pos)
            if found < 0:
                break
            abs_off = item["insns_off"] + found
            data[abs_off:abs_off + len(repl)] = repl
            hits.append({"method": item["name"], "class": item["class_name"],
                         "offset": abs_off, "method_idx": item["method_idx"]})
            pos = found + len(tgt)
    if not hits:
        return {"changed": False, "hits": 0, "data": bytes(data),
                "reason": "không tìm thấy phương thức khớp hoặc mẫu lệnh"}
    return {"changed": True, "hits": len(hits), "data":
            recalculate_dex_checksums(bytes(data)), "matches": hits}


def map_methods_report(dex_data: bytes, filter_regex: Optional[str] = None,
                       limit: int = 200) -> Dict[str, Any]:
    """Báo cáo bản đồ phương thức DEX (dùng chung DexMethodMap)."""
    mmap = DexMethodMap(dex_data)
    rx = re.compile(filter_regex) if filter_regex else None
    methods = []
    for item in mmap.map_methods():
        if rx and not rx.search(item["name"]) and not rx.search(item["class_name"]):
            continue
        methods.append(item)
        if len(methods) >= limit:
            break
    return {"header": {
                "magic": mmap.hdr.magic.decode("latin-1", errors="replace"),
                "file_size": mmap.hdr.file_size,
                "method_ids": mmap.hdr.method_ids_size,
                "class_defs": mmap.hdr.class_defs_size},
            "methods": methods, "shown": len(methods)}


def apply_dex_method_patch(path: str | Path, method_regex: str,
                           target: str, replacement: str,
                           backup_dir: Optional[str | Path] = None,
                           dry_run: bool = True) -> Dict[str, Any]:
    """Áp bản vá mức phương thức lên tệp .dex (sao lưu nếu ghi thật)."""
    fp = Path(path)
    original = fp.read_bytes()
    rep = patch_method_opcode(original, method_regex, target, replacement)
    rep["path"] = str(fp)
    rep["dry_run"] = dry_run
    if rep["changed"] and not dry_run:
        if backup_dir is not None:
            bdir = Path(backup_dir)
            bdir.mkdir(parents=True, exist_ok=True)
            bak = bdir / (fp.name + ".bak")
            if not bak.exists():
                bak.write_bytes(original)
        fp.write_bytes(rep["data"])
        rep["backup"] = str(bdir) if backup_dir else None
    return rep
