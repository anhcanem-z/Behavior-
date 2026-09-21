# -*- coding: utf-8 -*-
"""rodata_patcher — tìm chuỗi trong phân vùng .rodata/.data.rel.ro của file
.so (ELF) và sinh script Frida patch trực tiếp trên RAM.

Ý tưởng (không sửa file gốc, không giới hạn độ dài chuỗi mới):
  1. Xác định RVA (Relative Offset) của chuỗi trong .rodata — tự tìm bằng
     cách quét file .so hoặc lấy từ IDA/Ghidra (--offset).
  2. Script Frida lấy Base Address của module đang nạp (Module.findBaseAddress).
  3. Cấp phát vùng nhớ mới chứa chuỗi mới (Memory.allocUtf8String) — chuỗi mới
     có thể dài hơn chuỗi cũ tùy ý.
  4. Mở quyền ghi cho trang chứa chuỗi cũ (Memory.protect rwx) — tránh SIGSEGV
     khi ghi vào vùng Read-Only.
  5. Ghi theo 2 chiến lược:
       - inline  : ghi đè trực tiếp chuỗi mới lên vị trí cũ (kiểm tra dung
                   lượng, không cho tràn trừ khi --allow-overflow).
       - pointer : đổi con trỏ trỏ tới chuỗi (ghi NativePointer mới vào ô nhớ
                   đang giữ con trỏ cũ) — an toàn tuyệt đối với dữ liệu xung
                   quanh, chuỗi mới độ dài vô hạn.
  6. Khôi phục quyền ban đầu của trang (thường r--) để tránh phát hiện/lỗi.

Chuỗi trong mã nguồn / tên file giữ nguyên gốc.
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .elf_expander import extend_elf_with_string
    from .xref_hunter import hunt_and_patch_multiple_xrefs
    ADVANCED_BYPASS_AVAILABLE = True
except (ImportError, ValueError):
    ADVANCED_BYPASS_AVAILABLE = False

# ---- hằng số ELF ----
ELFMAG = b"\x7fELF"
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_ALLOC = 0x2
PT_LOAD = 1
PF_R = 0x4

# Tên section ưu tiên khi tìm chuỗi (phân vùng chỉ đọc chứa hằng chuỗi)
RODATA_HINTS = ("rodata", "data.rel.ro", "dynstr", "strtab", "data")


@dataclass
class StringHit:
    """Một lần xuất hiện chuỗi trong file .so."""
    file_offset: int  # offset trong file
    rva: int          # địa chỉ tương đối so với base (base.add(rva))
    section: str      # tên section chứa (hoặc "segment" khi không có section)
    value: str        # chuỗi đọc được (tới ký tự NUL)
    size: int         # độ dài chuỗi tính cả NUL (bytes)
    source: str       # "section" | "segment"



    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_offset": self.file_offset,
            "rva": self.rva,
            "section": self.section,
            "value": self.value,
            "size": self.size,
            "source": self.source,
        }


class ElfReader:
    """Đọc tối thiểu cấu trúc ELF32/ELF64 để ánh xạ file offset -> RVA.

    RVA ở đây là địa chỉ ảo tương đối so với Base Address của module khi nạp
    (ELF dạng ET_DYN có vaddr bắt đầu từ 0), nên lúc runtime chỉ cần
    Module.findBaseAddress(name).add(rva).
    """


    def is_aarch64(self) -> bool:
        """Kiểm tra xem file ELF có phải kiến trúc AArch64 không."""
        if len(self.data) < 20: return False
        import struct
        e_machine = struct.unpack('<H', self.data[18:20])[0]
        return e_machine == 183 # EM_AARCH64

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 4 or self.data[:4] != ELFMAG:
            raise ValueError("Không phải file ELF: %s" % self.path)

        ei_class = self.data[4]
        ei_data = self.data[5]
        if ei_class == 2:
            self.is64 = True
        elif ei_class == 1:
            self.is64 = False
        else:
            raise ValueError("EI_CLASS không hỗ trợ: %s" % ei_class)
        if ei_data == 1:
            self.endian = "<"
        elif ei_data == 2:
            self.endian = ">"
        else:
            raise ValueError("EI_DATA không hỗ trợ: %s" % ei_data)

        self._parse_header()
        self._parse_sections()
        self._parse_segments()
        self._section_names = self._read_section_names()

    def _parse_header(self):
        if self.is64:
            fmt = self.endian + "16sHHIQQQIHHHHHH"
            size = 64
            vals = struct.unpack(fmt, self.data[:size])
            self.e_type = vals[1]
            self.e_machine = vals[2]
            self.e_entry = vals[4]
            self.e_phoff = vals[5]
            self.e_shoff = vals[6]
            self.e_ehsize = vals[8]
            self.e_phentsize = vals[9]
            self.e_phnum = vals[10]
            self.e_shentsize = vals[11]
            self.e_shnum = vals[12]
            self.e_shstrndx = vals[13]
        else:
            fmt = self.endian + "16sHHIIIIIHHHHHH"
            size = 52
            vals = struct.unpack(fmt, self.data[:size])
            self.e_type = vals[1]
            self.e_machine = vals[2]
            self.e_entry = vals[4]
            self.e_phoff = vals[5]
            self.e_shoff = vals[6]
            self.e_ehsize = vals[8]
            self.e_phentsize = vals[9]
            self.e_phnum = vals[10]
            self.e_shentsize = vals[11]
            self.e_shnum = vals[12]
            self.e_shstrndx = vals[13]

    def _parse_sections(self):
        """self.sections: list[dict] theo thứ tự section header."""
        self.sections: List[Dict[str, Any]] = []
        if self.e_shoff == 0 or self.e_shnum == 0:
            return
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            raw = self.data[off:off + self.e_shentsize]
            if len(raw) < self.e_shentsize:
                break
            if self.is64:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = \
                    struct.unpack(self.endian + "IIQQQQIIQQ", raw[:64])
            else:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, sh_info, sh_addralign, sh_entsize) = \
                    struct.unpack(self.endian + "IIIIIIIIII", raw[:40])
            self.sections.append({
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "addralign": sh_addralign,
                "entsize": sh_entsize,
            })

    def _parse_segments(self):
        """self.segments: list[dict] PT_LOAD — dùng khi thiếu section header."""
        self.segments: List[Dict[str, Any]] = []
        if self.e_phoff == 0 or self.e_phnum == 0:
            return
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            raw = self.data[off:off + self.e_phentsize]
            if len(raw) < self.e_phentsize:
                break
            if self.is64:
                (p_type, p_flags, p_offset, p_vaddr, _p_paddr,
                 p_filesz, p_memsz, p_align) = \
                    struct.unpack(self.endian + "IIQQQQQQ", raw[:56])
            else:
                (p_type, p_offset, p_vaddr, _p_paddr,
                 p_filesz, p_memsz, p_flags, p_align) = \
                    struct.unpack(self.endian + "IIIIIIII", raw[:32])
            if p_type == PT_LOAD:
                self.segments.append({
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "align": p_align,
                })

    def _read_section_names(self) -> Dict[int, str]:
        names: Dict[int, str] = {}
        if self.e_shstrndx >= len(self.sections):
            return names
        shstr = self.sections[self.e_shstrndx]
        if shstr["type"] != SHT_STRTAB:
            return names
        table = self.data[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for idx, sec in enumerate(self.sections):
            start = sec["name_off"]
            if start < 0 or start >= len(table):
                names[idx] = ""
                continue
            end = table.find(b"\x00", start)
            if end < 0:
                end = len(table)
            try:
                names[idx] = table[start:end].decode("utf-8", "replace")
            except Exception:
                names[idx] = ""
        return names

    def section_name(self, index: int) -> str:
        return self._section_names.get(index, "")

    def section_at(self, file_offset: int) -> Optional[int]:
        """Trả index section chứa file_offset (ưu tiên section ALLOC)."""
        best = None
        for idx, sec in enumerate(self.sections):
            if sec["type"] == SHT_PROGBITS and sec["flags"] & SHF_ALLOC:
                if sec["offset"] <= file_offset < sec["offset"] + sec["size"]:
                    return idx
        for idx, sec in enumerate(self.sections):
            if sec["offset"] <= file_offset < sec["offset"] + sec["size"]:
                best = idx
        return best

    def file_offset_to_rva(self, file_offset: int) -> Tuple[int, str, str]:
        """Trả (rva, tên section, nguồn). Ưu tiên section header, fallback PT_LOAD."""
        idx = self.section_at(file_offset)
        if idx is not None:
            sec = self.sections[idx]
            rva = sec["addr"] + (file_offset - sec["offset"])
            return rva, self.section_name(idx) or "shdr[%d]" % idx, "section"
        for seg in self.segments:
            if seg["offset"] <= file_offset < seg["offset"] + seg["filesz"]:
                rva = seg["vaddr"] + (file_offset - seg["offset"])
                return rva, "segment", "segment"
        raise ValueError("Offset 0x%x nằm ngoài vùng file đã ánh xạ" % file_offset)

    def rva_to_file_offset(self, rva: int) -> Tuple[int, str]:
        """Ngược với file_offset_to_rva: RVA -> (file_offset, tên section).

        Dùng cho patch trực tiếp vào file .so (ghi đè tại offset thật).
        """
        for idx, sec in enumerate(self.sections):
            if (sec["type"] == SHT_PROGBITS and sec["flags"] & SHF_ALLOC
                    and sec["addr"] <= rva < sec["addr"] + sec["size"]):
                return sec["offset"] + (rva - sec["addr"]),                     self.section_name(idx) or "shdr[%d]" % idx
        for seg in self.segments:
            if seg["vaddr"] <= rva < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + (rva - seg["vaddr"]), "segment"
        raise ValueError("RVA 0x%x nằm ngoài vùng file đã ánh xạ" % rva)

    def read_cstring(self, file_offset: int, max_len: int = 4096) -> str:
        end = self.data.find(b"\x00", file_offset, file_offset + max_len)
        if end < 0:
            end = file_offset + max_len
        return self.data[file_offset:end].decode("utf-8", "replace")

    def list_alloc_sections(self) -> List[Dict[str, Any]]:
        """Liệt kê section ALLOC (thường chứa hằng chuỗi) để xem nhanh."""
        out = []
        for idx, sec in enumerate(self.sections):
            if sec["flags"] & SHF_ALLOC:
                out.append({
                    "index": idx,
                    "name": self.section_name(idx) or "shdr[%d]" % idx,
                    "type": sec["type"],
                    "addr": sec["addr"],
                    "offset": sec["offset"],
                    "size": sec["size"],
                })
        return out


def find_string_offsets(so_path: str | Path, needle: str,
                        all_hits: bool = False) -> List[StringHit]:
    """Tìm mọi vị trí chuỗi needle trong file .so — trả RVA + section.

    Mặc định chỉ trả các vị trí nằm trong section ALLOC (rodata/data...);
    bật all_hits để lấy cả vị trí ngoài vùng ánh xạ (debug/comment...).
    """
    reader = ElfReader(so_path)
    pattern = needle.encode("utf-8")
    hits: List[StringHit] = []
    start = 0
    while True:
        pos = reader.data.find(pattern, start)
        if pos < 0:
            break
        start = pos + 1
        try:
            rva, section, source = reader.file_offset_to_rva(pos)
        except ValueError:
            if not all_hits:
                continue
            rva, section, source = 0, "(ngoài vùng ánh xạ)", "none"
        value = reader.read_cstring(pos)
        # mở rộng size tới NUL để biết dung lượng chuỗi cũ
        nul = reader.data.find(b"\x00", pos, pos + 4096)
        if nul >= 0:
            size = nul - pos + 1
        else:
            size = len(pattern) + 1
        hits.append(StringHit(
            file_offset=pos, rva=rva, section=section,
            value=value, size=size, source=source,
        ))
    return hits


# =====================================================================
# SINH SCRIPT FRIDA
# =====================================================================

DEFAULT_MODULE_HINT = "libnative-lib.so"


def _hex_pattern(text: str) -> str:
    """Chuyển chuỗi thành pattern hex cho Memory.scanSync (vd '68 74 74 70')."""
    return " ".join("%02x" % b for b in text.encode("utf-8"))


RODATA_JS_TEMPLATE = """\
// ============================================================
// PatchX rodata-patcher — patch chuỗi trong .rodata trên RAM
// (không sửa file .so/.elf gốc, không giới hạn độ dài chuỗi mới)
// ============================================================

var RODATA_PATCHES = $patches_json;
var RODATA_OPTIONS = $options_json;

function rodataAlignDown(addr) {
    var pageSize = Memory.pageSize;
    var value = parseInt(addr.toString(), 16);
    var aligned = Math.floor(value / pageSize) * pageSize;
    return ptr('0x' + aligned.toString(16));
}

function rodataCapacity(target, maxBytes) {
    var cap = 0;
    var p = target;
    while (cap < maxBytes) {
        try {
            if (p.readU8() === 0) break;
        } catch (e) {
            break;
        }
        p = p.add(1);
        cap++;
    }
    return cap;
}

function rodataProtectRegion(addr, byteLen) {
    var pageSize = Memory.pageSize;
    var start = rodataAlignDown(addr);
    var endValue = parseInt(addr.add(byteLen).toString(), 16);
    var startValue = parseInt(start.toString(), 16);
    var span = Math.max(pageSize, endValue - startValue);
    var regionSize = Math.ceil(span / pageSize) * pageSize;
    return { start: start, size: regionSize };
}

function rodataPatchInline(target, patch) {
    var need = patch.new_len;
    var cap = rodataCapacity(target, Math.max(Memory.pageSize, need));
    if (cap < need && !RODATA_OPTIONS.allow_overflow) {
        console.log('[-] Bỏ qua ' + target + ': chuỗi mới (' + need +
            'B) vượt dung lượng (' + cap + 'B). Dùng --allow-overflow nếu muốn ghi đè.');
        return;
    }
    var range = Process.getRangeInfo(target);
    var oldProt = range ? range.protection : 'r--';
    var region = rodataProtectRegion(target, need);
    try {
        Memory.protect(region.start, region.size, 'rwx');
    } catch (e) {
        console.log('[-] Memory.protect lỗi: ' + e);
        return;
    }
    try {
        target.writeUtf8String(patch.new_string);
        console.log('[+] Ghi inline "' + patch.new_string + '" tại ' + target);
        send({ type: 'rodata_patch', mode: 'inline', target: target.toString(),
               module: patch.module, new_string: patch.new_string });
    } catch (e) {
        console.log('[-] Ghi inline lỗi: ' + e);
    } finally {
        if (RODATA_OPTIONS.restore) {
            Memory.protect(region.start, region.size, oldProt);
        }
    }
}

function rodataPatchPointer(slot, patch) {
    var buf = Memory.allocUtf8String(patch.new_string);
    if (buf.isNull()) {
        console.log('[-] Cấp phát chuỗi mới thất bại: ' + patch.new_string);
        return;
    }
    var range = Process.getRangeInfo(slot);
    var oldProt = range ? range.protection : 'r--';
    var region = rodataProtectRegion(slot, Process.pointerSize);
    try {
        Memory.protect(region.start, region.size, 'rwx');
    } catch (e) {
        console.log('[-] Memory.protect (pointer) lỗi: ' + e);
        return;
    }
    try {
        slot.writePointer(buf);
        console.log('[+] Đổi con trỏ tại ' + slot + ' -> ' + buf +
            ' ("' + patch.new_string + '")');
        send({ type: 'rodata_patch', mode: 'pointer', slot: slot.toString(),
               module: patch.module, new_string: patch.new_string });
    } catch (e) {
        console.log('[-] Ghi con trỏ lỗi: ' + e);
    } finally {
        if (RODATA_OPTIONS.restore) {
            Memory.protect(region.start, region.size, oldProt);
        }
    }
}

function rodataScanModule(base, patch) {
    var mod = Process.findModuleByName(patch.module);
    if (mod === null) {
        console.log('[-] Không tìm thấy module: ' + patch.module);
        return;
    }
    var found = 0;
    var ranges = mod.enumerateRanges('r--');
    ranges.forEach(function (range) {
        var matches = Memory.scanSync(range.base, range.size, patch.old_pattern);
        matches.forEach(function (m) {
            rodataPatchInline(m.address, patch);
            found++;
        });
    });
    console.log('[+] ' + patch.module + ': runtime scan ghi đè ' + found + ' vị trí.');
}

function rodataPatchEntry(base, patch) {
    var hasSlot = patch.ptr_rva !== null && patch.ptr_rva !== undefined;
    if (patch.runtime_scan) {
        rodataScanModule(base, patch);
        return;
    }
    var target = base.add(patch.rva);
    if (patch.mode === 'pointer' || patch.mode === 'both') {
        if (hasSlot) {
            rodataPatchPointer(base.add(patch.ptr_rva), patch);
        } else if (patch.mode === 'pointer') {
            console.log('[-] Mode pointer cần ptr_rva (ô nhớ giữ con trỏ cũ).');
        }
    }
    if (patch.mode === 'inline' || patch.mode === 'both') {
        rodataPatchInline(target, patch);
    }
}

function rodataPatchAll() {
    var groups = {};
    RODATA_PATCHES.forEach(function (p) {
        (groups[p.module] = groups[p.module] || []).push(p);
    });
    Object.keys(groups).forEach(function (name) {
        var base = Module.findBaseAddress(name);
        if (base === null) {
            console.log('[-] Không tìm thấy module: ' + name);
            return;
        }
        console.log('[+] Module ' + name + ' base = ' + base);
        groups[name].forEach(function (p) {
            try {
                rodataPatchEntry(base, p);
            } catch (e) {
                console.log('[-] Lỗi patch: ' + e);
            }
        });
    });
}

// Không cần Java.perform — thao tác thuần native, chạy được cả trên app
// không có runtime Java (pure native).
rodataPatchAll();
"""


def _normalize_patch(patch: Dict[str, Any], so_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Chuẩn hóa một patch: điền rva từ old_string nếu thiếu, tính độ dài bytes."""
    out = dict(patch)
    out.setdefault("module", DEFAULT_MODULE_HINT)
    out.setdefault("mode", "both")
    out.setdefault("ptr_rva", None)
    out.setdefault("runtime_scan", False)
    out.setdefault("label", "")

    def _to_int(value, name):
        if value is None or isinstance(value, int):
            return value
        try:
            return int(str(value), 0)
        except ValueError:
            raise ValueError("Patch %s không hợp lệ: %r" % (name, value))

    out["rva"] = _to_int(out.get("rva"), "rva")
    out["ptr_rva"] = _to_int(out.get("ptr_rva"), "ptr_rva")
    new_string = str(out.get("new_string", "") or "")
    if not new_string:
        raise ValueError("Patch thiếu new_string: %r" % patch)
    out["new_string"] = new_string
    out["new_len"] = len(new_string.encode("utf-8")) + 1  # tính cả NUL

    old_string = out.get("old_string")
    if old_string is not None:
        old_string = str(old_string)
        out["old_string"] = old_string
        out["old_len"] = len(old_string.encode("utf-8"))
        out["old_pattern"] = _hex_pattern(old_string)

    if out.get("runtime_scan"):
        if not old_string:
            raise ValueError("runtime_scan cần old_string để quét pattern")
        out["rva"] = None
        return out

    rva = out.get("rva")
    if rva is None and old_string:
        if not so_path:
            raise ValueError(
                "Tự tìm RVA theo old_string cần truyền so_path (file .so)")
        hits = find_string_offsets(Path(so_path), old_string)
        if not hits:
            raise ValueError(
                "Không tìm thấy chuỗi %r trong file — dùng --offset để khai báo RVA thủ công"
                % old_string)
        if len(hits) > 1:
            detail = "; ".join("0x%x (%s)" % (h.rva, h.section) for h in hits)
            raise ValueError(
                "Chuỗi %r xuất hiện nhiều vị trí: %s — dùng --offset để chọn RVA"
                % (old_string, detail))
        rva = hits[0].rva
    if rva is None:
        raise ValueError("Patch thiếu rva (dùng --offset hoặc --string để tự tìm)")
    out["rva"] = int(rva)
    return out


def normalize_rodata_patches(patches: List[Dict[str, Any]],
                              so_path: Optional[str | Path] = None
                              ) -> List[Dict[str, Any]]:
    """Chuẩn hóa danh sách patch (điền RVA, tính độ dài bytes) — public.

    Dùng để kiểm tra/lấy số liệu (vd cảnh báo inline vượt dung lượng)
    trước khi sinh script.
    """
    return [_normalize_patch(p, so_path=so_path) for p in patches]


def generate_rodata_patch_script(patches: List[Dict[str, Any]],
                                 restore: bool = True,
                                 allow_overflow: bool = False,
                                 so_path: Optional[str | Path] = None) -> str:
    """Sinh script Frida patch .rodata từ danh sách patch.

    Mỗi patch (dict) nhận:
      module        tên thư viện .so khi nạp (mặc định libnative-lib.so)
      rva           RVA chuỗi gốc trong .rodata (base.add(rva)); có thể bỏ qua
                    nếu có old_string để tự tìm trong so_path
      ptr_rva       RVA ô nhớ đang giữ con trỏ tới chuỗi (dùng cho mode pointer)
      mode          inline | pointer | both
      new_string    chuỗi mới (độ dài tùy ý)
      old_string    chuỗi gốc (dùng để tự tìm RVA và kiểm tra dung lượng)
      runtime_scan  quét RAM module tìm old_string rồi ghi inline
    """
    normalized = normalize_rodata_patches(patches, so_path=so_path)
    if not normalized:
        raise ValueError("Không có patch nào để sinh script")

    options = {
        "restore": bool(restore),
        "allow_overflow": bool(allow_overflow),
    }
    patches_json = json.dumps(normalized, ensure_ascii=False, indent=2)
    options_json = json.dumps(options, ensure_ascii=False, indent=2)
    script = (RODATA_JS_TEMPLATE
              .replace("$patches_json", patches_json)
              .replace("$options_json", options_json))
    return script


def write_rodata_script(patches: List[Dict[str, Any]],
                        output_file: str | Path,
                        restore: bool = True,
                        allow_overflow: bool = False,
                        so_path: Optional[str | Path] = None) -> Path:
    """Sinh script Frida và ghi ra file — trả đường dẫn đã ghi."""
    script = generate_rodata_patch_script(
        patches, restore=restore, allow_overflow=allow_overflow,
        so_path=so_path)
    out = Path(output_file)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(script, encoding="utf-8")
    return out


DEFAULT_BACKUP_DIR = Path("outputs") / "backup" / "rodata_apply"


def patch_so_file(so_path: str | Path,
                  patches: List[Dict[str, Any]],
                  out_path: Optional[str | Path] = None,
                  allow_overflow: bool = False,
                  backup: bool = True,
                  backup_dir: Optional[str | Path] = None,
                  advanced_bypass: bool = False) -> Dict[str, Any]:
    """Chèn chuỗi mới TRỰC TIẾP vào file .so (patch file, không cần Frida).

    Khác rodata-patch (Frida RAM): patch file bị GIỚI HẠN độ dài — chuỗi mới
    không được dài hơn dung lượng chuỗi cũ (tính tới NUL), nếu không sẽ phá
    cấu trúc file. Khi vượt: báo lỗi trừ khi allow_overflow=True (rủi ro) hoặc
    advanced_bypass=True (mở rộng ELF + vá XREF tự động trên AArch64).

    - mode pointer / runtime_scan: KHÔNG áp được vào file (pointer cần
      relocation lúc load; runtime_scan cần RAM) — báo lỗi rõ.
    - Mặc định sao lưu file gốc vào backup_dir (outputs/backup/rodata_apply/);
      tắt bằng backup=False. out_path khác None thì ghi bản mới, không đụng
      file gốc.
    """
    reader = ElfReader(so_path)
    data = bytearray(reader.data)
    report: Dict[str, Any] = {
        "so": str(so_path),
        "patched": [],
        "backup": None,
    }

    for patch in patches:
        npatch = _normalize_patch(patch, so_path=so_path)
        if npatch.get("runtime_scan"):
            raise ValueError(
                "runtime_scan chỉ dùng cho Frida RAM — không áp được vào file")
        if npatch.get("mode") == "pointer":
            raise ValueError(
                "mode pointer không áp trực tiếp vào file (con trỏ cần "
                "relocation lúc nạp); dùng rodata-patch để sinh script Frida")
        rva = npatch["rva"]
        file_offset, section = reader.rva_to_file_offset(rva)

        new_bytes = npatch["new_string"].encode("utf-8")
        nul = reader.data.find(b"\x00", file_offset, file_offset + 4096)
        if nul >= 0:
            cap = nul - file_offset          # byte tới NUL (không gồm NUL)
            old_end = nul + 1                # vị trí sau NUL cũ
        else:
            cap = len(reader.data) - file_offset
            old_end = file_offset + cap

        if len(new_bytes) > cap and not allow_overflow:
            use_adv = advanced_bypass or npatch.get("advanced_bypass", False)
            if use_adv and ADVANCED_BYPASS_AVAILABLE and reader.is_aarch64():
                report["patched"].append({
                    "rva": rva,
                    "file_offset": file_offset,
                    "section": section,
                    "old_value": npatch.get("old_string", ""),
                    "new_value": npatch["new_string"],
                    "new_bytes": len(new_bytes),
                    "capacity": cap,
                    "overflow": True,
                    "advanced_bypass": True,
                })
                continue
            else:
                raise ValueError(
                    "Chuỗi mới (%dB) dài hơn dung lượng tại offset 0x%x (%dB) — "
                    "Dùng luồng ĐỘNG (Frida RAM) hoặc bật Advanced Bypass trên AArch64." % (
                        len(new_bytes), file_offset, cap))


        old_value = reader.data[file_offset:old_end].decode("utf-8",
                                                            "replace")
        data[file_offset:file_offset + len(new_bytes)] = new_bytes
        if len(new_bytes) <= cap:
            # NUL + xóa phần dư của chuỗi cũ (tránh chuỗi ghép lộ ra)
            data[file_offset + len(new_bytes):old_end] = \
                b"\x00" * (old_end - file_offset - len(new_bytes))
        else:
            data[file_offset + len(new_bytes)] = 0  # NUL kết thúc chuỗi mới

        report["patched"].append({
            "rva": rva,
            "file_offset": file_offset,
            "section": section,
            "old_value": old_value.rstrip("\x00"),
            "new_value": npatch["new_string"],
            "new_bytes": len(new_bytes),
            "capacity": cap,
            "overflow": len(new_bytes) > cap,
        })

    if backup and out_path is None:
        bdir = Path(backup_dir or DEFAULT_BACKUP_DIR)
        bdir.mkdir(parents=True, exist_ok=True)
        backup_path = bdir / ("%s-%s.bak" % (
            Path(so_path).name,
            time.strftime("%Y%m%d-%H%M%S")))
        backup_path.write_bytes(reader.data)
        report["backup"] = str(backup_path)

    target = Path(out_path) if out_path else Path(so_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes(data))
    report["out"] = str(target)
    
    # Thực thi Advanced Static Bypass sau khi đã ghi file
    advanced_patches = [p for p in report["patched"] if p.get("advanced_bypass")]
    if advanced_patches:
        rva_map = {}
        for p in advanced_patches:
            new_rva = extend_elf_with_string(target, p["new_value"].encode("utf-8"))
            p["new_rva"] = new_rva
            rva_map[p["rva"]] = new_rva
        
        # Vá tất cả XREF trong 1 pass
        xrefs = hunt_and_patch_multiple_xrefs(str(target), rva_map)
        for p in advanced_patches:
            p["xrefs_patched"] = xrefs.get(p["rva"], 0)
            
    return report
