# -*- coding: utf-8 -*-
"""xref_hunter — Fast XREF Scanner for AArch64."""

import struct
from .aarch64_asm import decode_adrp, decode_add_imm, encode_adrp, encode_add_imm

def hunt_and_patch_multiple_xrefs(file_path: str, rva_map: dict) -> dict:
    """Quét và vá tất cả ADRP/ADD trỏ tới các old_rva trong 1 pass."""
    
    text_offset = 0
    text_vaddr = 0
    text_size = 0
    
    with open(file_path, 'r+b') as f:
        e_ident = f.read(16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHLQQQLHHHHHH', f.read(48))
        
        f.seek(e_phoff)
        for i in range(e_phnum):
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<LLQQQQQQ', f.read(e_phentsize))
            if p_type == 1 and (p_flags & 1): # PT_LOAD and Executable (PF_X)
                text_offset = p_offset
                text_vaddr = p_vaddr
                text_size = p_filesz
                break
                
        if text_size == 0:
            raise ValueError("Không tìm thấy PT_LOAD Executable")
            
        old_pages = {old_rva & ~0xFFF: old_rva for old_rva in rva_map.keys()}
        patched_counts = {old_rva: 0 for old_rva in rva_map.keys()}
        
        f.seek(text_offset)
        text_data = bytearray(f.read(text_size))
        
        total_patched = 0
        
        for i in range(0, text_size, 4):
            b3 = text_data[i+3]
            if b3 in (0x90, 0xb0, 0xd0, 0xf0):
                inst = struct.unpack('<I', text_data[i:i+4])[0]
                adrp_res = decode_adrp(inst)
                if adrp_res:
                    rd, page_offset = adrp_res
                    pc = text_vaddr + i
                    target_page = (pc & ~0xFFF) + page_offset
                    
                    if target_page in old_pages:
                        # Look for ADD
                        for j in range(i+4, min(i+40, text_size), 4):
                            add_inst = struct.unpack('<I', text_data[j:j+4])[0]
                            add_res = decode_add_imm(add_inst)
                            if add_res:
                                add_rd, add_rn, imm12 = add_res
                                if add_rn == rd and (target_page + imm12) in rva_map:
                                    old_rva = target_page + imm12
                                    new_rva = rva_map[old_rva]
                                    
                                    new_adrp = encode_adrp(rd, pc, new_rva)
                                    new_add = encode_add_imm(add_rd, rd, new_rva & 0xFFF)
                                    
                                    text_data[i:i+4] = struct.pack('<I', new_adrp)
                                    text_data[j:j+4] = struct.pack('<I', new_add)
                                    
                                    patched_counts[old_rva] += 1
                                    total_patched += 1
                                    break
        
        if total_patched > 0:
            f.seek(text_offset)
            f.write(text_data)
            
    return patched_counts

def hunt_and_patch_xrefs(file_path: str, old_rva: int, new_rva: int) -> int:
    return hunt_and_patch_multiple_xrefs(file_path, {old_rva: new_rva})[old_rva]
