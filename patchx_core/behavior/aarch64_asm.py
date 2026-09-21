# -*- coding: utf-8 -*-
"""aarch64_asm — Pure Python AArch64 Assembler/Disassembler for patchx.

Cung cấp khả năng phân tích và tái tạo mã máy (ADRP/ADD) để patch XREF.
"""

def sign_extend(val, bits):
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)

def decode_adrp(inst: int) -> tuple[int, int] | None:
    """Trả về (Rd, target_page_offset)."""
    if (inst & 0x9F000000) != 0x90000000:
        return None
    rd = inst & 0x1F
    immhi = (inst >> 5) & 0x7FFFF
    immlo = (inst >> 29) & 0x3
    imm = (immhi << 2) | immlo
    imm = sign_extend(imm, 21)
    return rd, imm << 12

def encode_adrp(rd: int, pc: int, target: int) -> int:
    """Sinh mã máy ADRP."""
    pc_page = pc & ~0xFFF
    target_page = target & ~0xFFF
    offset = target_page - pc_page
    if offset < -(1 << 32) or offset >= (1 << 32):
        raise ValueError("ADRP offset out of range")
    
    imm = (offset >> 12) & 0x1FFFFF
    immlo = imm & 0x3
    immhi = (imm >> 2) & 0x7FFFF
    
    inst = 0x90000000
    inst |= (immlo << 29)
    inst |= (immhi << 5)
    inst |= (rd & 0x1F)
    return inst

def decode_add_imm(inst: int) -> tuple[int, int, int] | None:
    """Trả về (Rd, Rn, imm12)."""
    if (inst & 0xFFC00000) == 0x91000000:
        rd = inst & 0x1F
        rn = (inst >> 5) & 0x1F
        imm12 = (inst >> 10) & 0xFFF
        return rd, rn, imm12
    return None

def encode_add_imm(rd: int, rn: int, imm12: int) -> int:
    """Sinh mã máy ADD."""
    inst = 0x91000000
    inst |= (imm12 & 0xFFF) << 10
    inst |= (rn & 0x1F) << 5
    inst |= (rd & 0x1F)
    return inst
