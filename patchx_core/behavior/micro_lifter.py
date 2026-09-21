# -*- coding: utf-8 -*-
"""micro_lifter — Proof of Concept: Static Binary Translation (ARM32 -> ARM64)."""

class IRInstruction:
    def __init__(self, opcode, dest, src1, src2=None):
        self.opcode = opcode
        self.dest = dest
        self.src1 = src1
        self.src2 = src2

    def __str__(self):
        if self.src2 is not None:
            return f"{self.opcode} {self.dest}, {self.src1}, {self.src2}"
        return f"{self.opcode} {self.dest}, {self.src1}"

def decode_arm32_add(inst: int):
    """Decode a simple ARM32 ADD instruction.
    Example: e0810002 -> add r0, r1, r2
    """
    if (inst & 0x0FE00000) == 0x00800000:
        rn = (inst >> 16) & 0xF
        rd = (inst >> 12) & 0xF
        rm = inst & 0xF
        return IRInstruction('ADD', f'R{rd}', f'R{rn}', f'R{rm}')
    return None

def recompile_to_arm64(ir: IRInstruction) -> int:
    """Compile IR back to AArch64 machine code."""
    if ir.opcode == 'ADD':
        rd = int(ir.dest[1:])
        rn = int(ir.src1[1:])
        rm = int(ir.src2[1:])
        
        inst = 0x0B000000
        inst |= (rm & 0x1F) << 16
        inst |= (rn & 0x1F) << 5
        inst |= (rd & 0x1F)
        return inst
    raise NotImplementedError(f"Unsupported IR: {ir.opcode}")

if __name__ == '__main__':
    print("=== BỘ DỊCH MÃ MÁY ĐA KIẾN TRÚC (Micro Lifter) ===")
    arm32 = 0xe0810002
    print(f"[+] 1. Mã máy ARM32 thô        : {hex(arm32)} (Lệnh gốc: ADD R0, R1, R2)")
    
    ir = decode_arm32_add(arm32)
    print(f"[+] 2. Nâng lên IR (Trung gian): {ir}")
    
    arm64 = recompile_to_arm64(ir)
    print(f"[+] 3. Tái biên dịch ra ARM64  : {hex(arm64)} (Lệnh mới: ADD W0, W1, W2)")
