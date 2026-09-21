# -*- coding: utf-8 -*-
"""micro_lifter_cfg — Kết hợp thuật toán CFG Unflatten vào Binary Lifter."""

import struct
from typing import List, Dict, Optional

class IRInstruction:
    def __init__(self, opcode: str, dest: str, src1: str, src2: Optional[str] = None):
        self.opcode = opcode
        self.dest = dest
        self.src1 = src1
        self.src2 = src2
        self.target_block = None # Dùng cho lệnh rẽ nhánh (Branch)

    def __str__(self):
        if self.opcode == 'B':
            return f"B -> {self.target_block}"
        if self.src2 is not None:
            return f"{self.opcode} {self.dest}, {self.src1}, {self.src2}"
        return f"{self.opcode} {self.dest}, {self.src1}"

class BasicBlock:
    def __init__(self, name: str):
        self.name = name
        self.instructions: List[IRInstruction] = []
        self.successors: List['BasicBlock'] = []
        self.offset = 0 # Sẽ được tính lại ở pha Recompile

    def add_inst(self, inst: IRInstruction):
        self.instructions.append(inst)

class CFGRecompiler:
    def __init__(self):
        self.blocks: List[BasicBlock] = []

    def add_block(self, block: BasicBlock):
        self.blocks.append(block)

    def recompile_arm64(self) -> bytes:
        """Pha tái biên dịch: Tuyến tính hóa CFG và vá lại Offset rẽ nhánh."""
        output = bytearray()
        
        # 1. Cấp phát Offset (Tuyến tính hóa các Basic Block)
        current_offset = 0
        for block in self.blocks:
            block.offset = current_offset
            # Tạm tính kích thước (ARM64 = 4 bytes/lệnh)
            current_offset += len(block.instructions) * 4
            
        # 2. Sinh mã máy ARM64
        for block in self.blocks:
            for ir in block.instructions:
                if ir.opcode == 'ADD':
                    # ADD Wd, Wn, Wm (0x0b000000)
                    rd = int(ir.dest[1:])
                    rn = int(ir.src1[1:])
                    rm = int(ir.src2[1:])
                    inst = 0x0B000000 | (rm << 16) | (rn << 5) | rd
                    output.extend(struct.pack('<I', inst))
                    
                elif ir.opcode == 'MOV':
                    # MOV Wd, Wn (Sử dụng ORR Wd, WZR, Wn: 0x2a0003e0)
                    rd = int(ir.dest[1:])
                    rn = int(ir.src1[1:])
                    inst = 0x2A0003E0 | (rn << 16) | rd
                    output.extend(struct.pack('<I', inst))
                    
                elif ir.opcode == 'B':
                    # Tính toán lại khoảng cách an toàn (Nhờ CFG)
                    target_block = next((b for b in self.blocks if b.name == ir.target_block), None)
                    if not target_block:
                        raise ValueError(f"CFG Lỗi: Không tìm thấy Block đích {ir.target_block}")
                        
                    # Offset tính bằng số lệnh (bytes / 4)
                    branch_offset = (target_block.offset - block.offset) // 4
                    # B <label> (0x14000000 | imm26)
                    inst = 0x14000000 | (branch_offset & 0x03FFFFFF)
                    output.extend(struct.pack('<I', inst))
        return output

if __name__ == '__main__':
    print("=== CFG TRANSLATOR: RE-LINKING BRANCHES ===")
    
    # Giả lập 3 khối lệnh đã được Lift từ một file ARM32 bị làm rối
    block_a = BasicBlock("BLOCK_A")
    block_b = BasicBlock("BLOCK_B")
    block_c = BasicBlock("BLOCK_C")
    
    # Phục hồi luồng (CFG) như cách cfg_unflatten.py làm trên Smali
    block_a.successors = [block_c, block_b]
    
    # Khối A: B BLOCK_C (Rẽ nhánh bỏ qua B)
    br_inst = IRInstruction('B', '', '')
    br_inst.target_block = "BLOCK_C"
    block_a.add_inst(br_inst)
    
    # Khối B: Lệnh bình thường
    block_b.add_inst(IRInstruction('ADD', 'R0', 'R1', 'R2'))
    
    # Khối C: Lệnh đích
    block_c.add_inst(IRInstruction('MOV', 'R0', 'R1'))
    
    cfg = CFGRecompiler()
    cfg.add_block(block_a)
    cfg.add_block(block_b)
    cfg.add_block(block_c)
    
    print("[+] CFG Tuyến tính hóa:")
    for b in cfg.blocks:
        print(f"  [{b.name}]")
        for i in b.instructions:
            print(f"    {i}")
            
    compiled_bytes = cfg.recompile_arm64()
    print("\n[+] ARM64 Machine Code (CFG Relinked):")
    for i in range(0, len(compiled_bytes), 4):
        inst_val = struct.unpack('<I', compiled_bytes[i:i+4])[0]
        print(f"  0x{i:04x}: {inst_val:08x}")
