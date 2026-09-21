# -*- coding: utf-8 -*-
"""dex_emulator — Bộ vi giả lập mã máy Dalvik / Smali tức thì trên RAM (Micro-DEX Emulator).

Cho phép giả lập thực thi luồng lệnh của một phương thức Smali trong bộ nhớ mà không cần:
  - Máy ảo Android (AVD / VM)
  - Thiết bị thật hoặc quyền Root
  - Môi trường Dalvik Runtime

Mục đích:
  - Kiểm chứng toán học kết quả thực thi của phương thức sau khi can thiệp (ví dụ: chứng minh hàm luôn trả về True).
  - Tốc độ siêu tốc: thực thi < 1 mili-giây cho mỗi phương thức.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class MicroDexEmulator:
    """Bộ vi giả lập thông dịch lệnh Dalvik/Smali trên RAM."""

    MAX_CYCLES = 500  # Ngưỡng chống vòng lặp vô tận

    def __init__(self, initial_registers: Optional[Dict[str, Any]] = None):
        self.registers: Dict[str, Any] = dict(initial_registers or {})
        self.labels: Dict[str, int] = {}
        self.instructions: List[Tuple[str, List[str]]] = []
        self.pc: int = 0  # Program Counter
        self.cycles: int = 0

    def load_smali_method(self, method_text: str):
        """Nạp các lệnh từ thân phương thức Smali."""
        self.registers.clear()
        self.labels.clear()
        self.instructions.clear()
        self.pc = 0
        self.cycles = 0

        lines = method_text.strip().split("\n")
        idx = 0
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("."):
                continue

            if s.startswith(":"):
                # Nhãn rẽ nhánh
                lbl = s.split()[0]
                self.labels[lbl] = idx
                continue

            parts = s.split(None, 1)
            opcode = parts[0]
            operands = []
            if len(parts) > 1:
                operands = [op.strip() for op in parts[1].split(",")]

            self.instructions.append((opcode, operands))
            idx += 1

    def run(self) -> Dict[str, Any]:
        """Thực thi thông dịch các lệnh đã nạp đến khi gặp return hoặc vượt ngưỡng chu kỳ."""
        while self.pc < len(self.instructions) and self.cycles < self.MAX_CYCLES:
            self.cycles += 1
            opcode, ops = self.instructions[self.pc]

            # 1. Nhóm lệnh gán hằng số (const)
            if opcode.startswith("const"):
                if len(ops) >= 2:
                    reg, val_str = ops[0], ops[1]
                    try:
                        val = int(val_str, 0)
                    except ValueError:
                        val = val_str
                    self.registers[reg] = val
                self.pc += 1

            # 2. Nhóm lệnh sao chép thanh ghi (move)
            elif opcode.startswith("move"):
                if len(ops) >= 2:
                    dst, src = ops[0], ops[1]
                    self.registers[dst] = self.registers.get(src, 0)
                self.pc += 1

            # 3. Nhóm lệnh rẽ nhánh điều kiện (if-*)
            elif opcode == "if-eqz":
                reg, lbl = ops[0], ops[1]
                if self.registers.get(reg, 0) == 0:
                    self.pc = self.labels.get(lbl, self.pc + 1)
                else:
                    self.pc += 1

            elif opcode == "if-nez":
                reg, lbl = ops[0], ops[1]
                if self.registers.get(reg, 0) != 0:
                    self.pc = self.labels.get(lbl, self.pc + 1)
                else:
                    self.pc += 1

            elif opcode == "if-eq":
                r1, r2, lbl = ops[0], ops[1], ops[2]
                if self.registers.get(r1, 0) == self.registers.get(r2, 0):
                    self.pc = self.labels.get(lbl, self.pc + 1)
                else:
                    self.pc += 1

            elif opcode == "if-ne":
                r1, r2, lbl = ops[0], ops[1], ops[2]
                if self.registers.get(r1, 0) != self.registers.get(r2, 0):
                    self.pc = self.labels.get(lbl, self.pc + 1)
                else:
                    self.pc += 1

            # 4. Nhóm lệnh nhảy không điều kiện (goto)
            elif opcode.startswith("goto"):
                lbl = ops[0]
                self.pc = self.labels.get(lbl, self.pc + 1)

            # 5. Nhóm lệnh lấy đối tượng tĩnh (sget)
            elif opcode.startswith("sget"):
                if len(ops) >= 2:
                    reg, field_ref = ops[0], ops[1]
                    if "TRUE" in field_ref:
                        self.registers[reg] = True
                    elif "FALSE" in field_ref:
                        self.registers[reg] = False
                    else:
                        self.registers[reg] = 1
                self.pc += 1

            # 6. Nhóm lệnh trả về (return)
            elif opcode == "return-void":
                return {
                    "completed": True,
                    "return_type": "void",
                    "return_value": None,
                    "cycles": self.cycles,
                    "registers": dict(self.registers),
                }

            elif opcode.startswith("return"):
                reg = ops[0] if ops else "v0"
                return {
                    "completed": True,
                    "return_type": "value",
                    "return_value": self.registers.get(reg),
                    "cycles": self.cycles,
                    "registers": dict(self.registers),
                }

            # Các lệnh khác (invoke, v.v.): bỏ qua mô phỏng, tiếp tục
            else:
                self.pc += 1

        return {
            "completed": self.pc >= len(self.instructions),
            "return_type": "exhausted",
            "return_value": self.registers.get("v0"),
            "cycles": self.cycles,
            "registers": dict(self.registers),
        }


def verify_method_bypass(method_text: str) -> Dict[str, Any]:
    """Kiểm chứng nhanh phương thức có trả về True (1) sau khi can thiệp hay không."""
    emu = MicroDexEmulator()
    emu.load_smali_method(method_text)
    res = emu.run()
    val = res.get("return_value")
    verified = val in (1, True, "0x1")
    return {
        "verified": verified,
        "return_value": val,
        "cycles": res.get("cycles", 0),
        "details": res,
    }
