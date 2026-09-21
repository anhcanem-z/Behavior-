# -*- coding: utf-8 -*-
"""advanced_bypass — Công cụ chèn chuỗi và vá XREF tĩnh cho AArch64 (Siêu việt).

Sử dụng ELF Section Appending và ARM64 CFG Relinking để nới rộng chuỗi vô hạn.
"""

import sys
import argparse
import shutil
from pathlib import Path
from ..behavior.elf_expander import extend_elf_with_string
from ..behavior.xref_hunter import hunt_and_patch_multiple_xrefs
from ..behavior.rodata_patcher import find_string_offsets, ElfReader

def main():
    parser = argparse.ArgumentParser(description="Advanced Static Bypass - Chèn chuỗi và vá XREF tĩnh (AArch64).")
    parser.add_argument("so", help="Đường dẫn tới file .so/.elf cần vá")
    parser.add_argument("--old-string", required=True, help="Chuỗi gốc cần thay thế")
    parser.add_argument("--new-string", required=True, help="Chuỗi mới (có thể dài vô hạn)")
    parser.add_argument("--out", required=True, help="Đường dẫn file đầu ra")
    
    args = parser.parse_args()
    
    so_path = Path(args.so)
    out_path = Path(args.out)
    
    if not so_path.exists():
        print(f"Lỗi: Không tìm thấy file {so_path}")
        sys.exit(1)
        
    reader = ElfReader(so_path)
    if not reader.is_aarch64():
        print("Lỗi: Advanced Bypass hiện chỉ hỗ trợ kiến trúc AArch64.")
        sys.exit(1)
        
    print(f"[*] Đang sao chép file gốc ra {out_path}...")
    shutil.copy2(so_path, out_path)
    
    print(f"[*] 1. Tìm kiếm chuỗi gốc '{args.old_string}'...")
    offsets = find_string_offsets(out_path, args.old_string, all_hits=True)
    if not offsets:
        print(f"Không tìm thấy chuỗi '{args.old_string}' trong file.")
        sys.exit(1)
        
    print(f"    -> Tìm thấy {len(offsets)} vị trí (RVAs).")
    
    print(f"[*] 2. Bơm chuỗi mới '{args.new_string}' vào phân vùng ELF...")
    new_str_bytes = args.new_string.encode('utf-8')
    new_rva = extend_elf_with_string(out_path, new_str_bytes)
    print(f"    -> Chuỗi mới đã được cấp phát tại RVA: {hex(new_rva)}")
    
    print(f"[*] 3. Săn tìm XREF và viết lại mã máy ARM64 (CFG Relinking)...")
    rva_map = {off.rva: new_rva for off in offsets}
    counts = hunt_and_patch_multiple_xrefs(out_path, rva_map)
    
    total = sum(counts.values())
    for old, cnt in counts.items():
        if cnt > 0:
            print(f"    - RVA {hex(old)}: Đã vá {cnt} lệnh ADRP/ADD")
            
    if total > 0:
        print(f"\\n[+] THÀNH CÔNG! Đã vá tổng cộng {total} XREFs. File xuất ra tại: {out_path}")
    else:
        print(f"\\n[-] Xong, nhưng KHÔNG tìm thấy lệnh XREF (ADRP/ADD) nào trỏ tới chuỗi gốc. File xuất ra tại: {out_path}")

if __name__ == '__main__':
    main()
