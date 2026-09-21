# -*- coding: utf-8 -*-
"""elf_expander — Mở rộng phân vùng ELF (Section Appending)."""

import struct
from pathlib import Path

def extend_elf_with_string(file_path: str | Path, new_string_bytes: bytes) -> int:
    with open(file_path, 'r+b') as f:
        e_ident = f.read(16)
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHLQQQLHHHHHH', f.read(48))
        
        f.seek(e_phoff)
        last_load_offset = 0
        last_load_vaddr = 0
        last_load_filesz = 0
        last_load_memsz = 0
        last_load_ph_pos = 0
        
        for i in range(e_phnum):
            ph_pos = f.tell()
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<LLQQQQQQ', f.read(e_phentsize))
            if p_type == 1: # PT_LOAD
                if p_vaddr > last_load_vaddr:
                    last_load_vaddr = p_vaddr
                    last_load_offset = p_offset
                    last_load_filesz = p_filesz
                    last_load_memsz = p_memsz
                    last_load_ph_pos = ph_pos
                    
        bss_size = last_load_memsz - last_load_filesz
        
        target_offset = last_load_offset + last_load_filesz
        f.seek(target_offset)
        f.write(b'\x00' * bss_size)
        
        string_rva = last_load_vaddr + last_load_memsz
        f.write(new_string_bytes + b'\x00')
        
        # We don't truncate or overwrite ELF headers. We just appended the required bytes over whatever was there.
        
        new_filesz = last_load_memsz + len(new_string_bytes) + 1
        new_memsz = new_filesz
        
        f.seek(last_load_ph_pos)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<LLQQQQQQ', f.read(e_phentsize))
        
        f.seek(last_load_ph_pos)
        f.write(struct.pack('<LLQQQQQQ', p_type, p_flags, p_offset, p_vaddr, p_paddr, new_filesz, new_memsz, p_align))
        
        return string_rva
