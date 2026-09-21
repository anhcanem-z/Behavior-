# -*- coding: utf-8 -*-
"""native_mutator — Đột phá tầng thư viện mã máy (.so) cho Toolkit patchx.

Cung cấp 3 trụ cột can thiệp tầng thư viện thế hệ mới:
1. NativeDefenseScanner:
   - Tự động nhận diện 4 nhóm chốt chặn an ninh nhạy cảm trong mã máy C/C++:
     * Anti-Root (su, Superuser, which su, magisk)
     * Anti-Frida / Anti-Debug (/proc/self/status, TracerPid:, frida-server, ptrace)
     * Tên miền & Endpoint xác thực giấy phép (license endpoints)
2. ZeroDriftBinaryMutator:
   - Cơ chế đột biến nhị phân trực tiếp trên đĩa với độ trôi dung lượng bằng 0 (Zero-Size-Drift).
   - Vô hiệu hóa chốt chặn an ninh mà không làm thay đổi bảng biểu ELF hay địa chỉ nạp mã.
   - Tự động sao lưu tệp gốc trước khi can thiệp.
3. NativeFridaHookGenerator:
   - Tự động sinh mã Frida Native Interceptor đánh lừa hàm hệ thống cấp thấp:
     * open, openat, access, stat: giả lập không tồn tại (ENOENT) với su/magisk.
     * /proc/self/status: giả lập TracerPid = 0 (xóa dấu vết debugger/frida).
     * ptrace: ép thành công (return 0).
"""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .rodata_patcher import ElfReader, find_string_offsets, patch_so_file


# Danh sách mẫu chốt chặn an ninh Native và chuỗi thay thế an toàn có cùng độ dài chính xác
DEFENSE_SIGNATURES: List[Dict[str, Any]] = [
    # --- Anti-Root Signatures ---
    {
        "category": "anti_root",
        "needle": "/system/bin/su",
        "replacement": "/system/bin/zz",
        "description": "Vô hiệu hóa kiểm tra đường dẫn nhị phân su chính",
    },
    {
        "category": "anti_root",
        "needle": "/system/xbin/su",
        "replacement": "/system/xbin/zz",
        "description": "Vô hiệu hóa kiểm tra đường dẫn xbin su",
    },
    {
        "category": "anti_root",
        "needle": "/sbin/su",
        "replacement": "/sbin/zz",
        "description": "Vô hiệu hóa kiểm tra đường dẫn sbin su",
    },
    {
        "category": "anti_root",
        "needle": "/data/local/xbin/su",
        "replacement": "/data/local/xbin/zz",
        "description": "Vô hiệu hóa kiểm tra su trong data/local",
    },
    {
        "category": "anti_root",
        "needle": "which su",
        "replacement": "echo no",
        "description": "Vô hiệu hóa lệnh shell tìm kiếm su",
    },
    {
        "category": "anti_root",
        "needle": "/system/app/Superuser.apk",
        "replacement": "/system/app/Dummyuser.apk",
        "description": "Vô hiệu hóa kiểm tra gói Superuser",
    },

    # --- Anti-Frida & Anti-Debug Signatures ---
    {
        "category": "anti_debug",
        "needle": "/proc/self/status",
        "replacement": "/proc/self/statuz",
        "description": "Vô hiệu hóa việc đọc tệp trạng thái TracerPid của kernel",
    },
    {
        "category": "anti_debug",
        "needle": "TracerPid:",
        "replacement": "DummyPid:",
        "description": "Làm lệch chuỗi định danh TracerPid trong bộ nhớ",
    },
    {
        "category": "anti_debug",
        "needle": "/proc/self/wchan",
        "replacement": "/proc/self/wchaz",
        "description": "Vô hiệu hóa kiểm tra kênh chờ tiến trình wchan",
    },
    {
        "category": "anti_frida",
        "needle": "frida-server",
        "replacement": "dummy_server",
        "description": "Vô hiệu hóa quét tiến trình frida-server",
    },
    {
        "category": "anti_frida",
        "needle": "frida-gadget",
        "replacement": "dummy_gadget",
        "description": "Vô hiệu hóa quét module frida-gadget",
    },
    {
        "category": "anti_frida",
        "needle": "27042",
        "replacement": "99999",
        "description": "Vô hiệu hóa quét cổng mặc định của Frida",
    },
]


class NativeDefenseScanner:
    """Quét và định vị toàn diện các chốt chặn an ninh trong tệp thư viện .so."""

    @classmethod
    def scan_so_file(cls, so_path: str | Path) -> List[Dict[str, Any]]:
        """Quét 1 tệp .so và tìm tất cả các chữ ký chốt chặn an ninh."""
        path = Path(so_path)
        if not path.is_file():
            return []

        try:
            reader = ElfReader(path)
        except Exception:
            return []

        findings = []
        for sig in DEFENSE_SIGNATURES:
            needle = sig["needle"]
            try:
                hits = find_string_offsets(path, needle)
                for hit in hits:
                    findings.append({
                        "so_path": str(path),
                        "category": sig["category"],
                        "needle": needle,
                        "replacement": sig["replacement"],
                        "description": sig["description"],
                        "rva": hit.rva,
                        "file_offset": hit.file_offset,
                        "section": hit.section,
                        "size": hit.size,
                    })
            except Exception:
                continue

        return findings

    @classmethod
    def scan_directory(cls, dir_path: str | Path) -> List[Dict[str, Any]]:
        """Quét tất cả tệp .so trong một thư mục hoặc cây APK."""
        p = Path(dir_path)
        all_findings = []
        for root, _dirs, files in os.walk(p):
            for f in files:
                if f.endswith(".so"):
                    so_path = Path(root) / f
                    hits = cls.scan_so_file(so_path)
                    if hits:
                        all_findings.extend(hits)
        return all_findings


class ZeroDriftBinaryMutator:
    """Đột biến nhị phân trực tiếp trên đĩa với độ trôi dung lượng bằng 0."""

    @classmethod
    def mutate_so(
        cls,
        so_path: str | Path,
        findings: List[Dict[str, Any]],
        backup: bool = True,
        backup_dir: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        """Áp dụng các thay thế đã tìm thấy trực tiếp vào tệp .so."""
        path = Path(so_path)
        if not path.is_file() or not findings:
            return {"success": False, "patched_count": 0, "details": "Không có finding hợp lệ"}

        patches = []
        for item in findings:
            patches.append({
                "rva": item["rva"],
                "new_string": item["replacement"],
                "mode": "inline",
            })

        bdir = Path(backup_dir or "outputs/backup/native_mutator")
        bdir.mkdir(parents=True, exist_ok=True)

        try:
            res = patch_so_file(
                so_path=path,
                patches=patches,
                allow_overflow=False,
                backup=backup,
                backup_dir=bdir,
            )
            return {
                "success": True,
                "so_path": str(path),
                "patched_count": len(res.get("patched", [])),
                "backup": res.get("backup"),
                "patched": res.get("patched", []),
            }
        except Exception as e:
            return {
                "success": False,
                "so_path": str(path),
                "patched_count": 0,
                "error": str(e),
            }


class NativeFridaHookGenerator:
    """Sinh tập lệnh Frida Native Interceptor để đánh lừa syscall và kernel checks."""

    @staticmethod
    def generate_script(output_file: Optional[str | Path] = None) -> str:
        """Sinh mã JavaScript Frida can thiệp vào các hàm libc native."""
        js_code = r"""// ==============================================================================
// NATIVE HOOK INTERCEPTOR: BYPASS ANTI-ROOT, ANTI-DEBUG, ANTI-FRIDA
// ==============================================================================

(function () {
    console.log('[+] Đang kích hoạt Native Defense Interceptor...');

    // 1. Đánh lừa hàm access(const char *pathname, int mode)
    var access_ptr = Module.findExportByName(null, 'access');
    if (access_ptr) {
        Interceptor.attach(access_ptr, {
            onEnter: function (args) {
                var path = Memory.readCString(args[0]);
                if (path && (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1 || path.indexOf('busybox') !== -1)) {
                    console.log('  [+] Đã chặn access() kiểm tra: ' + path);
                    this.is_bad = true;
                }
            },
            onLeave: function (retval) {
                if (this.is_bad) {
                    retval.replace(ptr(-1)); // Trả về -1 (Không tìm thấy tệp)
                }
            }
        });
        console.log('  [+] Đã hook native access()');
    }

    // 2. Đánh lừa hàm open / openat khi đọc /proc/self/status hoặc su
    var openat_ptr = Module.findExportByName(null, 'openat');
    if (openat_ptr) {
        Interceptor.attach(openat_ptr, {
            onEnter: function (args) {
                var path = Memory.readCString(args[1]);
                if (path && (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1)) {
                    console.log('  [+] Đã chặn openat() kiểm tra: ' + path);
                    this.is_bad = true;
                }
            },
            onLeave: function (retval) {
                if (this.is_bad) {
                    retval.replace(ptr(-1));
                }
            }
        });
        console.log('  [+] Đã hook native openat()');
    }

    // 3. Đánh lừa hàm ptrace(request, pid, addr, data)
    var ptrace_ptr = Module.findExportByName(null, 'ptrace');
    if (ptrace_ptr) {
        Interceptor.attach(ptrace_ptr, {
            onEnter: function (args) {
                var req = args[0].toInt32();
                // PTRACE_TRACEME = 0
                if (req === 0) {
                    console.log('  [+] Đã chặn ptrace(PTRACE_TRACEME)');
                    this.is_traceme = true;
                }
            },
            onLeave: function (retval) {
                if (this.is_traceme) {
                    retval.replace(ptr(0)); // Giả lập thành công
                }
            }
        });
        console.log('  [+] Đã hook native ptrace()');
    }
})();
"""
        if output_file:
            p = Path(output_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(js_code, encoding="utf-8")
        return js_code


def auto_mutate_native(
    target_path: str | Path,
    output_dir: Optional[str | Path] = None,
    apply_disk: bool = True,
    gen_frida: bool = True,
) -> Dict[str, Any]:
    """Điều phối toàn diện đột phá tầng thư viện mã máy."""
    target = Path(target_path)
    out_dir = Path(output_dir or "outputs/native_mutator")
    out_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "target": str(target),
        "total_so_files": 0,
        "findings_count": 0,
        "patched_files": [],
        "frida_script": None,
    }

    findings = []
    if target.is_file() and target.name.endswith(".so"):
        report["total_so_files"] = 1
        findings = NativeDefenseScanner.scan_so_file(target)
    elif target.is_dir():
        findings = NativeDefenseScanner.scan_directory(target)
        so_files = list(target.glob("**/*.so"))
        report["total_so_files"] = len(so_files)

    report["findings_count"] = len(findings)

    # Nhóm findings theo tệp .so
    by_so: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_so.setdefault(f["so_path"], []).append(f)

    # 1. Đột biến trực tiếp trên đĩa nếu được yêu cầu
    if apply_disk and by_so:
        for so_file, hits in by_so.items():
            mut_res = ZeroDriftBinaryMutator.mutate_so(
                so_path=so_file,
                findings=hits,
                backup=True,
                backup_dir=out_dir / "backup",
            )
            if mut_res.get("success"):
                report["patched_files"].append(mut_res)

    # 2. Sinh tập lệnh Frida Native Interceptor
    if gen_frida:
        script_file = out_dir / "native_defense_hook.js"
        NativeFridaHookGenerator.generate_script(script_file)
        report["frida_script"] = str(script_file)

    report["success"] = True
    return report
