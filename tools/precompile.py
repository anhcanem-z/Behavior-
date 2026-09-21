# -*- coding: utf-8 -*-
"""tools/precompile.py — Tiền biên dịch toàn bộ mã nguồn Python thành mã máy bytecode tối ưu (.pyc).

Tận dụng 8 nhân CPU của hệ thống để biên dịch song song với mức tối ưu hóa cao nhất,
giúp tăng tốc độ khởi động và thực thi toàn bộ hệ thống Toolkit.
"""

import compileall
import os
import sys
import time


def precompile_toolkit(root_dir=None, workers=None, opt_level=1):
    """Tiền biên dịch toàn bộ tệp .py trong toolkit thành .pyc tối ưu."""
    root = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    workers = workers or os.cpu_count() or 8
    print(f"[precompile] Bắt đầu tiền biên dịch mã máy Python bytecode trên {workers} nhân CPU...")
    start_time = time.perf_counter()

    import re
    rx_pattern = re.compile(r"/(\.git|\.cache|venv|outputs/tu-sinh|outputs/backup)/")

    success = compileall.compile_dir(
        root,
        maxlevels=10,
        ddir=None,
        force=True,
        rx=rx_pattern,
        quiet=1,
        workers=workers,
        optimize=opt_level,
    )

    elapsed = (time.perf_counter() - start_time) * 1000
    status_str = "THÀNH CÔNG" if success else "CÓ CẢNH BÁO"
    print(f"[precompile] {status_str}: Hoàn tất trong {elapsed:.2f} ms (mức tối ưu -O{opt_level}, {workers} luồng song song).")
    return success, elapsed


if __name__ == "__main__":
    precompile_toolkit()
