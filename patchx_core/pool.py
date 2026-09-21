# -*- coding: utf-8 -*-
"""Động cơ điều phối đa luồng song song tối ưu hóa cho môi trường Termux / ARM64.

Tận dụng kiến trúc chip đa nhân (8 nhân) để tăng tốc các tác vụ đọc đĩa,
quét cú pháp và phân tích dữ liệu lớn mà không gây quá tải bộ nhớ.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from typing import Any, Callable, Iterable, List, Optional


def get_cpu_cores() -> int:
    """Lấy số lượng nhân CPU khả dụng trên thiết bị."""
    try:
        return os.cpu_count() or 4
    except Exception:
        return 4


def run_parallel(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    max_workers: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> List[Any]:
    """Thực thi một hàm trên danh sách phần tử song song qua luồng công nhân.

    Tham số:
        func: Hàm xử lý cho từng phần tử hoặc từng nhóm phần tử.
        items: Danh sách dữ liệu đầu vào.
        max_workers: Số luồng tối đa (mặc định lấy theo số nhân CPU).
        chunk_size: Kích thước nhóm (nếu muốn gom nhóm để giảm tải điều phối).
    """
    item_list = list(items)
    if not item_list:
        return []

    workers = max_workers or get_cpu_cores()
    # Nếu danh sách quá nhỏ, chạy tuần tự để tiết kiệm chi phí tạo luồng
    if len(item_list) <= 2 or workers <= 1:
        return [func(item) for item in item_list]

    results = []
    if chunk_size and chunk_size > 1:
        # Gom nhóm phần tử
        chunks = [
            item_list[i : i + chunk_size]
            for i in range(0, len(item_list), chunk_size)
        ]
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_chunk = {
                executor.submit(func, chunk): chunk for chunk in chunks
            }
            for future in as_completed(future_to_chunk):
                try:
                    res = future.result()
                    if isinstance(res, list):
                        results.extend(res)
                    else:
                        results.append(res)
                except Exception:
                    pass
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_item = {
                executor.submit(func, item): item for item in item_list
            }
            for future in as_completed(future_to_item):
                try:
                    results.append(future.result())
                except Exception:
                    pass

    return results
