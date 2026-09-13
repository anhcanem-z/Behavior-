#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script thực thi: Tự động reset và bật lại dịch phụ đề + chia sẻ toàn màn hình sau 2m40s"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from patchx_core.auto_session_refresher import main

if __name__ == "__main__":
    main()
