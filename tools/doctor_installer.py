#!/data/data/com.termux/files/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cổng gọi nhanh: install-deps -> patchx_toolkit.py install-deps."""
import os, sys
BASE = os.path.dirname(os.path.realpath(__file__))
TOOL = os.path.join(BASE, "patchx_toolkit.py")
os.execv(sys.executable, [sys.executable, TOOL, "install-deps"] + sys.argv[1:])
