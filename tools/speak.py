#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phat am bao cao bang giong noi tieng Viet.

YEU CAU CUA USER (2026-09-20 22:52): thong bao giong noi phai la TIENG VIET CO DAU day du.
Ly do: dong TTS doc chu khong dau sai het thanh dieu (vi du "muc tieu" doc thanh "muc tiu"
/ "muc tiêu" khong ro nghia). Vi vay khi lang bat dau bang 'vi', neu noi dung dai ma KHONG
co dau, cong cu se CANH BAO ra stderr de nguoi viet biet ma sua — day la co che chong lap
lai dung loi da xay ra trong phien 01a0bf3b.
"""
import sys, re, shutil, subprocess, unicodedata


def co_dau_tieng_viet(text: str) -> bool:
    """True neu chuoi co dau (nguyen am co dau hoac dau thanh)."""
    if any(c in text for c in "ăâđêôơưĂÂĐÊÔƠƯ"):
        return True
    return any(unicodedata.category(c) == "Mn"
               for c in unicodedata.normalize("NFD", text))

def clean_text(text: str) -> str:
    text = re.sub(r'', '', text, flags=re.DOTALL)
    text = re.sub(r'[`#*_\-\|~]', ' ', text)
    text = re.sub(r'\[(.*?)\]\(.*?\)', r'', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def speak(text: str, rate: float = 1.0, lang: str = 'vi'):
    cleaned = clean_text(text)
    if not cleaned:
        return
    if lang.startswith('vi') and len(cleaned) >= 25 and not co_dau_tieng_viet(cleaned):
        sys.stderr.write(
            "CANH BAO: noi dung phat am THIEU DAU tieng Viet (%d ky tu). "
            "Yeu cau cua User 2026-09-20: thong bao giong noi phai co dau day du.\n"
            % len(cleaned))
    tts = shutil.which('termux-tts-speak')
    if tts:
        subprocess.run([tts, '-l', lang, '-r', str(rate), cleaned])
    else:
        sys.stderr.write("CANH BAO: khong thay termux-tts-speak — khong phat duoc.\n")

if __name__ == '__main__':
    msg = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    speak(msg)
