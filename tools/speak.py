#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, re, shutil, subprocess

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
    tts = shutil.which('termux-tts-speak')
    if tts:
        try:
            subprocess.run([tts, '-l', lang, '-r', str(rate), cleaned], timeout=3)
        except Exception:
            pass

if __name__ == '__main__':
    msg = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else sys.stdin.read()
    speak(msg)
