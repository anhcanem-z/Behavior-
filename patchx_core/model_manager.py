# -*- coding: utf-8 -*-
"""Quản lý cấu hình model và ngôn ngữ mục tiêu.

- Lưu cấu hình trong `outputs/config/model_config.json` (tạo thư mục nếu chưa tồn tại).
- Cung cấp hàm `list_models()`, `set_model(model_name, target_lang)`, `get_config()`.
- Các model hiện có: `vosk`, `gemini`, `deepseek`.
- Khi thay đổi, phát âm thông báo qua `tools/speak.py`.
"""
import json
import os
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[2] / "outputs" / "config"
CONFIG_FILE = CONFIG_DIR / "model_config.json"

DEFAULT_CONFIG = {
    "model": "vosk",
    "target_language": "vi"
}

def _ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def load_config() -> dict:
    """Load config, create default if missing."""
    _ensure_config_dir()
    if not CONFIG_FILE.is_file():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # Nếu file bị hỏng, reset về mặc định
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(cfg: dict) -> None:
    """Write config to disk."""
    _ensure_config_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def list_models() -> list:
    """Return danh sách model khả dụng."""
    return ["vosk", "gemini", "deepseek"]

def set_model(model_name: str, target_lang: str | None = None) -> dict:
    """Cập nhật model và/hoặc ngôn ngữ đích.

    Trả về cấu hình mới.
    """
    if model_name not in list_models():
        raise ValueError(f"Model '{model_name}' không được hỗ trợ. Các model: {', '.join(list_models())}")
    cfg = load_config()
    cfg["model"] = model_name
    if target_lang:
        cfg["target_language"] = target_lang
    save_config(cfg)
    # Phát âm thông báo
    from subprocess import run
    msg = f"Đã chuyển model thành {model_name}, ngôn ngữ đích {cfg['target_language']}"
    run(["python3", "tools/speak.py", msg])
    return cfg

def get_config() -> dict:
    """Return current config (model + target language)."""
    return load_config()
