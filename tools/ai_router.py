#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bộ định tuyến AI an toàn cho Termux.

Mục đích:
  - Thử gọi Gemini trước.
  - Nếu Gemini bị bộ lọc chặn, hết hạn mức hoặc gặp lỗi kỹ thuật,
    tự động chuyển câu hỏi sang DeepSeek, sau đó OpenRouter nếu có cấu hình.

Giới hạn:
  - Không sửa, không ẩn, không đánh lừa bộ lọc của bất kỳ nhà cung cấp nào.
  - Chỉ chuyển mô hình/nhà cung cấp khác cho cùng câu hỏi.

Cách dùng:
  python3 tools/ai_router.py "Câu hỏi cần xử lý"
  echo "Câu hỏi" | python3 tools/ai_router.py --stdin
  python3 tools/ai_router.py --json "Câu hỏi"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

try:
    import requests
except Exception as exc:  # pragma: no cover
    print("Thiếu thư viện `requests`. Cài bằng: pip install requests", file=sys.stderr)
    raise SystemExit(2) from exc


GEMINI_BASE = os.getenv(
    "GEMINI_API_BASE",
    "https://generativelanguage.googleapis.com",
).rstrip("/")

DEEPSEEK_BASE = os.getenv(
    "DEEPSEEK_API_BASE",
    "https://api.deepseek.com",
).rstrip("/")

OPENROUTER_BASE = os.getenv(
    "OPENROUTER_API_BASE",
    "https://openrouter.ai/api/v1",
).rstrip("/")

TIMEOUT = int(os.getenv("AI_ROUTER_TIMEOUT", "120"))
RETRIES = int(os.getenv("AI_ROUTER_RETRIES", "2"))


def _clean_model_name(model: str) -> str:
    model = (model or "").strip()
    if model.startswith("models/"):
        model = model[len("models/"):]
    if ":generateContent" in model:
        model = model.split(":generateContent", 1)[0]
    return model.rstrip("/")


def _is_filter_block(text: str) -> bool:
    hay = (
        "blocked by",
        "blockreason",
        "promptfeedback",
        "safety",
        "prohibited",
        "filters",
        "recitation",
    )
    low = (text or "").lower()
    return any(key in low for key in hay)


def _extract_gemini_text(data: dict) -> str:
    parts = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [])
    )
    return "".join(part.get("text", "") for part in parts if "text" in part)


def call_gemini(prompt: str, model: str, api_key: str) -> dict:
    model = _clean_model_name(model)
    url = f"{GEMINI_BASE}/v1beta/models/{model}:generateContent"
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
        },
    }
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }

    last_error = "Gemini không phản hồi."
    for attempt in range(1, RETRIES + 1):
        try:
            resp = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=TIMEOUT,
            )
        except Exception as exc:
            last_error = f"Lỗi mạng khi gọi Gemini: {exc}"
            if attempt >= RETRIES:
                break
            time.sleep(min(10, 2 * attempt))
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
                text = _extract_gemini_text(data)
                if not text.strip():
                    return {
                        "ok": False,
                        "provider": "gemini",
                        "error": "Gemini trả kết quả rỗng.",
                    }
                return {
                    "ok": True,
                    "provider": "gemini",
                    "model": model,
                    "text": text.strip(),
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "provider": "gemini",
                    "error": f"Không đọc được phản hồi Gemini: {exc}",
                }

        body = resp.text
        try:
            body = json.dumps(resp.json(), ensure_ascii=False)
        except Exception:
            pass

        if resp.status_code in (400, 401, 403) and _is_filter_block(body):
            return {
                "ok": False,
                "provider": "gemini",
                "error": "Gemini bị chặn bởi bộ lọc hoặc quyền truy cập.",
                "detail": body[:1200],
                "kind": "filter_or_permission",
            }

        if resp.status_code in (408, 429, 500, 502, 503, 504):
            last_error = f"Gemini HTTP {resp.status_code}: {body[:600]}"
            if attempt >= RETRIES:
                break
            time.sleep(min(10, 2 * attempt))
            continue

        return {
            "ok": False,
            "provider": "gemini",
            "error": f"Gemini HTTP {resp.status_code}",
            "detail": body[:1200],
        }

    return {
        "ok": False,
        "provider": "gemini",
        "error": last_error,
    }


def call_deepseek(prompt: str, model: str, api_key: str) -> dict:
    model = model or "deepseek-chat"
    url = f"{DEEPSEEK_BASE}/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=TIMEOUT,
        )
    except Exception as exc:
        return {
            "ok": False,
            "provider": "deepseek",
            "error": f"Lỗi mạng khi gọi DeepSeek: {exc}",
        }

    if resp.status_code != 200:
        return {
            "ok": False,
            "provider": "deepseek",
            "error": f"DeepSeek HTTP {resp.status_code}",
            "detail": resp.text[:1200],
        }

    try:
        text = resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return {
            "ok": False,
            "provider": "deepseek",
            "error": f"Không đọc được phản hồi DeepSeek: {exc}",
        }

    return {
        "ok": bool(text),
        "provider": "deepseek",
        "model": model,
        "text": text,
    }


def call_openrouter(prompt: str, model: str, api_key: str) -> dict:
    if not api_key or not model:
        return {
            "ok": False,
            "provider": "openrouter",
            "error": "Chưa cấu hình OPENROUTER_API_KEY và model OpenRouter.",
        }

    url = f"{OPENROUTER_BASE}/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "patchx-ai-router",
    }
    try:
        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=TIMEOUT,
        )
    except Exception as exc:
        return {
            "ok": False,
            "provider": "openrouter",
            "error": f"Lỗi mạng khi gọi OpenRouter: {exc}",
        }

    if resp.status_code != 200:
        return {
            "ok": False,
            "provider": "openrouter",
            "error": f"OpenRouter HTTP {resp.status_code}",
            "detail": resp.text[:1200],
        }

    try:
        text = resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return {
            "ok": False,
            "provider": "openrouter",
            "error": f"Không đọc được phản hồi OpenRouter: {exc}",
        }

    return {
        "ok": bool(text),
        "provider": "openrouter",
        "model": model,
        "text": text,
    }


def _read_prompt(args: argparse.Namespace) -> str:
    if args.stdin:
        return sys.stdin.read().strip()
    if args.prompt:
        return " ".join(args.prompt).strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Định tuyến câu hỏi qua Gemini, DeepSeek, OpenRouter."
    )
    parser.add_argument("prompt", nargs="*", help="Câu hỏi cần gửi")
    parser.add_argument("--stdin", action="store_true", help="Đọc câu hỏi từ stdin")
    parser.add_argument("--model", default=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
                        help="Model Gemini (mặc định đọc GEMINI_MODEL)")
    parser.add_argument("--deepseek-model", default=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
                        help="Model DeepSeek")
    parser.add_argument("--openrouter-model", default=os.getenv("OPENROUTER_MODEL", ""),
                        help="Model OpenRouter")
    parser.add_argument("--json", action="store_true", help="Xuất kết quả dạng JSON")
    args = parser.parse_args(argv)

    prompt = _read_prompt(args)
    if not prompt:
        parser.print_help()
        return 1

    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_GENERATIVE_AI_API_KEY")
    deepseek_key = os.getenv("DEEPSEEK_API_KEY")
    openrouter_key = os.getenv("OPENROUTER_API_KEY")

    results: list[dict] = []

    if gemini_key:
        gemini_result = call_gemini(prompt, args.model, gemini_key)
        results.append(gemini_result)
        if gemini_result.get("ok"):
            return _emit(gemini_result, args.json)
    else:
        results.append({
            "ok": False,
            "provider": "gemini",
            "error": "Chưa có GEMINI_API_KEY.",
        })

    if deepseek_key:
        deepseek_result = call_deepseek(prompt, args.deepseek_model, deepseek_key)
        results.append(deepseek_result)
        if deepseek_result.get("ok"):
            return _emit(deepseek_result, args.json)

    if openrouter_key:
        openrouter_result = call_openrouter(prompt, args.openrouter_model, openrouter_key)
        results.append(openrouter_result)
        if openrouter_result.get("ok"):
            return _emit(openrouter_result, args.json)

    return _emit_failure(results, args.json)


def _emit(result: dict, as_json: bool) -> int:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result.get("text", ""))
    return 0


def _emit_failure(results: list[dict], as_json: bool) -> int:
    payload = {
        "ok": False,
        "provider": "all",
        "error": "Không có nhà cung cấp nào trả lời được.",
        "attempts": results,
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(payload["error"], file=sys.stderr)
        for item in results:
            print(f"[{item.get('provider')}] {item.get('error')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
