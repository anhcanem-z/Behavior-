# -*- coding: utf-8 -*-
"""Đầu vào dòng lệnh thống nhất cho nhóm công cụ an ninh mạng gói tin."""

import argparse
import sys

from . import packet_arena, packet_forge, packet_guard
from .packet_middleware import SecureClient, SecureServer


def _run_legacy_tool(tool: str, argv: list[str]) -> int:
    """Chạy lại bộ CLI có sẵn của từng công cụ bằng cách hoán đổi sys.argv."""
    old_argv = sys.argv
    sys.argv = ["packet-%s" % tool] + list(argv or [])
    try:
        if tool == "guard":
            return packet_guard.main()
        if tool == "forge":
            return packet_forge.main()
        if tool == "arena":
            return packet_arena.main()
    finally:
        sys.argv = old_argv
    return 2


def _middleware_demo(host: str = "127.0.0.1", port: int = 9999) -> int:
    """Mô phỏng nhanh SDK phiên an toàn để kiểm chứng import và chạy thật."""
    server = SecureServer(host=host, port=port)

    @server.on_intent("PING")
    def _ping(session, params):
        return {"pong": True, "echo": params}

    @server.on_intent("STATUS")
    def _status(session, params):
        return {"server": "PacketMiddleware", "sessions": len(server.sessions)}

    server.start(blocking=False)
    client = SecureClient(host=host, port=port)
    if not client.connect():
        server.stop()
        print("[-] Không kết nối được tới SecureServer.")
        return 1

    response = client.send_intent("PING", {"message": "xin-chao-tu-toolkit"})
    print("[+] Phản hồi SecureClient:", response)
    client.close()
    server.stop()
    return 0


def _parse_middleware_options(tool_args: list[str]) -> tuple[str, int]:
    host = "127.0.0.1"
    port = 9999
    for idx, token in enumerate(tool_args):
        if token == "--host" and idx + 1 < len(tool_args):
            host = tool_args[idx + 1]
        elif token.startswith("--host="):
            host = token.split("=", 1)[1]
        elif token == "--port" and idx + 1 < len(tool_args):
            try:
                port = int(tool_args[idx + 1])
            except ValueError:
                pass
        elif token.startswith("--port="):
            try:
                port = int(token.split("=", 1)[1])
            except ValueError:
                pass
    return host, port


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="patchx packet",
        description=(
            "Bộ công cụ an ninh mạng gói tin cho Toolkit patchx: "
            "guard | forge | arena | middleware"
        ),
    )
    parser.add_argument(
        "tool",
        choices=["guard", "forge", "arena", "middleware"],
        help="Công cụ cần chạy.",
    )
    parser.add_argument(
        "tool_args",
        nargs=argparse.REMAINDER,
        help="Tham số phụ của công cụ đã chọn.",
    )
    args = parser.parse_args(argv)

    if args.tool in {"guard", "forge", "arena"}:
        return _run_legacy_tool(args.tool, args.tool_args)

    host, port = _parse_middleware_options(args.tool_args)
    return _middleware_demo(host=host, port=port)


if __name__ == "__main__":
    sys.exit(main())
