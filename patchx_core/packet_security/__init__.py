# -*- coding: utf-8 -*-
"""Gói công cụ an ninh mạng cho Toolkit patchx.

Gồm bốn mảnh phối hợp:
- PacketGuard: bảo vệ gói tin (mã hóa AEAD + chống phát lại).
- PacketForge: tiêm, chặn, sửa và làm nhiễu gói tin.
- PacketMiddleware: SDK phiên an toàn kiểu cắm-vào-dùng-ngay.
- PacketArena: đấu trường mô phỏng đối kháng Red Team / Blue Team.
"""

from .packet_guard import (
    AEADEngine,
    AntiReplayFilter,
    ChaCha20,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC_BYTES,
    PacketGuardClient,
    PacketGuardServer,
)
from .packet_forge import (
    PacketFuzzer,
    PacketInjector,
    PacketProxy,
    format_hexdump,
)
from .packet_middleware import (
    SecureClient,
    SecureServer,
    SecureSession,
)
from .packet_arena import LiveCombatArena

__all__ = [
    "AEADEngine",
    "AntiReplayFilter",
    "ChaCha20",
    "HEADER_FORMAT",
    "HEADER_SIZE",
    "MAGIC_BYTES",
    "PacketGuardClient",
    "PacketGuardServer",
    "PacketFuzzer",
    "PacketInjector",
    "PacketProxy",
    "format_hexdump",
    "SecureClient",
    "SecureServer",
    "SecureSession",
    "LiveCombatArena",
]
