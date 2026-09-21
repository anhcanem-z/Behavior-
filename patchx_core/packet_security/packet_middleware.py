#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketMiddleware - Plug-and-Play Zero-Trust Network SDK
Thư viện Middleware Tích hợp Nhanh cho Ứng dụng Thực tế

Cho phép bảo vệ bất kỳ ứng dụng Socket/Backend nào chỉ với 3 dòng code:
- Tự động bắt tay trao đổi khóa tạm thời (Ephemeral Key Exchange)
- Tự động mã hóa AEAD (ChaCha20 + HMAC-SHA256) mọi luồng dữ liệu
- Tự động lọc tấn công Replay (64-bit Sliding Window)
- Hỗ trợ mô hình Intent Routing (@server.on_intent) chuẩn nghiệp vụ

Tương thích: Python 3.8+ (Zero External Dependencies)
Mốc thời gian: 2026-09-18
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time
from typing import Callable, Dict, Any, Optional

try:
    from .packet_guard import AEADEngine, AntiReplayFilter, HEADER_FORMAT, HEADER_SIZE, MAGIC_BYTES
except ImportError:  # Chạy trực tiếp: python3 packet_middleware.py
    from packet_guard import AEADEngine, AntiReplayFilter, HEADER_FORMAT, HEADER_SIZE, MAGIC_BYTES


# =====================================================================
# 1. SECURE SESSION CONTEXT
# =====================================================================

class SecureSession:
    """Quản lý trạng thái phiên làm việc giữa Client và Server"""
    def __init__(self, session_id: int, shared_key: bytes):
        self.session_id = session_id
        self.shared_key = shared_key
        self.aead = AEADEngine(shared_key)
        self.replay_filter = AntiReplayFilter(window_size=64, max_time_drift_ms=2000)
        self.send_seq = 0
        self.created_at = time.time()

    def pack(self, payload_dict: Dict[str, Any]) -> bytes:
        self.send_seq += 1
        timestamp = int(time.time() * 1000)
        nonce = secrets.token_bytes(12)
        payload_bytes = json.dumps(payload_dict).encode("utf-8")

        associated_data = struct.pack("!2sQQQ", MAGIC_BYTES, self.session_id, self.send_seq, timestamp)
        ciphertext, tag = self.aead.seal(nonce, payload_bytes, associated_data)

        header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, self.session_id, self.send_seq, timestamp, tag, nonce)
        return header + ciphertext

    def unpack(self, raw_bytes: bytes) -> Dict[str, Any]:
        if len(raw_bytes) < HEADER_SIZE:
            raise ValueError("Gói tin dị dạng: Kích thước nhỏ hơn Header chuẩn")

        magic, session_id, seq_id, timestamp, tag, nonce = struct.unpack(HEADER_FORMAT, raw_bytes[:HEADER_SIZE])
        ciphertext = raw_bytes[HEADER_SIZE:]

        if magic != MAGIC_BYTES:
            raise ValueError("Gói tin không hợp lệ: Sai Magic Bytes")

        if session_id != self.session_id:
            raise ValueError(f"Sai lệch phiên kết nối: {session_id} != {self.session_id}")

        allowed, msg = self.replay_filter.check_and_update(seq_id, timestamp)
        if not allowed:
            raise ValueError(f"SECURITY ALERT (REPLAY): {msg}")

        associated_data = struct.pack("!2sQQQ", magic, session_id, seq_id, timestamp)
        plaintext = self.aead.open(nonce, ciphertext, associated_data, tag)
        return json.loads(plaintext.decode("utf-8"))


# =====================================================================
# 2. SECURE SERVER FRAMEWORK (DECORATOR / ROUTER PATTERN)
# =====================================================================

class SecureServer:
    """
    Máy chủ Socket bảo mật cao với mô hình điều phối Intent (@on_intent)
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        self.host = host
        self.port = port
        self.intent_handlers: Dict[str, Callable[[SecureSession, Dict[str, Any]], Dict[str, Any]]] = {}
        self.sessions: Dict[int, SecureSession] = {}
        self.server_sock: Optional[socket.socket] = None
        self.running = False

    def on_intent(self, intent_name: str):
        """Decorator đăng ký hàm xử lý cho từng Intent cụ thể"""
        def decorator(func: Callable[[SecureSession, Dict[str, Any]], Dict[str, Any]]):
            self.intent_handlers[intent_name] = func
            return func
        return decorator

    def _handle_client(self, conn: socket.socket, addr: tuple):
        session: Optional[SecureSession] = None
        try:
            # 1. Bắt tay tạo phiên (Handshake Protocol)
            handshake_raw = conn.recv(1024)
            if not handshake_raw.startswith(b"HANDSHAKE_REQ:"):
                conn.close()
                return

            client_ephemeral = handshake_raw[len(b"HANDSHAKE_REQ:"):]
            session_id = secrets.randbits(63)
            server_ephemeral = secrets.token_bytes(32)

            # Phối hợp sinh khóa bí mật chung (Master Key Derivation)
            shared_key = hashlib.sha256(client_ephemeral + server_ephemeral + b":PG_SESSION").digest()
            session = SecureSession(session_id, shared_key)
            self.sessions[session_id] = session

            # Phản hồi ACK kèm token phiên
            resp_ack = struct.pack("!Q", session_id) + server_ephemeral
            conn.sendall(resp_ack)

            # 2. Xử lý các gói tin nghiệp vụ đã được mã hóa
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break

                try:
                    # Giải mã & thẩm định bảo mật qua Middleware
                    incoming = session.unpack(data)
                    intent = incoming.get("intent")
                    params = incoming.get("params", {})

                    if intent in self.intent_handlers:
                        # Thực thi logic nghiệp vụ phía máy chủ
                        result = self.intent_handlers[intent](session, params)
                        response_payload = {"status": "SUCCESS", "intent": intent, "data": result}
                    else:
                        response_payload = {"status": "ERROR", "message": f"Không có handler cho intent '{intent}'"}

                except ValueError as ve:
                    # Chặn đứng các hành vi bất thường và trả về cảnh báo an ninh
                    response_payload = {"status": "SECURITY_REJECT", "alert": str(ve)}

                # Đóng gói và mã hóa phản hồi trả về Client
                encrypted_resp = session.pack(response_payload)
                conn.sendall(encrypted_resp)

        except Exception:
            pass
        finally:
            conn.close()

    def start(self, blocking: bool = True):
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(20)

        print(f"[+] SecureServer đang chạy tại {self.host}:{self.port}")
        print(f"[*] Đã nạp {len(self.intent_handlers)} intent handlers:")
        for name in self.intent_handlers:
            print(f"    -> Intent: @on_intent('{name}')")

        if blocking:
            self._serve_loop()
        else:
            th = threading.Thread(target=self._serve_loop, daemon=True)
            th.start()
            time.sleep(0.2)

    def _serve_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                th = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                th.start()
            except Exception:
                break

    def stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()


# =====================================================================
# 3. SECURE CLIENT SDK
# =====================================================================

class SecureClient:
    """Client SDK tự động bắt tay và đóng gói các Intent an toàn"""
    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.session: Optional[SecureSession] = None

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))

            # Thực hiện bắt tay trao đổi khóa
            client_ephemeral = secrets.token_bytes(32)
            self.sock.sendall(b"HANDSHAKE_REQ:" + client_ephemeral)

            ack_data = self.sock.recv(1024)
            session_id = struct.unpack("!Q", ack_data[:8])[0]
            server_ephemeral = ack_data[8:]

            shared_key = hashlib.sha256(client_ephemeral + server_ephemeral + b":PG_SESSION").digest()
            self.session = SecureSession(session_id, shared_key)
            return True
        except Exception as e:
            print(f"[-] Kết nối thất bại: {e}")
            return False

    def send_intent(self, intent: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if not self.sock or not self.session:
            raise RuntimeError("Chưa khởi tạo kết nối. Hãy gọi client.connect() trước.")

        # Mã hóa & Đóng gói intent
        packet = self.session.pack({"intent": intent, "params": params})
        self.sock.sendall(packet)

        # Nhận và giải mã phản hồi
        raw_resp = self.sock.recv(4096)
        return self.session.unpack(raw_resp)

    def close(self):
        if self.sock:
            self.sock.close()
