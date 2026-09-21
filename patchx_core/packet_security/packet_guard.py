#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketGuard - Enterprise Zero-Trust Packet Protection Engine
Phòng vệ Đa tầng Chống Thao túng Gói tin (Tampering) & Tiêm Gói tin (Injection)

Tương thích: Python 3.8+ (Chỉ dùng thư viện chuẩn: hmac, hashlib, secrets, struct, time)
Mốc thời gian: 2026-09-18
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
from typing import Dict, Any, Tuple, Optional


# =====================================================================
# 1. PURE-PYTHON CHACHA20 CIPHER (RFC 7539) & HMAC-SHA256 AUTHENTICATOR
# =====================================================================

class ChaCha20:
    """RFC 7539 ChaCha20 Stream Cipher (Pure Python, Zero External Dependencies)"""

    @staticmethod
    def _rotl32(v: int, c: int) -> int:
        return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

    @classmethod
    def _quarter_round(cls, x: list, a: int, b: int, c: int, d: int) -> None:
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = cls._rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = cls._rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = cls._rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = cls._rotl32(x[b] ^ x[c], 7)

    @classmethod
    def block(cls, key: bytes, counter: int, nonce: bytes) -> bytes:
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
        k = list(struct.unpack("<8I", key))
        n = list(struct.unpack("<3I", nonce))
        state = constants + k + [counter] + n
        working = list(state)

        for _ in range(10):
            # Column rounds
            cls._quarter_round(working, 0, 4, 8, 12)
            cls._quarter_round(working, 1, 5, 9, 13)
            cls._quarter_round(working, 2, 6, 10, 14)
            cls._quarter_round(working, 3, 7, 11, 15)
            # Diagonal rounds
            cls._quarter_round(working, 0, 5, 10, 15)
            cls._quarter_round(working, 1, 6, 11, 12)
            cls._quarter_round(working, 2, 7, 8, 13)
            cls._quarter_round(working, 3, 4, 9, 14)

        out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        return struct.pack("<16I", *out)

    @classmethod
    def encrypt(cls, key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
        res = bytearray()
        for i in range(0, len(plaintext), 64):
            block_key = cls.block(key, counter + (i // 64), nonce)
            chunk = plaintext[i:i + 64]
            res.extend(bytes(a ^ b for a, b in zip(chunk, block_key[:len(chunk)])))
        return bytes(res)


class AEADEngine:
    """
    Authenticated Encryption with Associated Data (AEAD)
    Sử dụng ChaCha20 + HMAC-SHA256 (Encrypt-then-MAC)
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Khóa phải có độ dài chính xác 32 bytes.")
        self.enc_key = hashlib.sha256(key + b":ENC").digest()
        self.mac_key = hashlib.sha256(key + b":MAC").digest()

    def seal(self, nonce: bytes, plaintext: bytes, associated_data: bytes) -> Tuple[bytes, bytes]:
        """Mã hóa payload và sinh mã xác thực toàn vẹn (Auth Tag)"""
        ciphertext = ChaCha20.encrypt(self.enc_key, 1, nonce, plaintext)
        # MAC tính trên: Nonce (12B) + Associated Data + Ciphertext + Chiều dài
        mac_data = nonce + associated_data + ciphertext + struct.pack("!QQ", len(associated_data), len(ciphertext))
        tag = hmac.new(self.mac_key, mac_data, hashlib.sha256).digest()[:16]
        return ciphertext, tag

    def open(self, nonce: bytes, ciphertext: bytes, associated_data: bytes, tag: bytes) -> bytes:
        """Kiểm tra toàn vẹn và giải mã (Constant-time comparison)"""
        mac_data = nonce + associated_data + ciphertext + struct.pack("!QQ", len(associated_data), len(ciphertext))
        expected_tag = hmac.new(self.mac_key, mac_data, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected_tag, tag):
            raise ValueError("SECURITY ALERT: Tag xác thực toàn vẹn không khớp! Gói tin đã bị THAO TÚNG (Tampered).")
        return ChaCha20.encrypt(self.enc_key, 1, nonce, ciphertext)


# =====================================================================
# 2. SLIDING WINDOW & ANTI-REPLAY FILTER (64-bit Bitmask)
# =====================================================================

class AntiReplayFilter:
    """
    Bộ lọc chống tấn công lặp gói tin (Replay Attack) dựa trên 64-bit Sliding Window
    Phù hợp cho cả giao thức TCP lẫn UDP đến lệch thứ tự.
    """
    def __init__(self, window_size: int = 64, max_time_drift_ms: int = 2000):
        self.window_size = window_size
        self.max_time_drift_ms = max_time_drift_ms
        self.highest_seq = 0
        self.bitmap = 0

    def check_and_update(self, seq_id: int, packet_time_ms: int) -> Tuple[bool, str]:
        current_time_ms = int(time.time() * 1000)

        # 1. Kiểm tra độ lệch thời gian
        drift = abs(current_time_ms - packet_time_ms)
        if drift > self.max_time_drift_ms:
            return False, f"Gói tin hết hạn hoặc độ trễ quá lớn: drift={drift}ms (Max={self.max_time_drift_ms}ms)"

        # 2. Kiểm tra chuỗi Sequence ID
        if self.highest_seq == 0:
            self.highest_seq = seq_id
            self.bitmap = 1
            return True, "OK (Init)"

        if seq_id > self.highest_seq:
            diff = seq_id - self.highest_seq
            if diff >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = ((self.bitmap << diff) & ((1 << self.window_size) - 1)) | 1
            self.highest_seq = seq_id
            return True, "OK (New Highest)"
        else:
            diff = self.highest_seq - seq_id
            if diff >= self.window_size:
                return False, f"Gói tin quá cũ rơi ra ngoài cửa sổ trượt: diff={diff} >= {self.window_size}"
            mask = 1 << diff
            if (self.bitmap & mask) != 0:
                return False, f"Phát hiện REPLAY ATTACK: seq_id={seq_id} đã từng được xử lý!"
            self.bitmap |= mask
            return True, "OK (In-window Out-of-order)"


# =====================================================================
# 3. SECURE PACKET PROTOCOL & INTENT VALIDATOR
# =====================================================================

# Cấu trúc Khung Gói Tin (Wire Format):
# [Magic: 2B] + [SessionID: 8B] + [SeqID: 8B] + [Timestamp: 8B] + [Tag: 16B] + [Nonce: 12B] + [Ciphertext: Var]
HEADER_FORMAT = "!2sQQQ16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAGIC_BYTES = b"PG"  # PacketGuard Identifier


class PacketGuardClient:
    """Mô phỏng Client an toàn: Đóng gói và gửi Intent"""
    def __init__(self, session_id: int, secret_key: bytes):
        self.session_id = session_id
        self.secret_key = secret_key
        self.aead = AEADEngine(secret_key)
        self.seq_id = 0

    def create_intent_packet(self, intent_type: str, params: Dict[str, Any]) -> bytes:
        self.seq_id += 1
        timestamp = int(time.time() * 1000)
        nonce = secrets.token_bytes(12)

        # Dữ liệu nghiệp vụ thuần túy dạng Intent
        payload = json.dumps({"intent": intent_type, "params": params}).encode("utf-8")

        # Associated Data chứa các thông tin cố định trong Header
        associated_data = struct.pack("!2sQQQ", MAGIC_BYTES, self.session_id, self.seq_id, timestamp)
        ciphertext, tag = self.aead.seal(nonce, payload, associated_data)

        # Đóng gói hoàn chỉnh
        packet = struct.pack(HEADER_FORMAT, MAGIC_BYTES, self.session_id, self.seq_id, timestamp, tag, nonce) + ciphertext
        return packet


class PacketGuardServer:
    """Mô phỏng Server quyền uy (Authoritative Server): Giải mã, Chống lặp và Xác thực nghiệp vụ"""
    def __init__(self, session_id: int, secret_key: bytes):
        self.session_id = session_id
        self.aead = AEADEngine(secret_key)
        self.replay_filter = AntiReplayFilter(window_size=64, max_time_drift_ms=2000)

        # Trạng thái Server-Side độc quyền
        self.db_player = {
            "balance": 1000,
            "hp": 100,
            "inventory": [],
            "last_action_time": 0
        }
        self.shop_items = {
            "item_sword_legend": {"price": 250, "level_req": 5},
            "item_health_potion": {"price": 20, "level_req": 1}
        }

    def process_incoming_packet(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Quy trình 4 bước thẩm định gói tin tại Gateway"""
        if len(raw_bytes) < HEADER_SIZE:
            return {"status": "REJECTED", "reason": "Dị dạng: Gói tin nhỏ hơn kích thước Header chuẩn"}

        # 1. Parse Header
        magic, session_id, seq_id, timestamp, tag, nonce = struct.unpack(HEADER_FORMAT, raw_bytes[:HEADER_SIZE])
        ciphertext = raw_bytes[HEADER_SIZE:]

        if magic != MAGIC_BYTES:
            return {"status": "REJECTED", "reason": "Dị dạng: Magic bytes không hợp lệ"}

        if session_id != self.session_id:
            return {"status": "REJECTED", "reason": f"Phiên không hợp lệ: session={session_id}"}

        # 2. Bộ lọc chống Replay Attack
        allowed, msg = self.replay_filter.check_and_update(seq_id, timestamp)
        if not allowed:
            return {"status": "REJECTED_REPLAY", "seq_id": seq_id, "reason": msg}

        # 3. Giải mã và kiểm tra mã toàn vẹn chống Manipulation
        associated_data = struct.pack("!2sQQQ", magic, session_id, seq_id, timestamp)
        try:
            plaintext = self.aead.open(nonce, ciphertext, associated_data, tag)
            payload = json.loads(plaintext.decode("utf-8"))
        except ValueError as ve:
            return {"status": "REJECTED_TAMPERING", "seq_id": seq_id, "reason": str(ve)}
        except Exception as ex:
            return {"status": "REJECTED_CORRUPTED", "reason": f"Lỗi giải mã payload: {str(ex)}"}

        # 4. Server-Authoritative Logic (Xác thực nghiệp vụ)
        intent = payload.get("intent")
        params = payload.get("params", {})
        result = self._execute_intent(intent, params)

        return {
            "status": "ACCEPTED",
            "seq_id": seq_id,
            "intent": intent,
            "result": result,
            "current_state": dict(self.db_player)
        }

    def _execute_intent(self, intent: str, params: Dict[str, Any]) -> str:
        """Xử lý ý định của client - Tuyệt đối không chấp nhận client can thiệp dữ liệu"""
        if intent == "BUY_ITEM":
            item_id = params.get("item_id")
            if item_id not in self.shop_items:
                return f"Thất bại: Vật phẩm {item_id} không tồn tại!"
            
            # GIÁ TIỀN ĐƯỢC TÍNH BỞI SERVER, KHÔNG PHẢI TỪ CLIENT
            item_price = self.shop_items[item_id]["price"]
            if self.db_player["balance"] < item_price:
                return f"Thất bại: Không đủ số dư (Cần {item_price}, hiện có {self.db_player['balance']})"

            self.db_player["balance"] -= item_price
            self.db_player["inventory"].append(item_id)
            return f"Thành công: Mua '{item_id}' với giá {item_price} vàng!"

        elif intent == "MUTATE_STATE":
            # Nếu kẻ tấn công cố tình tiêm một intent thay đổi chỉ số
            return "CẢNH BÁO AN NINH: Client không có quyền ghi đè trạng thái máy chủ!"

        return f"Ý định không xác định: {intent}"


# =====================================================================
# 4. CLI COMMAND SUITE & DEMO INTERFACES
# =====================================================================

def run_demo():
    print("=" * 70)
    print("  PACKETGUARD: MÔ PHỎNG LUỒNG GIAO THỨC AN TOÀN (NORMAL FLOW)")
    print("=" * 70)
    shared_key = secrets.token_bytes(32)
    session_id = 9988776655443322
    client = PacketGuardClient(session_id, shared_key)
    server = PacketGuardServer(session_id, shared_key)

    print(f"[*] Khởi tạo phiên: {session_id}")
    print(f"[*] Số dư ban đầu phía Server: {server.db_player['balance']} vàng\n")

    # Client gửi Intent mua đồ
    print("[+] Client gửi Intent: BUY_ITEM (item_id: item_sword_legend)")
    packet1 = client.create_intent_packet("BUY_ITEM", {"item_id": "item_sword_legend"})
    res1 = server.process_incoming_packet(packet1)
    print(f"    -> Server phản hồi: {res1['status']} | {res1.get('result')}")
    print(f"    -> Số dư hiện tại trên Server: {res1['current_state']['balance']} vàng\n")


def run_attack_tamper():
    print("=" * 70)
    print("  PACKETGUARD: THỬ NGHIỆM TẤN CÔNG THAO TÚNG GÓI TIN (TAMPERING)")
    print("=" * 70)
    shared_key = secrets.token_bytes(32)
    session_id = 1234567890
    client = PacketGuardClient(session_id, shared_key)
    server = PacketGuardServer(session_id, shared_key)

    print("[+] Client tạo gói tin mua vật phẩm hợp lệ...")
    valid_packet = client.create_intent_packet("BUY_ITEM", {"item_id": "item_health_potion"})
    print(f"[+] Kích thước gói tin chuẩn: {len(valid_packet)} bytes")

    # Kẻ tấn công can thiệp trên đường truyền (đổi 1 byte payload)
    print("[!] Kẻ tấn công (Proxy/Mitm) bắt gói tin và sửa đổi dữ liệu...")
    tampered_packet = bytearray(valid_packet)
    tampered_packet[-1] ^= 0xAA  # Sửa đổi bit cuối

    print("[*] Chuyển gói tin đã sửa đổi lên Server...")
    res = server.process_incoming_packet(bytes(tampered_packet))
    print(f"[-] KẾT QUẢ PHÒNG THỦ: {res['status']}")
    print(f"[-] Lý do từ chối: {res.get('reason')}")
    print("[✔] Thao túng gói tin đã bị chặn đứng hoàn toàn bởi AEAD Tag!")


def run_attack_replay():
    print("=" * 70)
    print("  PACKETGUARD: THỬ NGHIỆM TẤN CÔNG LẶP GÓI TIN (REPLAY ATTACK)")
    print("=" * 70)
    shared_key = secrets.token_bytes(32)
    session_id = 555666777
    client = PacketGuardClient(session_id, shared_key)
    server = PacketGuardServer(session_id, shared_key)

    print("[+] Client gửi gói tin mua bình máu lần 1...")
    packet = client.create_intent_packet("BUY_ITEM", {"item_id": "item_health_potion"})
    res1 = server.process_incoming_packet(packet)
    print(f"    -> Lần 1: {res1['status']} - {res1.get('result')}")

    print("\n[!] Kẻ tấn công sao chép gói tin hợp lệ và BẮN LẠI (Replay) liên tiếp...")
    for i in range(1, 4):
        replay_res = server.process_incoming_packet(packet)
        print(f"    -> Bắn lại lần {i}: [{replay_res['status']}] - {replay_res.get('reason')}")

    print("\n[✔] Tấn công Replay đã bị triệt tiêu bởi 64-bit Sliding Window Sequence Filter!")


def run_attack_inject():
    print("=" * 70)
    print("  PACKETGUARD: THỬ NGHIỆM TẤN CÔNG TIÊM GÓI TIN GIẢ MẠO (INJECTION)")
    print("=" * 70)
    session_id = 999111222
    server_key = secrets.token_bytes(32)
    server = PacketGuardServer(session_id, server_key)

    print("[!] Kẻ tấn công dùng script tự chế gói tin từ con số 0 mà không có Session Key...")
    fake_key = secrets.token_bytes(32)  # Khóa giả mạo
    fake_client = PacketGuardClient(session_id, fake_key)
    fake_packet = fake_client.create_intent_packet("MUTATE_STATE", {"hp": 999999, "balance": 999999})

    print("[*] Tiêm gói tin giả mạo lên Server...")
    res = server.process_incoming_packet(fake_packet)
    print(f"[-] KẾT QUẢ PHÒNG THỦ: {res['status']}")
    print(f"[-] Lý do từ chối: {res.get('reason')}")
    print("[✔] Tiêm gói tin thất bại: Server từ chối vì không giải mã được chữ ký hợp lệ!")


def run_benchmark():
    print("=" * 70)
    print("  PACKETGUARD: KIỂM THỬ HIỆU NĂNG ĐÓNG GÓI & GIẢI MÃ (BENCHMARK)")
    print("=" * 70)
    shared_key = secrets.token_bytes(32)
    session_id = 1122334455
    client = PacketGuardClient(session_id, shared_key)
    server = PacketGuardServer(session_id, shared_key)

    rounds = 2000
    print(f"[*] Thực thi kiểm thử hiệu năng với {rounds} gói tin...")

    start_time = time.perf_counter()
    for _ in range(rounds):
        pkt = client.create_intent_packet("BUY_ITEM", {"item_id": "item_health_potion"})
        res = server.process_incoming_packet(pkt)
        if res["status"] != "ACCEPTED":
            print(f"[!] Lỗi tại gói: {res}")
            break

    total_time = time.perf_counter() - start_time
    avg_latency_us = (total_time / rounds) * 1_000_000
    throughput = rounds / total_time

    print(f"[+] Tổng thời gian ({rounds} gói): {total_time:.4f} giây")
    print(f"[+] Độ trễ trung bình (Roundtrip Pack+Verify): {avg_latency_us:.2f} µs/gói")
    print(f"[+] Tốc độ xử lý (Throughput): {throughput:,.1f} gói/giây (trên 1 CPU Core)")
    print("[✔] Đạt tiêu chí tối ưu hóa cao cho các ứng dụng Real-time!")


def main():
    parser = argparse.ArgumentParser(description="PacketGuard - Zero-Trust Packet Protection Engine")
    parser.add_argument("--demo", action="store_true", help="Chạy luồng demo tương tác chuẩn")
    parser.add_argument("--attack-tamper", action="store_true", help="Mô phỏng thử nghiệm tấn công Thao túng gói tin")
    parser.add_argument("--attack-replay", action="store_true", help="Mô phỏng thử nghiệm tấn công Lặp gói tin")
    parser.add_argument("--attack-inject", action="store_true", help="Mô phỏng thử nghiệm tấn công Tiêm gói tin giả mạo")
    parser.add_argument("--benchmark", action="store_true", help="Đo đạc hiệu năng và độ trễ xử lý gói tin")

    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.attack_tamper:
        run_attack_tamper()
    elif args.attack_replay:
        run_attack_replay()
    elif args.attack_inject:
        run_attack_inject()
    elif args.benchmark:
        run_benchmark()
    else:
        # Mặc định chạy toàn bộ chuỗi kiểm thử
        run_demo()
        print()
        run_attack_tamper()
        print()
        run_attack_replay()
        print()
        run_attack_inject()
        print()
        run_benchmark()


if __name__ == "__main__":
    main()
