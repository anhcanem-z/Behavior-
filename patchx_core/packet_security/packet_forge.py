#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketForge - Interactive Network Packet Injection & Manipulation Toolkit
Bộ công cụ Kiểm thử & Thực hành Thao túng (Manipulation) và Tiêm (Injection) Gói tin

Tính năng:
1. Packet Injector: Tiêm gói tin thô TCP/UDP tùy biến (Text / Hex / Burst / Loop)
2. Interception Proxy: Proxy trung gian bắt chặn và sửa đổi dữ liệu on-the-fly (MITM Tampering)
3. Packet Fuzzer: Đột biến bit/byte ngẫu nhiên để kiểm thử độ bền (Fuzzing / Robustness)
4. Hex Dump Inspector: Hiển thị cấu trúc gói tin dạng Wireshark trực quan

Tương thích: Python 3.8+ (Zero External Dependencies)
Mốc thời gian: 2026-09-18
"""

import argparse
import binascii
import random
import re
import socket
import sys
import threading
import time
from typing import Optional, List, Tuple


# =====================================================================
# 1. HEX DUMP & FORMATTING UTILITIES (WIRESHARK-STYLE)
# =====================================================================

def format_hexdump(data: bytes, prefix: str = "  ") -> str:
    """Tạo hiển thị dạng Hex Dump chuyên nghiệp giống Wireshark/tcpdump"""
    lines = []
    length = len(data)
    for i in range(0, length, 16):
        chunk = data[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Căn lề hex cho các dòng cuối không đủ 16 bytes
        hex_padded = f"{hex_bytes:<47}"
        # Chuyển đổi ASCII hiển thị (thay các ký tự điều khiển bằng '.')
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}   {hex_padded}  |{ascii_text}|")
    return "\n".join(lines)


# =====================================================================
# 2. PACKET INJECTOR ENGINE (TCP / UDP)
# =====================================================================

class PacketInjector:
    """Động cơ tiêm gói tin tùy biến (Raw/Socket-level injection)"""
    def __init__(self, target_host: str, target_port: int, proto: str = "udp"):
        self.target_host = target_host
        self.target_port = target_port
        self.proto = proto.lower()

    def send_single(self, payload: bytes) -> bool:
        """Gửi một gói tin đơn lẻ"""
        sock = None
        try:
            if self.proto == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(payload, (self.target_host, self.target_port))
            elif self.proto == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((self.target_host, self.target_port))
                sock.sendall(payload)
            return True
        except Exception as ex:
            print(f"[-] Lỗi gửi gói tin ({self.proto.upper()}): {ex}")
            return False
        finally:
            if sock:
                sock.close()

    def inject_stream(self, payload: bytes, count: int = 1, interval_ms: int = 100):
        """Bơm gói tin theo chuỗi, tần suất burst hoặc loop"""
        print(f"[*] Bắt đầu tiêm gói tin {self.proto.upper()} tới {self.target_host}:{self.target_port}")
        print(f"[*] Số lượng: {count if count > 0 else 'Vô hạn (Ctrl+C để dừng)'} | Khoảng cách: {interval_ms} ms")
        print("--- Cấu trúc Payload ---")
        print(format_hexdump(payload))
        print("------------------------\n")

        sent = 0
        try:
            while count <= 0 or sent < count:
                success = self.send_single(payload)
                sent += 1
                status = "OK" if success else "FAIL"
                print(f"[{status}] Gói tin #{sent} ({len(payload)} bytes) đã bắn.")
                if interval_ms > 0:
                    time.sleep(interval_ms / 1000.0)
        except KeyboardInterrupt:
            print(f"\n[!] Người dùng hủy lệnh. Tổng số gói đã tiêm: {sent}")
        print(f"[✔] Hoàn tất tiêm gói tin. Tổng số: {sent} gói.")


# =====================================================================
# 3. INTERCEPTION & MANIPULATION PROXY (MITM TAMPERING ENGINE)
# =====================================================================

class PacketProxy:
    """
    Proxy trung gian can thiệp dữ liệu trên đường truyền (TCP Proxy)
    Bắt gói tin, quét theo rule và thao túng payload (Parameter Tampering)
    """
    def __init__(self, listen_host: str, listen_port: int, target_host: str, target_port: int):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.tamper_rules: List[Tuple[bytes, bytes]] = []
        self.replay_multiplier = 1
        self.delay_ms = 0
        self.running = False

    def add_tamper_rule(self, pattern: bytes, replacement: bytes):
        self.tamper_rules.append((pattern, replacement))

    def _manipulate_payload(self, data: bytes, direction: str) -> bytes:
        modified = data
        for pattern, replacement in self.tamper_rules:
            if pattern in modified:
                print(f"\n[🔥 MANIPULATION DETECTED - {direction}]")
                print(f"    Gốc: {pattern}")
                print(f"    Sửa: {replacement}")
                modified = modified.replace(pattern, replacement)
        return modified

    def _forward_channel(self, src: socket.socket, dst: socket.socket, direction: str):
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break

                # Áp dụng quy tắc thao túng gói tin
                tampered = self._manipulate_payload(data, direction)

                # Mô phỏng độ trễ (Latency Injection)
                if self.delay_ms > 0:
                    time.sleep(self.delay_ms / 1000.0)

                # Mô phỏng Replay Injection (Nhân đôi gói tin)
                for _ in range(self.replay_multiplier):
                    dst.sendall(tampered)
        except Exception:
            pass
        finally:
            src.close()
            dst.close()

    def start(self):
        self.running = True
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.listen_host, self.listen_port))
        server_sock.listen(10)

        print(f"[+] Proxy Interceptor đang lắng nghe tại: {self.listen_host}:{self.listen_port}")
        print(f"[+] Chuyển tiếp tới Target: {self.target_host}:{self.target_port}")
        if self.tamper_rules:
            print(f"[*] Số quy tắc thao túng kích hoạt: {len(self.tamper_rules)}")
            for p, r in self.tamper_rules:
                print(f"    Rule: {p} -> {r}")

        try:
            while self.running:
                client_sock, client_addr = server_sock.accept()
                print(f"\n[*] Nhận kết nối mới từ Client: {client_addr}")
                try:
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.connect((self.target_host, self.target_port))
                except Exception as e:
                    print(f"[-] Không thể kết nối tới Target: {e}")
                    client_sock.close()
                    continue

                # Tạo 2 luồng chuyển tiếp 2 chiều: Client->Server và Server->Client
                t1 = threading.Thread(target=self._forward_channel, args=(client_sock, remote_sock, "CLIENT->SERVER"), daemon=True)
                t2 = threading.Thread(target=self._forward_channel, args=(remote_sock, client_sock, "SERVER->CLIENT"), daemon=True)
                t1.start()
                t2.start()
        except KeyboardInterrupt:
            print("\n[!] Dừng Proxy Interceptor.")
        finally:
            self.running = False
            server_sock.close()


# =====================================================================
# 4. PACKET FUZZER ENGINE (MUTATION / CORRUPTION TESTING)
# =====================================================================

class PacketFuzzer:
    """Động cơ đột biến gói tin kiểm thử độ bền hệ thống"""
    @staticmethod
    def mutate(payload: bytes, mutation_rate: float = 0.05) -> bytes:
        mutated = bytearray(payload)
        num_mutations = max(1, int(len(mutated) * mutation_rate))
        for _ in range(num_mutations):
            strategy = random.choice(["flip_bit", "random_byte", "zero_byte", "extend_noise"])
            idx = random.randint(0, len(mutated) - 1)
            if strategy == "flip_bit":
                mutated[idx] ^= (1 << random.randint(0, 7))
            elif strategy == "random_byte":
                mutated[idx] = random.randint(0, 255)
            elif strategy == "zero_byte":
                mutated[idx] = 0x00
            elif strategy == "extend_noise":
                mutated.extend(random.randbytes(4))
        return bytes(mutated)


# =====================================================================
# 5. BUILT-IN DEMO & SELF-TEST SUITE
# =====================================================================

def run_standalone_demo():
    """Chạy mô phỏng toàn bộ chuỗi: Mock Server + Normal + Proxy Tampering + Injection"""
    print("=" * 72)
    print("  PACKETFORGE: CHẠY MÔ PHỎNG THỰC HÀNH CAN THIỆP GÓI TIN THỰC TẾ")
    print("=" * 72)

    MOCK_PORT = 19888
    PROXY_PORT = 18888

    # 1. Khởi chạy Mock Server trong luồng ngầm
    server_ready = threading.Event()
    received_logs = []

    def mock_server_loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", MOCK_PORT))
        srv.listen(5)
        server_ready.set()

        while True:
            try:
                conn, _ = srv.accept()
                data = conn.recv(1024)
                if data:
                    received_logs.append(data)
                    # Giả lập phản hồi của máy chủ
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nORDER_PROCESSED")
                conn.close()
            except Exception:
                break

    srv_thread = threading.Thread(target=mock_server_loop, daemon=True)
    srv_thread.start()
    server_ready.wait()
    print(f"[1] Mock Server backend đang chạy tại port {MOCK_PORT}")

    # 2. Khởi chạy Proxy Interceptor ở giữa
    proxy = PacketProxy("127.0.0.1", PROXY_PORT, "127.0.0.1", MOCK_PORT)
    # Quy tắc thao túng: Đổi giá tiền "price=1000" thành "price=0000"
    proxy.add_tamper_rule(b"price=1000", b"price=0000")

    proxy_thread = threading.Thread(target=proxy.start, daemon=True)
    proxy_thread.start()
    time.sleep(0.3)
    print(f"[2] Interception Proxy kích hoạt tại port {PROXY_PORT} (Đang chờ bắt gói...)")

    # 3. Kịch bản A: Client gửi gói tin mua hàng bình thường qua Proxy
    print("\n[3] CLIENT GỬI GÓI TIN MUA HÀNG:")
    client_payload = b"POST /api/buy HTTP/1.1\r\nHost: game.local\r\n\r\nitem_id=99&price=1000"
    print(format_hexdump(client_payload, prefix="    "))

    injector = PacketInjector("127.0.0.1", PROXY_PORT, proto="tcp")
    injector.send_single(client_payload)
    time.sleep(0.4)

    # 4. Kiểm tra Server Backend thực tế nhận được gì
    if received_logs:
        actual_received = received_logs[-1]
        print("\n[4] SERVER BACKEND THỰC TẾ NHẬN ĐƯỢC (Sau khi bị Proxy thao túng):")
        print(format_hexdump(actual_received, prefix="    "))

        if b"price=0000" in actual_received:
            print("\n[✔] THAO TÚNG THÀNH CÔNG: Proxy đã tráo đổi 'price=1000' thành 'price=0000' on-the-fly!")
        else:
            print("\n[-] Chưa khớp rule thao túng.")

    # 5. Kịch bản B: Tiêm gói tin thô UDP trực tiếp (Packet Injection)
    print("\n[5] THỬ NGHIỆM TIÊM GÓI TIN THÔ UDP (Direct Injection):")
    raw_packet = b"PING_BOT_HEARTBEAT\x00\x01\xFF\xAA"
    udp_injector = PacketInjector("127.0.0.1", MOCK_PORT, proto="udp")
    udp_injector.inject_stream(raw_packet, count=3, interval_ms=50)

    # 6. Kịch bản C: Fuzzing gói tin
    print("\n[6] THỬ NGHIỆM ĐỘT BIẾN GÓI TIN (Packet Fuzzer):")
    fuzzed = PacketFuzzer.mutate(client_payload, mutation_rate=0.1)
    print(format_hexdump(fuzzed, prefix="    "))
    print("[✔] Đã tạo đột biến bit/byte thành công để fuzzing.")

    print("\n" + "=" * 72)
    print("  HOÀN THÀNH TOÀN BỘ MÔ PHỎNG KIỂM THỬ GÓI TIN AN TOÀN!")
    print("=" * 72)


# =====================================================================
# 6. CLI ENTRY POINT
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PacketForge - Network Packet Injection & Manipulation Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="mode", help="Chế độ hoạt động")

    # Subcommand: demo
    subparsers.add_parser("demo", help="Chạy chuỗi mô phỏng can thiệp gói tin tự động")

    # Subcommand: inject
    p_inject = subparsers.add_parser("inject", help="Tiêm gói tin tùy biến tới mục tiêu")
    p_inject.add_argument("--host", required=True, help="Địa chỉ IP mục tiêu")
    p_inject.add_argument("--port", type=int, required=True, help="Cổng dịch vụ mục tiêu")
    p_inject.add_argument("--proto", choices=["udp", "tcp"], default="udp", help="Giao thức (Mặc định: udp)")
    p_inject.add_argument("--text", help="Nội dung payload dạng Text")
    p_inject.add_argument("--hex", help="Nội dung payload dạng chuỗi Hex (VD: '414243')")
    p_inject.add_argument("--count", type=int, default=1, help="Số lượng gói tin cần gửi (0 = liên tục)")
    p_inject.add_argument("--interval", type=int, default=100, help="Khoảng cách giữa các gói (ms)")

    # Subcommand: proxy
    p_proxy = subparsers.add_parser("proxy", help="Bật Proxy trung gian bắt chặn và sửa đổi gói tin (MITM)")
    p_proxy.add_argument("--listen-port", type=int, default=8888, help="Cổng Proxy lắng nghe")
    p_proxy.add_argument("--listen-host", default="0.0.0.0", help="IP Proxy lắng nghe")
    p_proxy.add_argument("--target-host", required=True, help="IP Server đích cần chuyển tiếp")
    p_proxy.add_argument("--target-port", type=int, required=True, help="Cổng Server đích")
    p_proxy.add_argument("--tamper", action="append", help="Quy tắc thay thế chuỗi Text (Cú pháp: 'FIND:REPLACE')")
    p_proxy.add_argument("--tamper-hex", action="append", help="Quy tắc thay thế chuỗi Hex (Cú pháp: 'HEX_FIND:HEX_REPLACE')")
    p_proxy.add_argument("--replay", type=int, default=1, help="Nhân số lượng gói tin gửi tới đích (Mô phỏng Replay)")
    p_proxy.add_argument("--delay", type=int, default=0, help="Độ trễ bơm thêm vào đường truyền (ms)")

    # Subcommand: fuzzer
    p_fuzz = subparsers.add_parser("fuzz", help="Tạo biến thể đột biến bit/byte gói tin")
    p_fuzz.add_argument("--text", help="Chuỗi gốc cần đột biến")
    p_fuzz.add_argument("--rate", type=float, default=0.05, help="Tỉ lệ đột biến (0.01 -> 0.5)")

    args = parser.parse_args()

    if args.mode == "demo" or len(sys.argv) == 1:
        run_standalone_demo()
    elif args.mode == "inject":
        payload = b""
        if args.hex:
            payload = binascii.unhexlify(args.hex.replace(" ", ""))
        elif args.text:
            payload = args.text.encode("utf-8")
        else:
            print("[-] Lỗi: Cần cung cấp --text hoặc --hex cho payload.")
            sys.exit(1)
        injector = PacketInjector(args.host, args.port, proto=args.proto)
        injector.inject_stream(payload, count=args.count, interval_ms=args.interval)
    elif args.mode == "proxy":
        proxy = PacketProxy(args.listen_host, args.listen_port, args.target_host, args.target_port)
        proxy.replay_multiplier = args.replay
        proxy.delay_ms = args.delay
        if args.tamper:
            for rule in args.tamper:
                parts = rule.split(":", 1)
                if len(parts) == 2:
                    proxy.add_tamper_rule(parts[0].encode("utf-8"), parts[1].encode("utf-8"))
        if args.tamper_hex:
            for rule in args.tamper_hex:
                parts = rule.split(":", 1)
                if len(parts) == 2:
                    proxy.add_tamper_rule(binascii.unhexlify(parts[0]), binascii.unhexlify(parts[1]))
        proxy.start()
    elif args.mode == "fuzz":
        base = args.text.encode("utf-8") if args.text else b"SAMPLE_PAYLOAD_FOR_FUZZING"
        fuzzed = PacketFuzzer.mutate(base, mutation_rate=args.rate)
        print("[*] Gốc:\n" + format_hexdump(base))
        print("[*] Đột biến:\n" + format_hexdump(fuzzed))


if __name__ == "__main__":
    main()
