#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PacketArena - Live Combat & Penetration Testing Orchestrator
Đấu trường Thực chiến Mạng: Red Team (PacketForge) vs Blue Team (PacketGuard)

Kịch bản đối đầu qua Socket mạng thật trên Localhost:
- Blue Team Server (Port 21001): PacketGuard Engine với AEAD & Anti-Replay
- Red Team MITM Proxy (Port 21002): PacketForge Interceptor & Tamper Engine
- Client: Gửi giao dịch qua Proxy để kiểm chứng khả năng phòng thủ

Mốc thời gian: 2026-09-18
"""

import json
import secrets
import socket
import sys
import threading
import time
from typing import Dict, Any, List

# Nạp động cơ từ 2 module đã xây dựng.
# Hỗ trợ cả hai cách nạp: theo gói patchx_core (dấu chấm) hoặc chạy trực tiếp.
try:
    from .packet_guard import PacketGuardClient, PacketGuardServer
    from .packet_forge import format_hexdump
except ImportError:  # Chạy trực tiếp: python3 packet_arena.py
    from packet_guard import PacketGuardClient, PacketGuardServer
    from packet_forge import format_hexdump


SERVER_PORT = 21001
PROXY_PORT = 21002
HOST = "127.0.0.1"


class LiveCombatArena:
    def __init__(self):
        self.session_id = 8899001122334455
        self.shared_key = secrets.token_bytes(32)
        self.server_engine = PacketGuardServer(self.session_id, self.shared_key)
        self.client_engine = PacketGuardClient(self.session_id, self.shared_key)

        self.server_running = False
        self.proxy_running = False
        self.proxy_tamper_active = False
        self.proxy_replay_multiplier = 1

        self.audit_results: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # 1. BLUE TEAM: Authoritative Socket Server
    # -------------------------------------------------------------
    def start_blue_server(self):
        self.server_running = True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, SERVER_PORT))
        srv.listen(10)
        srv.settimeout(0.5)

        def server_worker():
            while self.server_running:
                try:
                    conn, _ = srv.accept()
                    data = conn.recv(4096)
                    if data:
                        # Thẩm định gói tin qua PacketGuard Engine
                        verdict = self.server_engine.process_incoming_packet(data)
                        resp_bytes = json.dumps(verdict).encode("utf-8")
                        conn.sendall(resp_bytes)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
            srv.close()

        th = threading.Thread(target=server_worker, daemon=True)
        th.start()
        time.sleep(0.2)

    # -------------------------------------------------------------
    # 2. RED TEAM: MITM Interception Proxy
    # -------------------------------------------------------------
    def start_red_proxy(self):
        self.proxy_running = True
        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind((HOST, PROXY_PORT))
        proxy_sock.listen(10)
        proxy_sock.settimeout(0.5)

        def proxy_worker():
            while self.proxy_running:
                try:
                    client_conn, _ = proxy_sock.accept()
                    data = client_conn.recv(4096)
                    if data:
                        # Kiểm tra xem có kích hoạt can thiệp (Tampering) không
                        out_data = data
                        if self.proxy_tamper_active:
                            # Sửa đổi 1 byte trong payload đã mã hóa
                            tampered = bytearray(data)
                            tampered[-1] ^= 0x5A
                            out_data = bytes(tampered)

                        # Chuyển tiếp tới Blue Server (có thể kèm Replay)
                        for _ in range(self.proxy_replay_multiplier):
                            try:
                                to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                to_server.connect((HOST, SERVER_PORT))
                                to_server.sendall(out_data)
                                server_resp = to_server.recv(4096)
                                to_server.close()
                            except Exception:
                                server_resp = b'{"status":"PROXY_ERROR"}'

                        # Phản hồi lại cho Client
                        client_conn.sendall(server_resp)
                    client_conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break
            proxy_sock.close()

        th = threading.Thread(target=proxy_worker, daemon=True)
        th.start()
        time.sleep(0.2)

    # -------------------------------------------------------------
    # 3. HELPER: Client gửi gói tin qua Socket
    # -------------------------------------------------------------
    def send_packet_through_network(self, packet_bytes: bytes, target_port: int) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((HOST, target_port))
            sock.sendall(packet_bytes)
            raw_resp = sock.recv(4096)
            return json.loads(raw_resp.decode("utf-8"))
        except Exception as e:
            return {"status": "NETWORK_FAIL", "error": str(e)}
        finally:
            sock.close()

    # -------------------------------------------------------------
    # 4. ORCHESTRATION: Chuỗi kịch bản thực chiến
    # -------------------------------------------------------------
    def run_battle(self):
        print("=" * 76)
        print("   PACKETARENA: ĐẤU TRƯỜNG THỰC CHIẾN MẠNG RED TEAM vs BLUE TEAM")
        print("=" * 76)
        print(f"[*] Khởi động Blue Team Server trên {HOST}:{SERVER_PORT}")
        self.start_blue_server()
        print(f"[*] Khởi động Red Team MITM Proxy trên {HOST}:{PROXY_PORT}")
        self.start_red_proxy()
        print("[+] Hạ tầng mạng sẵn sàng. Bắt đầu 4 hiệp đấu đối kháng!\n")

        # ---------------------------------------------------------
        # HIỆP 1: Giao dịch hợp lệ bình thường (Baseline)
        # ---------------------------------------------------------
        print("[HIỆP 1] GIAO DỊCH BÌNH THƯỜNG (Normal Traffic)")
        print("  -> Client gửi intent BUY_ITEM qua Proxy (Proxy ở chế độ trong suốt)")
        pkt1 = self.client_engine.create_intent_packet("BUY_ITEM", {"item_id": "item_sword_legend"})
        t0 = time.perf_counter()
        resp1 = self.send_packet_through_network(pkt1, PROXY_PORT)
        lat1 = (time.perf_counter() - t0) * 1000

        verdict1 = "CHIẾN THẮNG" if resp1.get("status") == "ACCEPTED" else "THẤT BẠI"
        print(f"  -> Kết quả Server: {resp1.get('status')} | {resp1.get('result')}")
        print(f"  -> Đánh giá: {verdict1} (Độ trễ mạng: {lat1:.2f} ms)\n")
        self.audit_results.append({
            "round": "1. Normal Traffic",
            "threat": "None (Baseline)",
            "server_status": resp1.get("status"),
            "defense_success": resp1.get("status") == "ACCEPTED",
            "latency_ms": lat1
        })

        # ---------------------------------------------------------
        # HIỆP 2: Red Team kích hoạt Man-in-the-Middle Packet Tampering
        # ---------------------------------------------------------
        print("[HIỆP 2] TẤN CÔNG THAO TÚNG GÓI TIN (In-Flight Tampering)")
        print("  -> Red Team Proxy chặn gói tin và sửa đổi dữ liệu payload...")
        self.proxy_tamper_active = True
        pkt2 = self.client_engine.create_intent_packet("BUY_ITEM", {"item_id": "item_health_potion"})
        t0 = time.perf_counter()
        resp2 = self.send_packet_through_network(pkt2, PROXY_PORT)
        lat2 = (time.perf_counter() - t0) * 1000

        defended2 = resp2.get("status") == "REJECTED_TAMPERING"
        print(f"  -> Server phát hiện & xử lý: {resp2.get('status')}")
        print(f"  -> Lý do chặn: {resp2.get('reason')}")
        print(f"  -> Đánh giá Blue Team: {'PHÒNG THỦ THÀNH CÔNG [100%]' if defended2 else 'BỊ XÂM NHẬP'}\n")
        self.audit_results.append({
            "round": "2. In-Flight Tampering",
            "threat": "Man-in-the-Middle Byte Modification",
            "server_status": resp2.get("status"),
            "defense_success": defended2,
            "latency_ms": lat2
        })
        self.proxy_tamper_active = False

        # ---------------------------------------------------------
        # HIỆP 3: Red Team thực hiện Tấn công lặp lại (Replay Attack)
        # ---------------------------------------------------------
        print("[HIỆP 3] TẤN CÔNG LẶP GÓI TIN (Active Replay Attack)")
        print("  -> Client gửi 1 gói tin hợp lệ; Proxy nhân bản bắn lặp 3 lần liên tiếp...")
        self.proxy_replay_multiplier = 3
        pkt3 = self.client_engine.create_intent_packet("BUY_ITEM", {"item_id": "item_health_potion"})
        t0 = time.perf_counter()
        # Lần 1 qua proxy sẽ được server chấp nhận, nhưng các bản sao do proxy bắn lại sẽ bị chặn
        resp3 = self.send_packet_through_network(pkt3, PROXY_PORT)
        lat3 = (time.perf_counter() - t0) * 1000

        # Bắn trực tiếp lại chính gói tin này vào thẳng cổng Server để đo phản ứng chặn Replay
        replay_direct_resp = self.send_packet_through_network(pkt3, SERVER_PORT)
        defended3 = replay_direct_resp.get("status") == "REJECTED_REPLAY"
        print(f"  -> Server chặn bản sao lặp lại: {replay_direct_resp.get('status')}")
        print(f"  -> Lý do chặn: {replay_direct_resp.get('reason')}")
        print(f"  -> Đánh giá Blue Team: {'PHÒNG THỦ THÀNH CÔNG [100%]' if defended3 else 'BỊ XÂM NHẬP'}\n")
        self.audit_results.append({
            "round": "3. Replay Injection",
            "threat": "Duplicated Packet In-Flight",
            "server_status": replay_direct_resp.get("status"),
            "defense_success": defended3,
            "latency_ms": lat3
        })
        self.proxy_replay_multiplier = 1

        # ---------------------------------------------------------
        # HIỆP 4: Red Team tiêm gói tin giả mạo từ xa (Blind Injection)
        # ---------------------------------------------------------
        print("[HIỆP 4] TẤN CÔNG TIÊM GÓI TIN GIẢ MẠO (Blind Injection)")
        print("  -> Kẻ tấn công tự chế gói tin không có khóa bí mật, tiêm thẳng vào cổng Server...")
        fake_key = secrets.token_bytes(32)
        fake_client = PacketGuardClient(self.session_id, fake_key)
        fake_client.seq_id = 99  # Dùng Sequence ID mới để vượt qua bộ lọc Replay, kiểm thử bẫy AEAD
        fake_packet = fake_client.create_intent_packet("BUY_ITEM", {"item_id": "item_sword_legend"})

        t0 = time.perf_counter()
        resp4 = self.send_packet_through_network(fake_packet, SERVER_PORT)
        lat4 = (time.perf_counter() - t0) * 1000

        defended4 = resp4.get("status") in ["REJECTED_TAMPERING", "REJECTED", "REJECTED_REPLAY"]
        print(f"  -> Server chặn gói tin tiêm giả: {resp4.get('status')}")
        print(f"  -> Lý do chặn: {resp4.get('reason')}")
        print(f"  -> Đánh giá Blue Team: {'PHÒNG THỦ THÀNH CÔNG [100%]' if defended4 else 'BỊ XÂM NHẬP'}\n")
        self.audit_results.append({
            "round": "4. Blind Injection",
            "threat": "Unauthenticated Packet Crafting",
            "server_status": resp4.get("status"),
            "defense_success": defended4,
            "latency_ms": lat4
        })

        # ---------------------------------------------------------
        # Dọn dẹp luồng socket
        # ---------------------------------------------------------
        self.server_running = False
        self.proxy_running = False
        time.sleep(0.3)

        # ---------------------------------------------------------
        # BÁO CÁO NGHIỆM THU CHIẾN CUỘC
        # ---------------------------------------------------------
        print("=" * 76)
        print("                   BẢNG KẾT QUẢ THỰC CHIẾN ĐỐI KHÁNG")
        print("=" * 76)
        print(f"{'Hiệp':<22} | {'Hiểm họa':<26} | {'Trạng thái':<18} | {'Kết quả'}")
        print("-" * 76)
        all_passed = True
        for r in self.audit_results:
            passed = r["defense_success"]
            all_passed = all_passed and passed
            status_str = "CHẶN ĐỨNG [PASS]" if passed else "THẤT THỦ [FAIL]"
            print(f"{r['round']:<22} | {r['threat']:<26} | {r['server_status']:<18} | {status_str}")
        print("-" * 76)
        overall = "100% TOÀN DIỆN (CHẶN ĐỨNG MỌI CUỘC TẤN CÔNG)" if all_passed else "CÒN LỖ HỔNG"
        print(f"[✔] TỔNG KẾT BẢO VỆ BLUE TEAM: {overall}")
        print("=" * 76)


def main():
    arena = LiveCombatArena()
    arena.run_battle()


if __name__ == "__main__":
    main()
