#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Động cơ Tự động Làm Mới Phiên Dịch Phụ Đề & Bật Chia Sẻ Toàn Màn Hình (Auto Session Refresher)

Chức năng:
  - Tự động reset và bật lại phiên dịch phụ đề theo chu kỳ định cấu hình (mặc định 2 phút 40 giây = 160 giây)
    nhằm vô hiệu hóa triệt để giới hạn ngắt kết nối 3 phút (180 giây) của máy chủ dịch thời gian thực (Saydi AI / WebSocket).
  - Tự động tương tác và chấp thuận hộp thoại chia sẻ màn hình MediaProjection của Android (chuyển sang 'Toàn bộ màn hình'
    và bấm 'Bắt đầu ngay' / 'Start now').
  - Hỗ trợ cả môi trường thiết bị thật / máy ảo qua ADB lẫn chạy trực tiếp trên Termux (hỗ trợ root qua `su` hoặc appops).
  - Tích hợp phát âm thông báo qua TTS (Text-To-Speech) sau mỗi chu kỳ thành công.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cmd(cmd_list, timeout: int = 15) -> Tuple[int, str, str]:
    """Thực thi lệnh an toàn."""
    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as e:
        return -1, "", str(e)


class AutoSessionRefresher:
    def __init__(
        self,
        package: str = "com.sota.aitranslatex",
        interval: int = 160,
        adb_device: Optional[str] = None,
        use_root: bool = False,
        speak_tts: bool = True
    ):
        self.package = package
        self.interval = interval  # 160s = 2 phút 40 giây
        self.adb_device = adb_device
        self.use_root = use_root
        self.speak_tts = speak_tts
        self.screen_width = 1080
        self.screen_height = 2400

    def _exec_device(self, shell_cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
        """Thực thi shell command trên thiết bị đích (qua ADB hoặc local)."""
        if self.adb_device:
            cmd = ["adb", "-s", self.adb_device, "shell"]
            if self.use_root:
                cmd.extend(["su", "-c", shell_cmd])
            else:
                cmd.append(shell_cmd)
            return run_cmd(cmd, timeout=timeout)

        # Kiểm tra nếu đang chạy trong Termux / Android nội bộ
        if shutil.which("getprop") or os.path.exists("/system/bin/sh"):
            if self.use_root and shutil.which("su"):
                return run_cmd(["su", "-c", shell_cmd], timeout=timeout)
            return run_cmd(["sh", "-c", shell_cmd], timeout=timeout)

        # Fallback qua adb mặc định nếu có
        if shutil.which("adb"):
            cmd = ["adb", "shell"]
            if self.use_root:
                cmd.extend(["su", "-c", shell_cmd])
            else:
                cmd.append(shell_cmd)
            return run_cmd(cmd, timeout=timeout)

        return run_cmd(["sh", "-c", shell_cmd], timeout=timeout)

    def detect_screen_size(self):
        """Lấy kích thước màn hình thiết bị."""
        rc, out, _ = self._exec_device("wm size")
        if rc == 0 and "Physical size:" in out:
            m = re.search(r"(\d+)x(\d+)", out)
            if m:
                self.screen_width = int(m.group(1))
                self.screen_height = int(m.group(2))
                return self.screen_width, self.screen_height
        return 1080, 2400

    def grant_project_media(self) -> bool:
        """Cố gắng cấp quyền PROJECT_MEDIA trước để bỏ qua hộp thoại (nếu có quyền root/adb)."""
        cmd = f"cmd appops set {self.package} PROJECT_MEDIA allow"
        rc, _, _ = self._exec_device(cmd)
        return rc == 0

    def accept_mediaprojection_dialog(self) -> bool:
        """Tự động chọn 'Toàn bộ màn hình' và bấm 'Bắt đầu ngay' trên dialog Android 14/15."""
        # 1. Thử dump UI để quét node (lưu vào outputs/tu-sinh/uidump.xml)
        tu_sinh_dir = os.path.join(ROOT, "outputs", "tu-sinh")
        os.makedirs(tu_sinh_dir, exist_ok=True)
        dump_target = os.path.join(tu_sinh_dir, "uidump.xml")
        dump_cmd = (
            f"mkdir -p '{tu_sinh_dir}' 2>/dev/null; "
            f"uiautomator dump '{dump_target}' 2>/dev/null && cat '{dump_target}' || "
            "uiautomator dump /data/local/tmp/uidump.xml 2>/dev/null && cat /data/local/tmp/uidump.xml"
        )
        rc, out, _ = self._exec_device(dump_cmd, timeout=8)
        # Xóa sạch tệp tự sinh vô dụng ngay sau khi đã đọc xong nội dung
        self._exec_device(f"rm -f '{dump_target}' /data/local/tmp/uidump.xml 2>/dev/null")
        if os.path.isfile(dump_target):
            try:
                os.remove(dump_target)
            except Exception:
                pass

        handled = False
        if rc == 0 and out:
            # Kiểm tra nếu xuất hiện hộp thoại MediaProjection
            if any(k in out for k in ["MediaProjection", "screen_share_mode_spinner", "Toàn bộ màn hình", "Entire screen", "Bắt đầu ngay", "Start now"]):
                print("  [AutoRefresher] Phát hiện hộp thoại chia sẻ màn hình MediaProjection.")

                # Nếu spinner đang hiển thị hoặc có tùy chọn 'Toàn bộ màn hình' / 'Entire screen'
                spinner_x = self.screen_width // 2
                spinner_y = int(self.screen_height * 0.45)
                self._exec_device(f"input tap {spinner_x} {spinner_y}")
                time.sleep(0.5)

                # Bấm phím mũi tên xuống và Enter để chọn Toàn bộ màn hình (Entire screen)
                self._exec_device("input keyevent 20")  # KEYCODE_DPAD_DOWN
                time.sleep(0.3)
                self._exec_device("input keyevent 66")  # KEYCODE_ENTER
                time.sleep(0.5)

                # Tìm và click nút 'Bắt đầu ngay' / 'Start now' (nằm ở góc dưới bên phải dialog)
                btn_x = int(self.screen_width * 0.78)
                btn_y = int(self.screen_height * 0.65)
                self._exec_device(f"input tap {btn_x} {btn_y}")
                time.sleep(0.5)
                handled = True

        # Fallback mù (blind tap) nếu uiautomator không phản hồi hoặc dialog đang nổi
        if not handled:
            confirm_x = int(self.screen_width * 0.75)
            confirm_y = int(self.screen_height * 0.65)
            self._exec_device(f"input tap {confirm_x} {confirm_y}")
            self._exec_device("input keyevent 66")
        return True

    def trigger_reset_cycle(self) -> bool:
        """Thực hiện 1 chu kỳ: Dừng phiên cũ -> Chờ 1.5s -> Bật lại phiên mới -> Xử lý cấp quyền."""
        print(f"\n[AutoRefresher] === BẮT ĐẦU CHU KỲ LÀM MỚI PHIÊN DỊCH ({self.package}) ===")

        # 1. Cố gắng cấp quyền appops
        self.grant_project_media()

        # 2. Dừng phiên dịch hiện tại (tắt mic / ngắt session)
        mic_x = self.screen_width // 2
        mic_y = int(self.screen_height * 0.78)

        print(f"  [1/4] Chạm nút dừng phiên dịch hiện tại tại ({mic_x}, {mic_y})...")
        self._exec_device(f"input tap {mic_x} {mic_y}")

        # 3. Nghỉ giải phóng kết nối WebSocket an toàn (1.5s)
        print("  [2/4] Chờ giải phóng kết nối WebSocket cũ (1.5s)...")
        time.sleep(1.5)

        # 4. Kích hoạt lại phiên dịch mới
        print(f"  [3/4] Bật lại phiên dịch phụ đề mới tại ({mic_x}, {mic_y})...")
        self._exec_device(f"input tap {mic_x} {mic_y}")
        time.sleep(1.2)

        # 5. Tự động chấp thuận chia sẻ màn hình toàn bộ (MediaProjection)
        print("  [4/4] Tự động xác nhận quyền chia sẻ toàn màn hình...")
        self.accept_mediaprojection_dialog()

        # 6. Thông báo phát âm qua TTS
        msg = f"Đã tự động làm mới phiên dịch phụ đề và bật chia sẻ toàn màn hình. Chu kỳ tiếp theo sau 2 phút 40 giây."
        print(f"  [OK] {msg}")

        if self.speak_tts:
            self._speak(msg)

        return True

    def _speak(self, text: str):
        """Phát âm thông báo qua TTS."""
        speak_script = os.path.join(ROOT, "tools", "speak.py")
        if os.path.isfile(speak_script):
            subprocess.Popen([sys.executable, speak_script, text])
        elif shutil.which("termux-tts-speak"):
            subprocess.Popen(["termux-tts-speak", "-l", "vi", "-r", "1.0", text])

    def run_loop(self):
        """Vòng lặp tự động định kỳ sau mỗi interval (160 giây)."""
        self.detect_screen_size()
        print(f"[AutoRefresher] Khởi chạy vòng lặp tự động:")
        print(f"  - Ứng dụng mục tiêu: {self.package}")
        print(f"  - Chu kỳ làm mới: {self.interval} giây (2 phút 40 giây)")
        print(f"  - Kích thước màn hình: {self.screen_width}x{self.screen_height}")
        print(f"  - Nhấn Ctrl+C để dừng vòng lặp bất cứ lúc nào.")

        cycle = 1
        while True:
            try:
                print(f"\n--- Chu kỳ #{cycle} ---")
                self.trigger_reset_cycle()

                remaining = self.interval
                print(f"[AutoRefresher] Đang đếm ngược tới chu kỳ kế tiếp...")
                while remaining > 0:
                    mins = remaining // 60
                    secs = remaining % 60
                    sys.stdout.write(f"\r  >> Còn lại: {mins:02d}:{secs:02d} ({remaining}s) trước khi làm mới...  ")
                    sys.stdout.flush()
                    step = min(5, remaining)
                    time.sleep(step)
                    remaining -= step
                print("\n  >> Hết thời gian chờ! Tiến hành làm mới phiên...")
                cycle += 1
            except KeyboardInterrupt:
                print("\n[AutoRefresher] Người dùng đã hủy vòng lặp. Dừng tiến trình.")
                break
            except Exception as e:
                print(f"\n[AutoRefresher] Lỗi ngoại lệ: {e}")
                time.sleep(5)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Tu dong reset va bat lai tinh nang dich phu de va bat chia se toan man hinh sau moi 2 phut 40 giay."
    )
    parser.add_argument(
        "--interval", "-i", type=int, default=160,
        help="Khoang thoi gian giua moi lan reset tinh bang giay (mac dinh: 160 = 2 phut 40 giay)"
    )
    parser.add_argument(
        "--package", "-p", type=str, default="com.sota.aitranslatex",
        help="Goi ung dung muc tieu (mac dinh: com.sota.aitranslatex)"
    )
    parser.add_argument(
        "--device", "-d", type=str, default=None,
        help="Thiet bi ADB (vi du: 100.64.170.99:5555)"
    )
    parser.add_argument(
        "--root", action="store_true",
        help="Su dung quyen root (su) tren thiet bi"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Chi chay 1 chu ky lam moi duy nhat roi thoat"
    )
    parser.add_argument(
        "--no-tts", action="store_true",
        help="Khong phat am bao cao qua TTS"
    )

    args = parser.parse_args()
    refresher = AutoSessionRefresher(
        package=args.package,
        interval=args.interval,
        adb_device=args.device,
        use_root=args.root,
        speak_tts=not args.no_tts
    )

    if args.once:
        refresher.detect_screen_size()
        refresher.trigger_reset_cycle()
    else:
        refresher.run_loop()


if __name__ == "__main__":
    main()
