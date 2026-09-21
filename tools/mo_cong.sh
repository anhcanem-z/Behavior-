#!/data/data/com.termux/files/usr/bin/bash
# mo_cong.sh — Mở / Đóng / Quản lý TOÀN BỘ các cổng phục vụ hệ thống PatchX & App:
#   • Cổng THU LOG  8787 (tools/remote_log_server.py)           — App tự gửi log/crash về
#   • Cổng AI PROXY 8765 (tools/external/codex_gemini_proxy.py)  — AI Gemini Pro + DeepSeek
#   • Cổng WEBUI    8080 (webui/server.py --port 8080)          — Dashboard quản trị trực quan
#
# Lệnh hỗ trợ:
#   bash tools/mo_cong.sh          # Mở FULL tất cả các cổng (mặc định)
#   bash tools/mo_cong.sh full     # Mở FULL tất cả các cổng
#   bash tools/mo_cong.sh app      # Chỉ mở 2 cổng phục vụ app (8787 & 8765)
#   bash tools/mo_cong.sh thu      # Chỉ mở cổng thu log 8787
#   bash tools/mo_cong.sh ai       # Chỉ mở cổng AI Proxy 8765
#   bash tools/mo_cong.sh web      # Chỉ mở WebUI Dashboard 8080
#   bash tools/mo_cong.sh kiem     # Kiểm tra trạng thái toàn bộ các cổng
#   bash tools/mo_cong.sh tat      # Tắt toàn bộ các cổng

set -u

GOC="/data/data/com.termux/files/home/_patchx"
NHA="/data/data/com.termux/files/home/tmp"

CONG_THU=8787
CONG_AI=8765
CONG_WEB=8080

LOG_THU="$NHA/cong_thu_${CONG_THU}.log"
LOG_AI="$NHA/cong_ai_${CONG_AI}.log"
LOG_WEB="$NHA/cong_web_${CONG_WEB}.log"

MAU_THU="tools/remote_log_server.py"
MAU_AI="tools/external/codex_gemini_proxy.py"
MAU_WEB="webui/server.py"

cd "$GOC" || exit 1
mkdir -p "$NHA" outputs/behavior/remote_logs

# Tim PID theo cmdline thật
tim_pid() {
    python3 - "$1" <<'PY'
import os, sys
mau = sys.argv[1]
toi, cha = os.getpid(), os.getppid()
for pid in sorted(os.listdir("/proc"), key=lambda x: (len(x), x)):
    if not pid.isdigit():
        continue
    if int(pid) in (toi, cha):
        continue
    try:
        cmd = open("/proc/%s/cmdline" % pid, "rb").read().decode("utf-8", "replace").split("\0")
    except OSError:
        continue
    if len(cmd) >= 2 and "python3" in os.path.basename(cmd[0]):
        if any(mau in arg for arg in cmd):
            print(pid)
PY
}

dang_nghe() {
    python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); print("MO")
except Exception:
    print("TAT")
finally:
    s.close()
PY
}

mo_thu() {
    if [ "$(tim_pid "$MAU_THU")" != "" ]; then echo "  [8787] Cổng Thu Log  : ĐÃ CHẠY SẴN (PID $(tim_pid "$MAU_THU" | head -1))"; return; fi
    termux-wake-lock 2>/dev/null
    setsid nohup python3 "$MAU_THU" --port "$CONG_THU" > "$LOG_THU" 2>&1 < /dev/null &
    sleep 2
    echo "  [8787] Cổng Thu Log  : $(dang_nghe $CONG_THU) (PID $(tim_pid "$MAU_THU" | head -1)) · Log: $LOG_THU"
}

mo_ai() {
    if [ "$(tim_pid "$MAU_AI")" != "" ]; then echo "  [8765] Cổng AI Proxy : ĐÃ CHẠY SẴN (PID $(tim_pid "$MAU_AI" | head -1))"; return; fi
    termux-wake-lock 2>/dev/null
    setsid nohup python3 "$MAU_AI" > "$LOG_AI" 2>&1 < /dev/null &
    sleep 2
    echo "  [8765] Cổng AI Proxy : $(dang_nghe $CONG_AI) (PID $(tim_pid "$MAU_AI" | head -1)) · Log: $LOG_AI"
}

mo_web() {
    if [ "$(tim_pid "$MAU_WEB")" != "" ]; then echo "  [8080] WebUI Dashboard: ĐÃ CHẠY SẴN (PID $(tim_pid "$MAU_WEB" | head -1))"; return; fi
    termux-wake-lock 2>/dev/null
    setsid nohup python3 "$MAU_WEB" --port "$CONG_WEB" > "$LOG_WEB" 2>&1 < /dev/null &
    sleep 2
    echo "  [8080] WebUI Dashboard: $(dang_nghe $CONG_WEB) (PID $(tim_pid "$MAU_WEB" | head -1)) · http://127.0.0.1:$CONG_WEB"
}

tat_cong() {
    for mau in "$MAU_THU" "$MAU_AI" "$MAU_WEB"; do
        for pid in $(tim_pid "$mau"); do
            kill "$pid" 2>/dev/null && echo "  ✔ Đã dừng PID $pid ($mau)"
        done
    done
    sleep 1
    termux-wake-unlock 2>/dev/null
    echo "  🔒 Khóa đánh thức Termux: ĐÃ NHẢ"
}

kiem() {
    echo "================ TRẠNG THÁI CÁC CỔNG DỊCH VỤ ================"
    printf "  • [8787] Cổng Thu Log  : %s (PID %s)\n" "$(dang_nghe $CONG_THU)" "$(tim_pid "$MAU_THU" | head -1)"
    printf "  • [8765] Cổng AI Proxy : %s (PID %s)\n" "$(dang_nghe $CONG_AI)" "$(tim_pid "$MAU_AI" | head -1)"
    printf "  • [8080] WebUI Server  : %s (PID %s)\n" "$(dang_nghe $CONG_WEB)" "$(tim_pid "$MAU_WEB" | head -1)"
    echo "------------------------------------------------------------"
    echo "  🤖 Mô hình AI đang phục vụ:"
    python3 - <<'PY'
import json, urllib.request
try:
    d = json.load(urllib.request.urlopen("http://127.0.0.1:8765/v1/models", timeout=5))
    for m in d.get("data", []):
        print("    -", m["id"], "|", m["owned_by"])
except Exception as e:
    print("    (Cổng AI chưa mở hoặc chưa phản hồi: %s)" % type(e).__name__)
PY
    echo "  🔑 Trạng thái tài khoản Google Pro:"
    python3 tools/external/google_login.py --kiem 2>/dev/null || echo "    (Chưa đăng nhập)"
    echo "  📝 Tệp log thu gần nhất:"
    ls -t outputs/behavior/remote_logs/*.jsonl 2>/dev/null | head -1 | sed 's/^/    /'
    echo "============================================================"
}

case "${1:-full}" in
    full|all|ca-hai|"")
        echo "=== MỞ FULL TOÀN BỘ CÁC CỔNG (8787, 8765, 8080) ==="
        mo_thu
        mo_ai
        mo_web
        echo ""
        kiem
        ;;
    app)
        echo "=== MỞ CÁC CỔNG PHỤC VỤ APP (8787, 8765) ==="
        mo_thu
        mo_ai
        ;;
    thu)
        echo "=== MỞ CỔNG THU LOG (8787) ==="
        mo_thu
        ;;
    ai)
        echo "=== MỞ CỔNG AI PROXY (8765) ==="
        mo_ai
        ;;
    web)
        echo "=== MỞ CỔNG WEBUI DASHBOARD (8080) ==="
        mo_web
        ;;
    kiem|--kiem|status)
        kiem
        ;;
    tat|--tat|stop)
        echo "=== TẮT TOÀN BỘ CÁC CỔNG ==="
        tat_cong
        ;;
    *)
        echo "Cách dùng: bash tools/mo_cong.sh [full|app|thu|ai|web|kiem|tat]"
        exit 2
        ;;
esac
