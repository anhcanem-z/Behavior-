#!/data/data/com.termux/files/usr/bin/bash
# Script tự động reset và bật lại tính năng dịch phụ đề và chia sẻ toàn màn hình sau mỗi 2 phút 40 giây (160s)
python3 "$(dirname "$0")/auto_session_reset.py" "$@"
