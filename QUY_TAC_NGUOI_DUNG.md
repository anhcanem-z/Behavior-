# QUY_TAC_NGUOI_DUNG.md — Tổng Hợp Quy Tắc Bắt Buộc Của User Cho PatchX Toolkit

> Cập nhật: 2026-09-19 16:05:00 +07 · Áp dụng bắt buộc cho mọi Terminal CLI, Agent và AI (Codex, Claude, Gemini, OpenCode).
> Mô hình 3 tầng: Nguồn chuẩn duy nhất ➔ Quy tắc chuyên biệt ➔ Bản đồ ánh xạ đối chiếu (User phê duyệt 2026-09-19).

---

<!-- PATCHX-TIME:BEGIN -->
## MỐC THỜI GIAN HIỆN TẠI & NGUYÊN TẮC ĐO THỰC
- **Mốc hệ thống**: `2026-09-19 16:05:00 +07` · epoch `1789808700` · TZ `Asia/Ho_Chi_Minh`
- **Quy tắc bắt buộc**: Không suy đoán ngày giờ; chạy lệnh `date '+%F %T %Z'` trước khi ghi log, đặt tên file hoặc đóng mốc báo cáo. Mọi kết luận phải kèm số liệu đo được thực tế.
<!-- PATCHX-TIME:END -->

---

## 1. BẢNG KHẨU QUYẾT PHẢN XẠ NHANH (MỨC T1 - T3)

| STT | Khẩu Quyết Phản Xạ 1 Dòng | Mức Luật | Đường Dẫn Nguồn Chuẩn (Đối Chiếu) |
|:---:|:---|:---:|:---|
| 1 | 🟣 **CHỈ THỊ RÕ RÀNG**: Chỉ làm khi có chỉ thị đích danh. Mơ hồ ➔ KHÔNG ĐƯỢC LÀM, lập báo cáo phương án chờ duyệt. | T1 | [Mục Chỉ Thị Rõ Ràng Mới Được Làm](#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19) |
| 2 | 🟣 **PHANH AN TOÀN T1**: Gặp bất thường / chưa chắc ➔ DỪNG NGAY, BẢO LƯU, BÁO CÁO 3 MỤC, CHỜ LỆNH. | T1 | [Mục Phanh An Toàn T1](#4-c%C6%A1-ch%E1%BA%BF-phanh-an-to%C3%A0n-t1-khi-g%E1%BA%B7p-b%E1%BA%A5t-th%C6%B0%E1%BB%9Dng--ch%C6%B0a-ch%E1%BA%AFc) |
| 3 | 🟣 **HAI QUY TẮC CỐT LÕI**: Phân định rạch ròi Toolkit và APK. TUYỆT ĐỐI CẤM TÁC ĐỘNG CHÉO. | T1 | [`toolkit.md`](file:///data/data/com.termux/files/home/_patchx/toolkit.md) & [`apk.md`](file:///data/data/com.termux/files/home/_patchx/apk.md) |
| 4 | 🔴 **RANH GIỚI PHẠM VI**: Trong `_patchx`: r=1, w=1. Mọi nơi khác: r=0, w=0. Vượt phạm vi phải xin phép. | T1 | [Mục Giới Hạn Phạm Vi Quyền](#gi%E1%BB%9Bi-h%E1%BA%A1n-ph%E1%BA%A1m-vi-quy%E1%BB%81n--b%E1%BA%AFt-bu%E1%BB%99c-cho-m%E1%BB%8Di-cli-terminal-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17-si%E1%BA%BFt-l%E1%BA%A7n-2-l%C3%BAc-2026-09-17-1007) |
| 5 | 🔴 **AN TOÀN DỮ LIỆU**: Cấm xóa/sửa khi chưa nén sao lưu. Cấm tự ý chạy test nặng khi chưa có lệnh. | T1 | [Mục Luật Quy Tắc Của User](#lu%E1%BA%ADt-quy-t%E1%BA%AFc-c%E1%BB%A7a-user--hi%E1%BB%87u-l%E1%BB%B1c-theo-t%E1%BA%A7ng--thang-%C4%91i%E1%BB%83m-l%C3%BD-do-m%E1%BB%91c-510--ch%E1%BA%BF-t%C3%A0i) |
| 6 | 🟡 **ĐỊNH DANH ĐA NEO**: Mọi báo cáo/kết luận phải có >=3 neo (thời gian thật, mã phiên, git, sha256). | T2 | [Mục Định Danh Đa Neo](#%C4%91%E1%BB%8Bnh-danh-%C4%91a-neo--kh%C3%B4ng-d%C3%B9ng-ri%C3%AAng-th%E1%BB%9Di-gian-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17) |
| 7 | 🟡 **TIÊU CHÍ NGHIỆM THU**: 12 tiêu chí TC-01..TC-12 (0 trùng lặp, 0 lệch bản sao, 100% có neo). | T2 | [Mục Tiêu Chí Đạt 100%](#6-ti%C3%AAu-ch%C3%AD-%C4%91%E1%BA%A1t-100-tc-01-%C4%91%E1%BA%BFn-tc-12) |
| 8 | 🟡 **BÁO CÁO PHÁT ÂM (TTS)**: Luôn phát âm qua `python3 tools/speak.py` và có khối TÓM TẮT ĐỌC NHANH. | T2 | [Mục Quy Tắc Báo Cáo Phát Âm](#10-quy-t%E1%BA%AFc-b%C3%A1o-c%C3%A1o-ph%C3%A1t-%C3%A2m-tts-tr%C3%ACnh-b%C3%A0y-6-m%C3%A0u--ki%E1%BB%83m-th%E1%BB%AD) |
| 9 | 🟢 **TRÌNH BÀY 6 MÀU**: Vận dụng 6 màu (🔴 🟡 🟢 🔵 🟣 💠); CẤM dùng thuật ngữ chuyên môn toàn cục. | T3 | [Mục Quy Tắc Trình Bày 6 Màu](#10-quy-t%E1%BA%AFc-b%C3%A1o-c%C3%A1o-ph%C3%A1t-%C3%A2m-tts-tr%C3%ACnh-b%C3%A0y-6-m%C3%A0u--ki%E1%BB%83m-th%E1%BB%AD) |
| 10 | 🟢 **GHI NHẬN KINH NGHIỆM**: Cập nhật bài học sau mỗi phiên vào `AGENTS_TRANG_THAI.md` & `KINH_NGHIEM_HOC_HOI.md`. | T2 | [`AGENTS_TRANG_THAI.md`](file:///data/data/com.termux/files/home/_patchx/AGENTS_TRANG_THAI.md) |

---


---

## 3. HAI QUY TẮC CỐT LÕI ƯU TIÊN CẤP CAO NHẤT: TOOLKIT.MD & APK.MD
Hai file `toolkit.md` và `apk.md` là **HAI QUY TẮC CỐT LÕI CÓ MỨC ƯU TIÊN CAO NHẤT TOÀN HỆ THỐNG**:
- **Phát triển Toolkit** ([`toolkit.md`](file:///data/data/com.termux/files/home/_patchx/toolkit.md)): Áp dụng khi Toolkit là đối tượng trực tiếp được phân tích, sửa đổi, nâng cấp.
- **Sửa và xử lý APK/Target** ([`apk.md`](file:///data/data/com.termux/files/home/_patchx/apk.md)): Áp dụng khi APK, App, cây APK hoặc Target là đối tượng phân tích, kiểm thử hoặc xử lý.
- **Nguyên tắc phân định bắt buộc**: AI bắt buộc nhận diện rõ nhiệm vụ; **TUYỆT ĐỐI KHÔNG TÁC ĐỘNG CHÉO**. Gặp bất thường ➔ Kích hoạt Cơ chế Phanh T1.

---


---


---


---


---


---


---

## 10. QUY TẮC BÁO CÁO PHÁT ÂM (TTS), TRÌNH BÀY 6 MÀU & KIỂM THỬ
1. **Báo cáo phát âm qua giọng nói (TTS)**: MỌI báo cáo kết quả/kết luận gửi User phải đồng thời phát âm qua `python3 tools/speak.py "..."` kèm khối `> [!TIP] TÓM TẮT ĐỌC NHANH (TTS)` ở đầu câu trả lời.
2. **Quy chuẩn 6 màu sắc trình bày**:
   - 🔴 Đỏ (RED): Nguy hiểm, lỗi, vi phạm quy tắc.
   - 🟡 Vàng (YELLOW): Cảnh báo nghi vấn, điểm cần chú ý.
   - 🟢 Xanh lá (GREEN): An toàn, thành công, đạt 100%.
   - 🔵 Xanh dương (BLUE): Đồ thị luồng, cấu trúc tệp, điểm vào.
   - 🟣 Tím (MAGENTA): Trí tuệ ngữ nghĩa, quy tắc tối cao.
   - 💠 Cyan (CYAN): Khung điều hướng, gợi ý thao tác.
3. **CẤM DÙNG THUẬT NGỮ CHUYÊN MÔN TOÀN CỤC**: Chuyển toàn bộ sang tiếng Việt thông dụng, mộc mạc.
4. **Quy tắc kiểm thử**: Tuyệt đối KHÔNG tự ý chạy kiểm thử nặng (`tests/run_tests.py`, `simulate`...). Chỉ chạy khi có yêu cầu trực tiếp từ User.
5. **Ghi nhận kinh nghiệm**: Ghi nhận bài học sau mỗi phiên vào `AGENTS_TRANG_THAI.md` và `KINH_NGHIEM_HOC_HOI.md`.
