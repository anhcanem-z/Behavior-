# GEMINI.md — Bản Đồ Ánh Xạ Đối Chiếu Quy Tắc Cho Gemini CLI

> Mốc thời gian hệ thống: 2026-09-19 16:05:00 +07 · TZ Asia/Ho_Chi_Minh
> Bản đồ ánh xạ điều hướng thông minh theo mô hình 3 tầng (User phê duyệt 2026-09-19).
> Tệp này đóng vai trò là "Bản đồ chỉ mục ánh xạ". Mọi quy tắc chi tiết được định nghĩa duy nhất tại nguồn chuẩn. Khi gặp tình huống tương ứng, AI bắt buộc phải mở tệp gốc để đối chiếu trước khi hành động.

---

## 1. BẢNG KHẨU QUYẾT PHẢN XẠ NHANH (MỨC T1 - T3)

| STT | Khẩu Quyết Phản Xạ 1 Dòng | Mức Luật | Đường Dẫn Nguồn Chuẩn (Đối Chiếu) |
|:---:|:---|:---:|:---|
| 1 | 🟣 **CHỈ THỊ RÕ RÀNG**: Chỉ làm khi có chỉ thị đích danh. Mơ hồ ➔ KHÔNG ĐƯỢC LÀM, lập báo cáo phương án chờ duyệt. | T1 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19) |
| 2 | 🟣 **PHANH AN TOÀN T1**: Gặp bất thường / chưa chắc ➔ DỪNG NGAY, BẢO LƯU, BÁO CÁO 3 MỤC, CHỜ LỆNH. | T1 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19) |
| 3 | 🟣 **HAI QUY TẮC CỐT LÕI**: Phân định rạch ròi Toolkit và APK. TUYỆT ĐỐI CẤM TÁC ĐỘNG CHÉO. | T1 | [`toolkit.md`](file:///data/data/com.termux/files/home/_patchx/toolkit.md) & [`apk.md`](file:///data/data/com.termux/files/home/_patchx/apk.md) |
| 4 | 🔴 **RANH GIỚI PHẠM VI**: Trong `_patchx`: r=1, w=1. Mọi nơi khác: r=0, w=0. Vượt phạm vi phải xin phép. | T1 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#gi%E1%BB%9Bi-h%E1%BA%A1n-ph%E1%BA%A1m-vi-quy%E1%BB%81n--b%E1%BA%AFt-bu%E1%BB%99c-cho-m%E1%BB%8Di-cli-terminal-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17-si%E1%BA%BFt-l%E1%BA%A7n-2-l%C3%BAc-2026-09-17-1007) |
| 5 | 🔴 **AN TOÀN DỮ LIỆU**: Cấm xóa/sửa khi chưa nén sao lưu. Cấm tự ý chạy test nặng khi chưa có lệnh. | T1 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#lu%E1%BA%ADt-quy-t%E1%BA%AFc-c%E1%BB%A7a-user--hi%E1%BB%87u-l%E1%BB%B1c-theo-t%E1%BA%A7ng--thang-%C4%91i%E1%BB%83m-l%C3%BD-do-m%E1%BB%91c-510--ch%E1%BA%BF-t%C3%A0i) |
| 6 | 🟡 **ĐỊNH DANH ĐA NEO**: Mọi báo cáo/kết luận phải có >=3 neo (thời gian thật, mã phiên, git, sha256). | T2 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#%C4%91%E1%BB%8Bnh-danh-%C4%91a-neo--kh%C3%B4ng-d%C3%B9ng-ri%C3%AAng-th%E1%BB%9Di-gian-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17) |
| 7 | 🟡 **TIÊU CHÍ NGHIỆM THU**: 12 tiêu chí TC-01..TC-12 (0 trùng lặp, 0 lệch bản sao, 100% có neo). | T2 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#6-ti%C3%AAu-ch%C3%AD-%C4%91%E1%BA%A1t-100-tc-01-%C4%91%E1%BA%BFn-tc-12) |
| 8 | 🟡 **BÁO CÁO PHÁT ÂM (TTS)**: Luôn phát âm qua `python3 tools/speak.py` và có khối TÓM TẮT ĐỌC NHANH. | T2 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#10-quy-t%E1%BA%AFc-b%C3%A1o-c%C3%A1o-ph%C3%A1t-%C3%A2m-tts-tr%C3%ACnh-b%C3%A0y-6-m%C3%A0u--ki%E1%BB%83m-th%E1%BB%AD) |
| 9 | 🟢 **TRÌNH BÀY 6 MÀU**: Vận dụng 6 màu (🔴 🟡 🟢 🔵 🟣 💠); CẤM dùng thuật ngữ chuyên môn toàn cục. | T3 | [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#10-quy-t%E1%BA%AFc-b%C3%A1o-c%C3%A1o-ph%C3%A1t-%C3%A2m-tts-tr%C3%ACnh-b%C3%A0y-6-m%C3%A0u--ki%E1%BB%83m-th%E1%BB%AD) |
| 10 | 🟢 **GHI NHẬN KINH NGHIỆM**: Cập nhật bài học sau mỗi phiên vào `AGENTS_TRANG_THAI.md` & `KINH_NGHIEM_HOC_HOI.md`. | T2 | [`AGENTS_TRANG_THAI.md`](file:///data/data/com.termux/files/home/_patchx/AGENTS_TRANG_THAI.md) |

---

## 2. BẢN ĐỒ ÁNH XẠ ĐỐI CHIẾU CHI TIẾT KHI CẦN TRA CỨU

Khi thực hiện nhiệm vụ cụ thể, Gemini CLI bắt buộc phải đối chiếu đúng mục tương ứng:

1. **Khi nhận chỉ thị mới từ User**:
   - Đối chiếu: [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19)
   - Kiểm tra: Có đủ 6 điều kiện thực hiện chưa? Nếu User ra lệnh rộng (như "thay đổi toàn bộ hệ thống"), đã lập bản đồ công việc và phân tích giải pháp tối ưu chưa?
2. **Khi phát triển, sửa đổi, nâng cấp Toolkit**:
   - Đối chiếu: [`toolkit.md`](file:///data/data/com.termux/files/home/_patchx/toolkit.md)
   - Nhận thức: Tối ưu từ đồng bộ đến đồng nhất. Nếu gặp bất thường ➔ Kích hoạt Phanh T1.
3. **Khi sửa, phân tích, xử lý APK / Target**:
   - Đối chiếu: [`apk.md`](file:///data/data/com.termux/files/home/_patchx/apk.md)
   - Nhận thức: Bắt buộc dùng Module Behavior, không sửa nhầm sang Toolkit.
4. **Khi cần chạm đến file ngoài thư mục `_patchx`**:
   - Đối chiếu: [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#gi%E1%BB%9Bi-h%E1%BA%A1n-ph%E1%BA%A1m-vi-quy%E1%BB%81n--b%E1%BA%AFt-bu%E1%BB%99c-cho-m%E1%BB%8Di-cli-terminal-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17-si%E1%BA%BFt-l%E1%BA%A7n-2-l%C3%BAc-2026-09-17-1007)
   - Quy trình: Đo tỉ lệ gần giống (>= 90%), báo đường dẫn tuyệt đối, xin phép User và ghi sổ neo.
5. **Khi có nghi vấn về xung đột hoặc lỗi vi phạm**:
   - Đối chiếu: [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ki%E1%BB%83m-tra-nhanh-tr%C6%B0%E1%BB%9Bc-khi-l%C3%A0m--x%E1%BB%AD-l%C3%BD-khi-vi-ph%E1%BA%A1m-b%E1%BA%AFt-bu%E1%BB%99c)
   - Thực hiện: 3 câu hỏi kiểm tra nhanh; Thang điểm lý do 10 mức (mốc 5/10).
6. **Khi nghiệm thu và đóng phiên**:
   - Đối chiếu: [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#6-ti%C3%AAu-ch%C3%AD-%C4%91%E1%BA%A1t-100-tc-01-%C4%91%E1%BA%BFn-tc-12) & [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#%C4%91%E1%BB%8Bnh-danh-%C4%91a-neo--kh%C3%B4ng-d%C3%B9ng-ri%C3%AAng-th%E1%BB%9Di-gian-user-y%C3%AAu-c%E1%BA%A7u-2026-09-17)
   - Thực hiện: Kiểm tra đủ 12 tiêu chí TC-01..TC-12, chốt bản ghi `dong-moc` vào sổ `ledger.jsonl`.
