# 📘 SỔ TAY HƯỚNG DẪN TRA CỨU LỆNH TOÀN DIỆN — PATCHX & PUSHX

> Tài liệu tra cứu độc lập dành cho nhà phát triển, modder và kỹ sư kiểm thử an toàn APK trên Termux/Android.  
> Được biên soạn chi tiết theo **7 nhóm chức năng tối ưu**, bao gồm cú pháp, ví dụ thực tế và giải nghĩa tham số.

---

## 🧭 1. TỔNG QUAN & HAI ĐIỂM VÀO HỆ THỐNG

Bạn có thể sử dụng linh hoạt một trong hai lệnh sau từ bất kỳ thư mục nào trên Termux:

| Lệnh thực thi | Vai trò & Đặc điểm | Khi nào nên dùng |
|:---:|---|---|
| `patchx` | **Lõi hiện đại (Modern Core):** Tập trung vào phân tích ngữ nghĩa, Taint Flow, Fast In-place và các quy trình tự động hóa mới. | Khi phân tích sâu APK, quét Security Gates, vá in-place DEX/AXML. |
| `pushx` | **Bản kế thừa toàn diện (Legacy & Toolkit Bridge):** Bảo tồn 100% các lệnh cổ điển (`doctor`, `run`, `package`, `apk-full`, `webui`) đồng thời chuyển tiếp mượt mà sang 7 nhóm lệnh của `patchx`. | Điểm vào khuyên dùng hàng ngày; tích hợp đầy đủ cả cái cũ và cái mới. |

---

## 📑 2. BẢNG TRA CỨU NHANH THEO 7 NHÓM CHỨC NĂNG

### 🔍 NHÓM 1: TIẾP NHẬN & CHẨN ĐOÁN HỆ THỐNG
Dùng để khảo sát ban đầu, kiểm tra môi trường công cụ và trích xuất chứng chỉ mà không cần giải mã APK.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `intake` | `pushx intake <target.apk> [-o dir]` | Tiếp nhận APK/APKS/AAB, kiểm kê DEX/ABI/chữ ký (Zero-Extraction). |
| `capabilities` | `pushx capabilities` | Ghi nhận và kiểm tra năng lực công cụ môi trường (aapt2, java, adb, apktool). |
| `signature-cert` | `pushx signature-cert <target.apk>` | Trích xuất file chứng chỉ DER gốc và tính toán mã băm SHA-256 cert. |
| `selfcheck` | `pushx selfcheck` | Tự kiểm tra toàn diện module lõi và tính hợp lệ của kho patch. |
| `doctor` | `pushx doctor` | *(Lệnh kế thừa)* Chẩn đoán chi tiết phiên bản công cụ và các file APK mẫu. |

---

### 🧠 NHÓM 2: PHÂN TÍCH NGỮ NGHĨA SÂU & TAINT FLOW (ZERO-WORKKEY)
Trọng tâm đột phá của toolkit: Phân tích đồ thị gọi hàm (Call-Graph) và lần vết thanh ghi (Taint Flow) để tìm cổng logic bảo vệ mà **hoàn toàn không dựa vào từ khóa/tên hàm dễ bị R8 đổi tên**.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `analyze` | `pushx analyze <cay_smali> [-o report.json]` | Phân tích cây APK, phát hiện Packer, nghi vấn mã hóa chuỗi và **15+ Security Gates**. |
| `model` | `pushx model <cay_smali> [--v2] [--with-bodies]` | Tạo mô hình trung gian `app_model` (V1/V2) thể hiện đồ thị gọi hàm và điểm rẽ nhánh. |
| `semantic-plan` | `pushx semantic-plan <cay_smali> [muc_tieu]` | Lập kế hoạch ngữ nghĩa tự động theo mục tiêu can thiệp và điều kiện logic. |
| `plan-compile` | `pushx plan-compile <plan.json>` | Biên dịch kế hoạch ngữ nghĩa thành bản nháp transaction các khối can thiệp. |
| `plan-preflight` | `pushx plan-preflight <plan.json>` | Thẩm định tiền khả thi bản nháp transaction trước khi ghi đè vào file mã nguồn. |
| `behavior` | `pushx behavior <cay_smali>` | Phân tích hành vi tĩnh dựa trên 28 mẫu nhận diện ontology. |
| `targets` | `pushx targets <cay_smali>` | Liệt kê danh sách các hàm/lớp mục tiêu cần xem xét sửa đổi. |

---

### ⚡ NHÓM 3: ĐIỀU PHỐI PIPELINE HỢP NHẤT & TỰ ĐỘNG HÓA
Các luồng dây chuyền tự động hóa khép kín từ file APK đầu vào đến APK thành phẩm.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `pipeline` | `pushx pipeline <target.apk> --mode <MODE>` | **Bộ não điều phối thống nhất:** Hỗ trợ các mode `auto`, `intake`, `semantic`, `fast`, `behavior`, `native`, `combo`. |
| `behavior-pipeline`| `pushx behavior-pipeline <cay_smali>` | Luồng khép kín: detector $\rightarrow$ CFG $\rightarrow$ target $\rightarrow$ sinh hook Frida. |
| `gadget-pipeline` | `pushx gadget-pipeline <target.apk>` | Nhúng `libfrida-gadget.so` offline vào APK để chạy hook trên máy **không cần root**. |
| `smart-combo` | `pushx smart-combo <target.apk>` | Tự động sinh tổ hợp patch tối ưu dựa trên Active Learning từ lịch sử thành công. |

---

### 🚀 NHÓM 4: CAN THIỆP NHỊ PHÂN SIÊU TỐC IN-PLACE (<0.5S)
Can thiệp trực tiếp byte nhị phân bên trong tệp nén ZIP mà **không cần chạy `apktool`**, tiết kiệm 95% thời gian và pin trên Termux.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `fast-patch` | `pushx fast-patch <target.apk> [tuy_chon]` | Quy trình 1-Click: Vá DEX/AXML/ARSC in-place, gỡ chữ ký cũ và đóng gói siêu tốc. |
| `dex-patch` | `pushx dex-patch <classes.dex> [OLD=NEW]` | Thay chuỗi hoặc opcode bytecode DEX trực tiếp ở cấp độ byte. |
| `axml-patch` | `pushx axml-patch <AndroidManifest.xml> [OLD=NEW]` | Thay chuỗi trong AXML, hỗ trợ `--bypass-nsc` (bỏ SSL Pinning) và đổi quyền. |
| `arsc-patch` | `pushx arsc-patch <resources.arsc> [OLD=NEW]` | Phân tích cấu trúc String Pool và thay thế chuỗi tài nguyên in-place. |
| `apk-repack-fast` | `pushx apk-repack-fast <goc.apk> -o <out.apk>` | Đóng gói lại APK cực nhanh chỉ với các entry bị sửa đổi (Zero-Copy). |
| `macro-list` | `pushx macro-list [--registers N]` | Liệt kê danh mục Smali Macro sẵn có và kiểm tra tính an toàn thanh ghi. |

---

### 🛡️ NHÓM 5: NATIVE LAYER & FRIDA MEMORY HOOK
Chuyên trị các ứng dụng bảo vệ bằng thư viện C/C++ (`.so`) và can thiệp bộ nhớ RAM.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `native-sig-bypass`| `pushx native-sig-bypass <target.apk>` | Tự động quét và bypass mã băm SHA-256 cert trong các thư viện `.so`. |
| `start-scan` | `pushx start-scan <thu_muc_so>` | Quét toàn diện tất cả các file `.so` trong APK để tìm điểm nhạy cảm. |
| `rodata-find` | `pushx rodata-find <file.so> <chuoi>` | Tìm địa chỉ RVA của chuỗi nằm trong phân vùng `.rodata` hoặc `.data`. |
| `rodata-apply` | `pushx rodata-apply <file.so> <old> <new>` | Sửa chuỗi trực tiếp vào file `.so` (patch nhị phân vĩnh viễn, không cần Frida). |
| `rodata-patch` | `pushx rodata-patch <file.so> <chuoi>` | Sinh đoạn mã Frida để ghi đè chuỗi trên RAM lúc ứng dụng đang chạy. |
| `smart-scan` | `pushx smart-scan <file.so>` | Quét thông minh và xếp hạng chuỗi `.rodata` theo điểm tin cậy (Confidence). |
| `remote-observe` | `pushx remote-observe <package_name>` | Kết nối Frida theo dõi các cờ điều khiển logic ứng dụng từ xa. |
| `remote-patch` | `pushx remote-patch <package_name>` | Sinh patch ép cờ trạng thái thông qua RPC điều khiển từ xa. |
| `remote-map` | `pushx remote-map <package_name>` | Xuất bản đồ các cờ tính năng nhận diện được. |

---

### 📦 NHÓM 6: QUẢN TRỊ BỘ PATCH & KHUNG COMBO
Quản lý kho 68+ bộ patch chuẩn hóa, phân tích độ tương thích và ghép chuỗi patch.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `combo` | `pushx combo <thu_muc_patch>` | Phân tích và tạo các bộ gộp patch có độ tương thích cao. |
| `diff-apk` | `pushx diff-apk <apk1> <apk2>` | So sánh sự khác biệt giữa hai bản APK để tự sinh ra bộ patch tương ứng. |
| `suggest-apk` | `pushx suggest-apk <target.apk>` | Gợi ý chuỗi patch phù hợp nhất dựa trên đặc điểm cấu trúc APK. |
| `suggest-llm` | `pushx suggest-llm "yêu cầu"` | Gợi ý các bộ patch thích hợp theo ngôn ngữ tự nhiên. |
| `roadmap` | `pushx roadmap <target.apk>` | Sinh sơ đồ lộ trình thực thi chuỗi patch theo thứ tự logic. |
| `simulate` | `pushx simulate <cay_apk> <patch.zip>` | Mô phỏng áp patch lên cây mã nguồn để kiểm tra xung đột mà không lưu đè. |
| `smart-patch` | `pushx smart-patch <cay_apk>` | Sinh bản patch smali thông minh có khả năng chống chọi obfuscation. |
| `pairip-bypass` | `pushx pairip-bypass <cay_apk>` | Vô hiệu hóa lớp bảo vệ kiểm tra bản quyền PairIP. |

---

### 🛠️ NHÓM 7: KIỂM ĐỊNH CHẤT LƯỢNG & GIAO DIỆN ĐIỀU KHIỂN
Kiểm tra cú pháp, đo độ bao phủ, quản lý vòng đời bộ patch và giao diện người dùng.

| Lệnh | Cú pháp cơ bản | Mô tả chức năng |
|---|---|---|
| `apply` | `pushx apply <cay_apk> <patch.zip>` | Áp trực tiếp file patch (.zip) lên cây mã nguồn đã giải mã. |
| `audit` | `pushx audit <patch.zip>` | Kiểm tra kiến trúc, tính an toàn thanh ghi và chuẩn mực của patch. |
| `upgrade` | `pushx upgrade <patch.zip> -o <out_dir>`| Nâng cấp file patch cũ lên chuẩn cấu trúc v3 hiện đại. |
| `optimize` | `pushx optimize <patch.zip>` | Tối ưu hóa thứ tự các khối lệnh, loại bỏ các bước thừa trong patch. |
| `validate` | `pushx validate <cay_apk>` | Xác thực tính hợp lệ của cây mã nguồn (Smali, XML, cấu trúc DEX). |
| `dex-budget` | `pushx dex-budget <cay_apk>` | Ước lượng số lượng tham chiếu DEX (DEX refs) để tránh vượt quá 65.536 method. |
| `golden` | `pushx golden <cay_apk>` | Cổng thẩm định Golden Gate Build — tiêu chuẩn chất lượng cao nhất. |
| `ui` | `pushx ui` | Khởi động giao diện dòng lệnh TUI điều khiển tương tác. |
| `webui` | `pushx webui [--port 8787]` | Mở giao diện WebUI trực quan trên trình duyệt điện thoại. |
| `clean` | `pushx clean <thu_muc>` | Dọn dẹp sạch sẽ các tệp `.tmp`, `.bak` và thư mục rác sau khi patch. |

---

## 💡 3. HƯỚNG DẪN CÁC LUỒNG LÀM VIỆC MẪU (RECIPES)

### 🔹 Luồng 1: Tự động hóa thông minh 1-Click (Khuyên dùng nhất)
Khi bạn có một file APK mới và muốn hệ thống tự động làm mọi thứ từ phân tích, gỡ bảo vệ, vá in-place đến đóng gói:
```bash
pushx pipeline Apks/target.apk --mode auto -o outputs/target_patched.apk
```
*Hệ thống sẽ tự động chạy liên hoàn:*
1. Khảo sát cấu trúc tệp (Intake).
2. Dò tìm Security Gates bằng Taint Flow (Zero-Workkey).
3. Gỡ bỏ Network Security Config (bỏ SSL Pinning) trong AndroidManifest.xml.
4. Vá in-place các cờ điều khiển và đóng gói lại APK trong vòng vài giây.

---

### 🔹 Luồng 2: Phân tích chuyên sâu Zero-Workkey trên cây mã nguồn
Khi bạn đã giải mã một APK và muốn tìm các cổng logic quyết định bảo vệ (bản quyền, root, tamper, reflection):
```bash
pushx analyze outputs/apk/apk-trees/a_src
```
*Kết quả hiển thị:*
- Đồ thị gọi hàm (Call-Graph top 15).
- Danh sách 15+ Security Gates kèm mức độ tin cậy (`[85% CAO]`), nguồn Taint và gợi ý can thiệp (`INVERT_BRANCH` hoặc `RETURN_CONSTANT`).

---

### 🔹 Luồng 3: Can thiệp siêu tốc In-Place không qua giải mã (<0.5 giây)
Khi bạn muốn đổi nhanh một chuỗi kiểm tra hoặc vô hiệu hóa SSL Pinning trực tiếp trên file APK:
```bash
# Gỡ Network Security Config và thay chuỗi DEX
pushx fast-patch Apks/target.apk --dex-str "is_vip=true" -o Apks/target_fast.apk
```

---

### 🔹 Luồng 4: Nhúng Frida Gadget chạy trên máy không cần Root
Khi ứng dụng có logic kiểm tra phức tạp trên máy chủ và bạn muốn chạy kịch bản Frida trên thiết bị gốc không root:
```bash
pushx gadget-pipeline Apks/target.apk
```
*Sau khi cài đặt APK kết quả:* Ứng dụng sẽ tự động nạp `libfrida-gadget.so` và thực thi kịch bản `hook.js` ngay khi mở màn hình chính!

---

## 🎨 4. QUY CHUẨN MÀU SẮC HIỂN THỊ TRÊN MÀN HÌNH

Hệ thống sử dụng các mã màu chuẩn ANSI giúp bạn nhận diện tức thì tình trạng mã nguồn:
* 🔴 **Màu Đỏ (`RED`):** Cảnh báo nguy hiểm — Phát hiện Packer, kiểm tra Root, Shell đóng gói hoặc lỗi biên dịch.
* 🟡 **Màu Vàng (`YELLOW`):** Cảnh báo nghi vấn — Nghi mã hóa chuỗi (R8 Obfuscation), thanh ghi Taint Source đang theo dõi.
* 🟢 **Màu Xanh Lá (`GREEN`):** Trạng thái an toàn — Cổng bảo vệ có điểm tin cậy cao (`[85% CAO]`), đề xuất can thiệp thành công.
* 🔵 **Màu Xanh Dương (`BLUE`):** Đồ thị luồng — Đồ thị gọi hàm (Call-Graph), các lớp kế thừa và Entrypoint.
* 🟣 **Màu Tím (`MAGENTA`):** Trí tuệ ngữ nghĩa — Security Gates phát hiện bởi Zero-Workkey Taint Flow.
* 💠 **Màu Cyan (`CYAN`):** Khung điều hướng — Tên phương thức, tiêu đề nhóm lệnh và gợi ý thao tác.

---

> 📌 **Mẹo lưu trữ:** Bạn có thể mở tài liệu này bất cứ lúc nào trên Termux bằng lệnh:
> ```bash
> cat HUONG_DAN_LENH.md | less -R
> ```
