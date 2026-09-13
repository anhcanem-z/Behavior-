# AGENTS.md — patchx toolkit (Reverse APK / Smali / Java) — bản behavior + Frida

Tài liệu tổng hợp tối ưu để mọi phiên Codex sau này nắm ngay bối cảnh, quy
trình, lệnh, mốc đo được và việc tiếp theo — không cần đọc lại lịch sử.
File trạng thái tổng hợp duy nhất: `AGENTS_TRANG_THAI.md`.

## GIỚI HẠN PHẠM VI TOÀN CỤC (bắt buộc — ưu tiên cao nhất)

- **TOÀN BỘ Codex, mọi phiên, mọi công cụ — quy tắc chung cho cả hệ thống**:
  chỉ được hoạt động trong phạm vi **thư mục làm việc hiện tại (working
  directory) và các thư mục con của nó**.
- Trong dự án này, thư mục làm việc là `_patchx` (cùng mọi thư mục con như
  `upgraded/`, `patchx_core/`, `outputs/`, `Apks/`...). Nếu Codex được mở ở
  thư mục khác thì phạm vi hoạt động là thư mục đó + thư mục con.
- Trong phạm vi thư mục làm việc + thư mục con: được **đọc, ghi, thao tác đầy
  đủ**.
- **Ngoài phạm vi** thư mục làm việc + thư mục con (ví dụ
  `/storage/emulated/0/Modder Hub/`, `patch1/` worklist, `Download/`,
  `/storage/emulated/0` nói chung): **CHỈ ĐƯỢC ĐỌC (read-only)** — không ghi,
  không sửa, không xóa, không tạo file, không chạy lệnh gây thay đổi dữ liệu
  (rm, mv, install, cài đặt, ghi file/log ngoài phạm vi...).
- Muốn **ghi/tác động** ngoài phạm vi: phải được **người dùng yêu cầu rõ**;
  chỉ tác động đúng phạm vi được yêu cầu và trình bày trước khi thực hiện.
- Script `tools/status_report.py` đã tự giới hạn trong `_patchx` (chỉ chạy khi
  `cwd` nằm trong thư mục làm việc toolkit, chỉ đọc dữ liệu nội bộ).

## ƯU TIÊN SỐ 1 KHI MỞ CODEX (bắt buộc)

- **Bước đầu tiên của mọi phiên**: quét ngay `AGENTS_TRANG_THAI.md` — file
  trạng thái tổng hợp duy nhất — để nạp toàn bộ dữ liệu hiện trạng, rồi mới
  làm việc khác.
- Sau khi nạp, kiểm tra toolkit có thay đổi không (mtime báo cáo, số liệu mới
  trong `outputs/audit/audit.json`, `outputs/baseline/metrics.json`,
  `outputs/**/*`, `outputs/apk/apk-patch/`, `outputs/behavior/`).
- Nếu có thay đổi: **cập nhật ngay `AGENTS_TRANG_THAI.md`** theo quy tắc tự
  cập nhật trong mục 0 của file đó, trước khi xử lý yêu cầu của người dùng.
- **Báo cáo tự động khi online**: chỉ khi phiên Codex đang nằm trong thư mục
  toolkit (`cwd` trong `_patchx`) — chạy ngay `python3 tools/status_report.py`
  và trình cho người dùng phần **A. Thông tin cơ bản** + **B. Thành phần cần
  bổ sung** (kèm mục cần cập nhật trong `AGENTS_TRANG_THAI.md`). Nếu Codex
  mở ngoài thư mục toolkit thì không báo tình trạng toolkit.

## Quy ước bắt buộc

- Tài liệu, bình luận, thông báo viết bằng **tiếng Việt**.
- Danh từ/chuỗi trong mã nguồn (khóa patch, mẫu regex, nội dung smali/XML,
  tên biến, tên tệp) **giữ nguyên gốc** — không dịch, không đổi, tránh lỗi
  cấu trúc khi áp patch.
- Bộ sưu tập gốc không bị sửa; mọi chuẩn hóa ghi ra thư mục mới (`upgraded/`,
  `outputs/`, ...).
- Regex lỗi/không khớp chỉ cảnh báo, không tự sửa nội dung patch.
- `EXECUTE_DEX` mặc định bỏ qua; chỉ chạy với `--dex-runner` an toàn.
- Mọi kết luận phải có số liệu đo được (test, simulate, coverage).
- 3 file hướng dẫn lệnh `HUONG_DAN_LENH.txt`, `HUONG_DAN_BEHAVIOR_FRIDA.txt`,
  `HUONG_DAN_GADGET.txt` là tài liệu ưu tiên GIỮ LẠI — luôn đồng bộ đường dẫn
  thư mục khi cấu trúc đổi.

## QUY TẮC KIỂM THỬ (bắt buộc — yêu cầu từ User)

- **Tuyệt đối KHÔNG tự ý chạy kiểm thử** (`tests/run_tests.py`, `simulate`, `golden`, `ci`, `baseline`, v.v.) khi không thật sự cần thiết.
- **Chỉ được sử dụng kiểm thử khi ĐÃ ĐƯỢC SỰ ĐỒNG Ý HOẶC YÊU CẦU TRỰC TIẾP TỪ USER**.
- **Ưu tiên rà soát tĩnh**: Phân tích logic, kiểm tra cú pháp, đọc hiểu mã nguồn và đối chiếu cấu trúc; hạn chế tối đa việc chiếm dụng CPU, bộ nhớ và gây gián đoạn phiên làm việc trên môi trường Termux.

## QUY TẮC PHÁT ÂM BÁO CÁO QUA GIỌNG NÓI (TTS) (bắt buộc — vĩnh viễn)

- **MỌI báo cáo kết quả, kết luận, tóm tắt trạng thái hoặc thông báo hoàn thành nhiệm vụ gửi cho User** đều phải đồng thời được phát âm qua giọng nói tiếng Việt bằng lệnh:
  `python3 tools/speak.py "Nội dung tóm tắt báo cáo"` (hoặc `termux-tts-speak -l vi -r 1.0 "..."`).
- **Yêu cầu phát âm**: Tóm tắt ngắn gọn, gãy gọn, cô đọng nội dung quan trọng nhất của câu trả lời để User nghe được ngay mà không cần đọc màn hình.
- **Tính vĩnh viễn**: Mọi phiên làm việc hiện tại và tương lai của Codex/AI đều bắt buộc tuân thủ quy tắc này.

## GHI NHẬN KINH NGHIỆM SAU MỖI PHIÊN XỬ LÝ (bắt buộc)

- MỌI thông tin/dữ liệu thu được khi xử lý file (smali, APK, lib .so, script
  Frida, log VM/Logcat, UI thật, endpoint API, hành vi obfuscation...) là
  NGUỒN KINH NGHIỆM QUÝ cho các phiên sau — phải ghi NGAY TRONG PHIÊN, không
  chờ phiên sau.
- Ghi vào `AGENTS_TRANG_THAI.md`: thêm mốc vào mục 8 (lịch sử) + bổ sung bài
  học vào mục 9 (bản đồ truy vết, giới hạn đã chứng minh, môi trường) + cập
  nhật dòng "Ngày cập nhật" ở đầu file.
- Task có trace riêng thì ghi luôn vào file trace tương ứng (ví dụ
  `outputs/behavior/fake_server/TRACE_HI_TRANSLATE.md`) — nếu chưa có, tạo
  mới theo mẫu file này.
- Mỗi bypass/patch đã thử (thành công LẪN thất bại) ghi tối thiểu: đã làm gì,
  hook/patch ở đâu (class/method smali hoặc RVA .so), kết quả thật (log/UI/
  exit code), vì sao fail — để phiên sau không thử lại đường chết.
- Phát hiện mới sau MỖI lần xử lý phải được cập nhật thêm vào file trạng thái
  trước khi kết thúc phiên (nguyên tắc "luôn luôn cập nhật phát hiện mới").


## QUY TẮC HỌC HỎI & ÁP DỤNG KINH NGHIỆM TỪ INTERNET (bắt buộc)

- **Khi User yêu cầu tìm hiểu / học hỏi kinh nghiệm trên Internet**:
  1. Chủ động tìm kiếm, phân tích sâu các cơ chế, kỹ thuật mới từ internet (thay đổi hành vi, dữ liệu, cấu hình, lệnh, can thiệp SDK, bypass RASP...).
  2. **Tự động đánh giá và sàng lọc**: Chỉ chọn các hướng **tốt nhất, khả thi nhất, phù hợp nhất với kiến trúc toolkit `_patchx` và môi trường Termux / Android** (tài nguyên giới hạn, non-root, Python 3.14, Fast-Path, Smali AST, Frida Gadget).
  3. **Lưu trữ vào file riêng duy nhất**: Toàn bộ các kinh nghiệm được chọn lọc phải được ghi/bổ sung có cấu trúc vào file `KINH_NGHIEM_HOC_HOI.md` (nằm ở thư mục gốc workspace `_patchx`).
- **Khi User yêu cầu áp dụng kinh nghiệm đã học**:
  1. Tự động đọc và tổng hợp toàn bộ các kinh nghiệm đã tích lũy trong `KINH_NGHIEM_HOC_HOI.md`.
  2. Rà soát, đối chiếu lại với các bài học kinh nghiệm xử lý file, fix lỗi thực tế (như lỗi Overlapped Zip, Sandbox Termux, AXML/ARSC packing...) và hiện trạng nâng cấp của toolkit.
  3. Lập **Bản đánh giá toàn diện & Đề xuất giải pháp hợp lý** (phân tích mức độ ảnh hưởng, tính tương thích, mã nguồn dự kiến) trình User duyệt trước khi thực thi code.


## ĐỒNG BỘ TỰ ĐỘNG KHI THÊM TÍNH NĂNG / NÂNG CẤP (bắt buộc)

MỖI khi thêm tính năng mới, sửa lệnh, hoặc nâng cấp module — phải cập nhật
ĐỒNG THỜI các module bị ảnh hưởng (không để lệch):

- **Code**: module mới trong `patchx_core/` hoặc `patchx_core/behavior/` →
  đăng ký vào `patchx_core/cli.py` (parser lệnh) nếu là lệnh; module behavior
  mới phải có test tương ứng trong `tests/run_tests.py`.
- **CLI entry**: lệnh mới/sửa trong `cli.py` → kiểm tra `patchx` script và
  `patchx_toolkit.py` (nếu là lệnh orchestrator) còn khớp; cập nhật
  `HUONG_DAN_LENH.txt` / `HUONG_DAN_BEHAVIOR_FRIDA.txt` / `HUONG_DAN_GADGET.txt`
  nếu thuộc nhóm tương ứng.
- **Từ điển hành vi**: hành vi mới học được (kho `outputs/behavior/discovered/`)
  → nếu muốn dùng vĩnh viễn, merge vào `SMART_BEHAVIORS` trong
  `patchx_core/behavior/smart_ontology.py`; `behavior_learner` tự ghi kho khi
  quét, không sửa từ điển gốc.
- **Test**: mọi thay đổi code → chạy test nhóm liên quan trước khi kết luận;
  cập nhật số liệu thật vào `AGENTS_TRANG_THAI.md` (mục 0.2, mục 8).
- **Cấu trúc thư mục**: thay đổi đường dẫn → cập nhật `OPERATIONS/NAVIGATION.json`,
  `outputs/README.md`, 3 file `HUONG_DAN_*.txt` (đường dẫn thư mục).
- **Đóng gói**: sau khi thay đổi module → tạo bản `dist/` mới bằng
  `patchx package` khi cần phát hành.

Kiểm tra đồng bộ tự động (chạy sau mỗi thay đổi lớn):

    python3 tools/sync_modules.py

Script rà: lệnh `cli.py` ↔ tài liệu hướng dẫn, module behavior ↔ test,
kho hành vi đã học ↔ từ điển gốc, mtime code ↔ `AGENTS_TRANG_THAI.md` —
in thiếu sót cần bổ sung (không tự sửa file).


## Vị trí dữ liệu quan trọng

- Bộ làm việc chính: `upgraded/` — **60 zip chuẩn hóa** (nguồn: bộ gốc
  "1. PATCH others" đã nâng cấp; `patchx_index.json` + `patchx_report.md`
  lưu trong `outputs/scan/`).
- Toolkit: `patchx_toolkit.py` (doctor/run/package/list/session/apk-plan/
  apk-test/apk-fix-res/apk-patch/apk-debug/apk-build/apk-full/apk-runtime/
  bench-scan/plan-ui/webui/install-deps); bản phân phối: `dist/`.
- APK đầu vào: `Apks/` — 5 APK (Live Translator 172M, Mango Translate 91M,
  app.apk 79M, app.objection.apk 71M, dich.apk 122M).
- Cây giải mã: `outputs/apk/apk-trees/` (app — 709M; thư mục split rỗng đã xóa).
- APK build nhanh: `outputs/apk/apk-build/`; APK đã patch:
  `outputs/apk/apk-patch/` (keystore debug + APK ký).
- Behavior + Frida: `patchx_core/behavior/` (detector, target, cfg, ontology,
  model, patcher, pipeline, gadget_pipeline, frida_generator,
  crypto_interceptor, remote_controller, flows); artifact tại
  `outputs/behavior/` + `outputs/behavior/gadget/` (APK nhúng gadget,
  libgadget.so, gadget_debug.keystore).
- Cache quét APK: `outputs/cache/scan_*.json` (theo hash cây, nạp lại ~0s).
- Kho combo thành công: `outputs/combos/combos_success.json` (1 lượt ghi
  2026-08-20); combo sinh ra tại `combos/`, `combos_auto/` (thư mục gốc).
- Kho tri thức học hỏi Internet: `KINH_NGHIEM_HOC_HOI.md` (lưu trữ có cấu trúc các kinh nghiệm can thiệp hành vi, cấu hình, lệnh và SDK đã sàng lọc).
- Hook điều khiển thu thập dữ liệu từ xa: `hook_remote_data_control/`.
- Docs lịch sử: `NGU_CANH.md`, `UPGRADE_PLAN_V3.md`, `EVALUATION.md`.
- Script dev (giữ ở thư mục gốc, không đóng gói): `sync_patchx.py`,
  `sync_imports.py`, `upgrade_behavior.py`.
- Backup: `.patchx/backup/` (bản gốc apktool), `outputs/backup/`
  (bản lưu trước khi đồng bộ cấu trúc `pre_sync_20260821/`).

## Lệnh cốt lõi

Chạy từ `_patchx`:

| Nhóm | Lệnh |
|------|------|
| Behavior/Frida | `patchx behavior CÂY` (smali), `targets CÂY`, `behavior-pipeline CÂY -o outputs/behavior`, `gadget-pipeline APK -o outputs/behavior/gadget`, `remote-map CÂY --flow/--dataflow`, `remote-patch`, `remote-observe --hook outputs/behavior/generated_hook.js`, `rodata-find FILE.SO --string CHUỖI`, `rodata-patch FILE.SO --string CHUỖI --new CHUỖI_MỚI [--offset RVA] [--mode inline/pointer/both]`, `rodata-apply FILE.SO --string CHUỖI --new CHUỖI_MỚI`, `rodata_bypass_main.py FILE.SO --flow static\|dynamic ...` (module + main riêng) |
| Quét .so thông minh | `patchx smart-scan FILE.SO [--min-risk N] [--show-noise] [--behaviors]` (1 file .so — lọc nhiễu + data-flow + xác thực chéo + Confidence 0-100), `patchx start-scan APK\|THƯ_MỤC\|FILE.SO [--abi ...]` (start-scan = native .so HÀNG LOẠT; behavior = smali); từ điển hành vi: `patchx_core/behavior/smart_ontology.py` (`--behaviors` để in) |
| Quét & kiểm tra | `patchx scan KHO`, `index KHO -o outputs/scan`, `dupes KHO`, `manifest KHO`, `report KHO`, `audit KHO`, `selfcheck`, `test`, `menu [--list/--goal/--run]` (danh sách chức năng chọn pipeline) |
| Nâng cấp | `patchx upgrade .. -o upgraded`, `optimize .. -o optimized`, `combo .. --only <năng-lực> -o ...` |
| Đo | `patchx coverage PATCH CÂY`, `suggest`, `roadmap .. CÂY -o outputs/roadmap`, `simulate .. -o outputs/simulate` |
| Phân tích | `patchx analyze CÂY`, `model CÂY --v2`, `semantic-plan CÂY PLAN --verbose`, `plan-compile`, `plan-preflight`, `acceptance`, `knowledge`, `diff-apk GỐC MOD` |
| CI | `patchx ci KHO -o outputs/ci`, `golden -o outputs/golden`, `baseline capture --dir outputs/baseline` |
| Áp | `patchx apply PATCH... CÂY` (backup + idempotent, có `--dry-run`) |
| Toolkit | `python3 patchx_toolkit.py doctor / run / package / list / session / apk-plan / apk-test / apk-fix-res / apk-patch / apk-debug / apk-build / apk-full / apk-runtime / bench-scan / plan-ui / webui / install-deps` |

Mọi lệnh ghi báo cáo đều mặc định vào `outputs/<module>/` (xem
`outputs/README.md`); vẫn ghi đè bằng `-o` nếu cần.

## Luồng chuẩn

1. `scan`/`index` → xem bộ sưu tập có gì.
2. `audit` → phát hiện lỗi kiến trúc từng patch.
3. `upgrade` → chuẩn hóa; `optimize` → gộp patch cùng mục tiêu.
4. `combo` → gộp patch bổ trợ theo họ chức năng + class-link.
5. `coverage`/`roadmap`/`apk-plan` → đo trên APK thật, xếp hạng.
6. `apply` → áp lên cây APK đã giải mã (`outputs/apk/apk-trees/`).
7. `apk-build`/`apk-full` → build → sign → verify (xem hướng dẫn chi tiết).

## Trạng thái hiện tại (tóm tắt — chi tiết trong AGENTS_TRANG_THAI.md)

- `selfcheck`: **8/8 module OK, 60 patch đọc được, 0 lỗi** (2026-08-21).
- Test suite: **chưa chạy hết** — dừng ở `test_bypass_advisor` do lệch schema
  key có dấu/không dấu (`cách_công_cụ` trong test vs `cach_cong_cu` trong
  code) — lỗi CÓ SẴN của bản này; mốc cũ: 52/52 (14/08), 174/174 (16/08).
- Đã dọn cache mô phỏng cũ schema (TMP/patchx_sim_cache) 2026-08-21.
- Cấu trúc `outputs/` đã thiết lập + đồng bộ source 2026-08-21 (backup
  `outputs/backup/pre_sync_20260821/`).
- Lưu ý: lệnh `webui` có trong toolkit nhưng thư mục `webui/` chưa tồn tại
  trong bản này — cần bổ sung khi dùng.

## Việc tiếp theo (ưu tiên)

1. Chạy lại test sau khi sửa schema lệch (`cách_công_cụ`/`cach_cong_cu`) để
   có mốc test thật cho file trạng thái.
2. Quyết định xóa/giữ dữ liệu nặng: `Apks/` (1.3G), `frida-termux-build/`
   (117M), `libgadget.so` gốc (25M, trùng bản trong outputs/behavior/gadget/).
3. Bổ sung `webui/` nếu cần dùng giao diện web.
4. Chạy `package` để tạo bản phân phối `dist/` đầu tiên.
