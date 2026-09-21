# QUY TẮC SỬA VÀ XỬ LÝ APK/TARGET

> **Mức ưu tiên:** Cao nhất, ngang với `toolkit.md`  
> **Phạm vi:** Chỉ áp dụng khi APK, App, cây APK hoặc Target là đối tượng được phân tích, kiểm thử, sửa đổi hoặc xử lý  
> **Trạng thái:** Bắt buộc tuân thủ trước, trong và sau nhiệm vụ

---

## Nguyên tắc phân định bắt buộc

Quy tắc này thuộc một trong hai phạm vi chính có mức ưu tiên ngang nhau:

1. **Phát triển Toolkit:** Toolkit là đối tượng trực tiếp được sửa đổi, sửa lỗi, nâng cấp, tối ưu, tái cấu trúc hoặc bổ sung chức năng.
2. **Sửa và xử lý APK/Target:** APK, App, cây APK hoặc Target là đối tượng trực tiếp được phân tích, kiểm thử, sửa đổi hoặc xử lý; Toolkit chỉ là hệ thống công cụ phục vụ mục tiêu này.

AI bắt buộc phải nhận diện rõ nhiệm vụ hiện tại thuộc phạm vi nào trước khi tác động. Việc phân định này không nhằm buộc AI phải làm rõ máy móc mọi bước hoặc mọi quy trình, mà nhằm bảo đảm nhận thức bên trong luôn đúng: đang tác động vào đâu, vì mục tiêu gì, kỳ vọng riêng của người dùng là gì và quy tắc nào thực sự có liên quan.

Hai phạm vi có mức ưu tiên ngang nhau nhưng phải được áp dụng độc lập theo đúng đối tượng và ngữ cảnh. Không được dùng quy tắc Phát triển Toolkit để tự ý sửa Toolkit trong lúc nhiệm vụ chỉ yêu cầu xử lý APK; không được dùng quy tắc Sửa và xử lý APK để thay đổi kiến trúc, module hoặc cấu hình của Toolkit. Khi một nhiệm vụ thực sự liên quan đến cả hai phạm vi, AI phải tách rõ từng phần việc, đối tượng tác động, kết quả mong đợi và thứ tự thực hiện; không được nhập hai phạm vi thành một hành động mơ hồ.

Trước, trong và sau nhiệm vụ, AI phải duy trì việc phân định này, không được chỉ kiểm tra một lần ở đầu rồi dần lơ là. Nếu phát hiện nguy cơ nhầm phạm vi, xung đột quy tắc, tác động chéo, sửa nhầm, xóa nhầm, ghi đè nhầm hoặc sai lệch với kỳ vọng người dùng, AI phải báo rõ. Với vấn đề quan trọng, AI phải dừng phần liên quan và chờ chỉ thị đủ rõ; phản hồi chỉ liên quan một phần hoặc chưa giải quyết đúng điểm nghi ngờ không được tự diễn giải thành sự đồng ý.


---

## 1. Mục tiêu

Khi sửa hoặc xử lý APK/Target, AI phải linh hoạt theo yêu cầu, mục tiêu và kỳ vọng riêng của người dùng. Trọng tâm là đạt đúng kết quả người dùng cần trên Target, không phải tự ý thay đổi hay phát triển Toolkit. AI phải duy trì nhận thức chính xác về Target, phần cần phân tích hoặc sửa, căn cứ kỹ thuật, tác động dự kiến và tiêu chí kết quả trong toàn bộ nhiệm vụ.

Việc "nhận rõ" không chỉ là biết tên công việc hoặc thuộc một quy trình cố định. AI phải hiểu bên trong Target: cấu trúc, thành phần, luồng logic, hành vi, điểm quyết định, quan hệ phụ thuộc và những dữ liệu có liên quan trực tiếp đến mục tiêu. Từ nhận thức đó, AI mới lựa chọn, sắp xếp và phối hợp công cụ theo hướng phù hợp nhất với kỳ vọng người dùng.

---

## 2. Nhận thức bắt buộc về Toolkit khi xử lý Target

Trước khi áp dụng Toolkit lên Target, AI phải nhận rõ toàn bộ công cụ và module hiện có, bao gồm:

- Công dụng và chức năng thực tế.
- Hiệu quả có thể đạt được đối với từng loại mục tiêu.
- Điểm mạnh và khả năng phối hợp giữa các công cụ.
- Đầu vào, đầu ra và dữ liệu có thể dùng để kiểm chứng chéo.
- Khả năng áp dụng theo cấu trúc, mã nguồn, CFG, hành vi và đặc điểm thực tế của Target.

AI không được chọn công cụ ngẫu nhiên, theo thói quen hoặc chỉ vì công cụ đó thường được sử dụng. Việc lựa chọn phải có căn cứ từ mục tiêu, kỳ vọng người dùng và dữ liệu của Target.

---

## 3. Tổ chức công cụ thành cụm chức năng

AI phải sắp xếp các công cụ thành những cụm linh hoạt theo mục tiêu thực tế, gồm nhưng không giới hạn ở:

- Phân tích tĩnh.
- Phân tích động.
- Phân tích nhị phân.
- Phân tích hành vi.
- Dịch ngược.
- Kiểm thử.
- Sửa đổi APK.
- Các cụm chuyên biệt khác được hình thành theo Target và yêu cầu người dùng.

Một công cụ có thể thuộc nhiều cụm nếu chức năng thực tế phù hợp. Việc phân cụm không phải khuôn cố định; AI phải điều chỉnh theo cấu trúc APK, mã nguồn, CFG, Target, từ điển hành vi, cơ sở tri thức chung, bằng chứng kỹ thuật và kết quả trung gian.

---

## 4. Module Behavior là thành phần bắt buộc

Mọi cụm công cụ được sử dụng cho Target đều phải gọi và sử dụng **Module Behavior** như một thành phần trung tâm để:

- Phân tích hành vi thông minh.
- Khai thác CFG, Target và các điểm quyết định.
- Sử dụng từ điển hành vi và cơ sở tri thức chung.
- Hình thành, kiểm tra và loại bỏ giả thuyết không phù hợp.
- Liên kết, đối chiếu và kiểm chứng kết quả giữa các công cụ.
- Đánh giá mức độ tin cậy của dữ kiện và kết luận.
- Nhận diện hành vi hoặc quan hệ vượt ngoài phần mô tả trực tiếp.

Module Behavior không được xem là công cụ chỉ dành cho cụm phân tích hành vi. Đây là lớp hỗ trợ bắt buộc cho mọi cụm công cụ có tham gia xử lý Target.

---

## 5. Nguyên tắc sửa và xử lý APK

AI phải:

- Xác định chính xác APK/Target và phần được phép tác động.
- Bảo toàn bản gốc hoặc khả năng khôi phục trước thay đổi quan trọng.
- Phân biệt rõ phân tích, kiểm thử, sửa đổi và kết luận.
- Chỉ sửa phần có căn cứ và thực sự phục vụ mục tiêu người dùng.
- Kiểm tra ảnh hưởng của thay đổi lên cấu trúc, luồng logic, hành vi và thành phần liên quan.
- Không tự ý thay đổi Toolkit để hoàn thành nhiệm vụ APK nếu người dùng chưa yêu cầu phạm vi đó.
- Phân biệt rõ dữ kiện quan sát được, suy luận có căn cứ và phần chưa xác định.
- Luôn đối chiếu hướng xử lý với kỳ vọng người dùng, không chỉ với một quy trình kỹ thuật cố định.

---

## 6. Xử lý bất thường

AI phải kích hoạt ngay **Cơ chế Phanh An Toàn T1 (Dừng - Bảo lưu - Báo cáo 3 mục - Chờ chỉ thị)** theo [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19) khi phát hiện các dấu hiệu đặc thù của APK:

- Yêu cầu, Target hoặc phạm vi sửa chưa rõ.
- Quy tắc áp dụng mâu thuẫn hoặc không phù hợp ngữ cảnh (nhầm sang sửa Toolkit).
- Dữ liệu, bằng chứng hoặc phản hồi chưa đủ để xác định ý định.
- Nguy cơ sửa, xóa, ghi đè hoặc tác động nhầm Target.
- Thay đổi có thể gây hỏng chức năng, sai hành vi hoặc ảnh hưởng ngoài dự kiến.
- Kết quả giữa các công cụ mâu thuẫn hoặc chưa đủ tin cậy.
- Hướng xử lý có dấu hiệu lệch kỳ vọng người dùng.

Vấn đề quan trọng phải được dừng tại phần liên quan để chờ chỉ thị rõ ràng. Nếu phản hồi của người dùng chỉ liên quan một phần hoặc chưa giải quyết đúng điểm nghi ngờ, AI không được tự diễn giải thành xác nhận và không được tự ý tiếp tục.


---

## 7. Tiêu chí kiểm tra và nghiệm thu

### Trước khi xử lý APK/Target

- [ ] Đã xác định rõ đây là nhiệm vụ Sửa và xử lý APK/Target.
- [ ] Đã xác định chính xác Target và phần được phép tác động.
- [ ] Đã hiểu mục tiêu và kỳ vọng riêng của người dùng.
- [ ] Đã nhận diện cấu trúc, logic, hành vi và dữ liệu liên quan đến mục tiêu.
- [ ] Đã nhận rõ các công cụ và module có thể phục vụ nhiệm vụ.
- [ ] Đã lập cụm công cụ phù hợp và xác định vai trò của Module Behavior.
- [ ] Đã xác định căn cứ, rủi ro và phương án bảo toàn hoặc khôi phục.
- [ ] Không còn điểm nghi ngờ quan trọng chưa được làm rõ.

### Trong khi xử lý

- [ ] Hành động vẫn đúng Target, đúng phần và đúng phạm vi.
- [ ] Không vô tình chuyển sang sửa hoặc phát triển Toolkit.
- [ ] Lựa chọn công cụ vẫn phù hợp với dữ liệu và kết quả mới.
- [ ] Module Behavior đang thực hiện vai trò phân tích và kiểm chứng.
- [ ] Kết quả giữa các công cụ đã được liên kết và đối chiếu.
- [ ] Thay đổi không gây ảnh hưởng ngoài dự kiến lên thành phần khác.
- [ ] Hướng xử lý vẫn đúng kỳ vọng người dùng.
- [ ] Bất thường quan trọng đã được báo cáo và xử lý đúng quy tắc.
- [ ] Quy tắc vẫn được duy trì, không bị lơ là theo thời gian.

### Nghiệm thu

- [ ] Target được phân tích hoặc sửa đúng mục tiêu và phạm vi.
- [ ] Kết quả phù hợp với kỳ vọng đã xác định của người dùng.
- [ ] Không sửa nhầm, xóa nhầm, ghi đè nhầm hoặc tác động ngoài phạm vi.
- [ ] Các cụm công cụ được sử dụng phù hợp và có căn cứ.
- [ ] Module Behavior đã hoàn thành vai trò phân tích, liên kết và kiểm chứng.
- [ ] Kết quả quan trọng đã được kiểm chứng bằng phương pháp phù hợp khi có thể.
- [ ] Dữ kiện, suy luận và phần chưa xác định được phân biệt rõ.
- [ ] Không còn mâu thuẫn hoặc bất thường nghiêm trọng chưa được xử lý.
- [ ] Thay đổi không gây hỏng chức năng hoặc hành vi ngoài dự kiến.
- [ ] Kết quả, căn cứ và thay đổi có thể truy vết.
- [ ] Báo cáo cuối cùng nêu rõ kết quả, căn cứ, ảnh hưởng và điểm chưa xác định.

### Không đạt nghiệm thu nếu

- Nhầm APK/Target với Toolkit hoặc tác động sai đối tượng.
- Tiến hành khi chưa rõ mục tiêu, phạm vi hoặc ý định người dùng.
- Tự suy đoán và sửa khi chưa đủ căn cứ.
- Chọn công cụ máy móc, không dựa trên Target và kỳ vọng người dùng.
- Không sử dụng Module Behavior theo yêu cầu bắt buộc.
- Không kiểm chứng kết quả quan trọng hoặc trình bày suy đoán như kết luận chắc chắn.
- Bỏ qua tác động tiêu cực, mâu thuẫn hoặc bất thường đã phát hiện.
- Kết quả đi lệch mục tiêu hoặc kỳ vọng đã xác định.
- Chỉ tuân thủ quy tắc ở đầu nhiệm vụ rồi lơ là trong hoặc sau quá trình.

---

## 8. Tự nhắc bắt buộc

**Trước:** Tôi có đang sửa hoặc xử lý APK/Target không? Target nào, phần nào và người dùng cần kết quả gì?  
**Trong:** Tôi có còn tác động đúng Target, đúng phạm vi và đúng kỳ vọng không?  
**Sau:** Kết quả đã đúng mục tiêu, được kiểm chứng, không gây ảnh hưởng ngoài dự kiến và đủ điều kiện nghiệm thu chưa?
