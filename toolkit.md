# QUY TẮC PHÁT TRIỂN TOOLKIT

> **Mức ưu tiên:** Cao nhất, ngang với `apk.md`  
> **Phạm vi:** Chỉ áp dụng khi Toolkit là đối tượng được phát triển hoặc thay đổi  
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

Khi phát triển Toolkit, AI phải hiểu Toolkit như một hệ thống thống nhất, không chỉ là tập hợp các công cụ và module riêng lẻ. Mục tiêu phát triển là nhận diện đúng điểm mạnh, điểm yếu, điểm nghẽn, phần chưa ổn định, phần chưa hoàn thiện và khả năng phối hợp còn thiếu; từ đó tối ưu đồng bộ toàn bộ hệ thống, tiến từ **đồng bộ** đến **đồng nhất**, tạo khả năng cộng hưởng và phát huy tối đa sức mạnh tổng thể của Toolkit.

Mọi hoạt động phải linh hoạt theo mục tiêu và kỳ vọng riêng của người dùng. AI phải luôn nhận rõ Toolkit đang hướng tới điều gì, lợi thế cốt lõi nằm ở đâu, thay đổi hiện tại phục vụ hướng phát triển nào và liệu hướng đó có còn phù hợp với kỳ vọng của người dùng hay không.

---

## 2. Nhận thức bắt buộc về toàn bộ Toolkit

Ngay lần đầu áp dụng quy tắc này và sau mỗi thay đổi quan trọng, AI phải rà soát toàn bộ Toolkit, bao gồm:

- Cây thư mục, đường dẫn, package và phụ thuộc.
- Công cụ, module, tệp cấu hình và dữ liệu dùng chung.
- Chức năng, vai trò, quan hệ và luồng phối hợp giữa các thành phần.
- Điểm mạnh hiện có và lợi thế cốt lõi.
- Điểm yếu, điểm nghẽn, lỗi, phần thiếu ổn định hoặc chưa hoàn thiện.
- Chức năng thiếu, dư thừa, trùng lặp hoặc chưa được khai thác đúng mức.
- Thành phần hoạt động rời rạc, liên kết yếu hoặc không còn phù hợp với định hướng chung.
- Ảnh hưởng của từng thay đổi lên kiến trúc, logic, hiệu năng và khả năng phối hợp toàn hệ thống.

AI phải duy trì bức tranh tổng thể này trong suốt quá trình phát triển. Không được vì tập trung vào nhiệm vụ cục bộ mà quên mục tiêu dài hạn, cấu trúc chung hoặc các phần còn lại của Toolkit.

---

## 3. Nguyên tắc phát triển đồng bộ và đồng nhất

AI phải:

- Phát huy đúng điểm mạnh và lợi thế đang có của Toolkit.
- Chủ động tìm và tháo gỡ điểm nghẽn đang hạn chế nhiều module hoặc toàn hệ thống.
- Cải thiện phần yếu và phần chưa ổn định thay vì chỉ tiếp tục đầu tư cho phần đã mạnh.
- Không bỏ qua các phần khác chỉ vì đang tập trung vào một lợi thế nổi bật.
- Không tối ưu cục bộ nếu thay đổi đó chia cắt, làm suy yếu hoặc phá vỡ khả năng phối hợp chung.
- Ưu tiên giải pháp có thể tái sử dụng, liên kết, kiểm chứng và khuếch đại năng lực giữa các module.
- Hướng các module và công cụ về cùng cấu trúc logic, định hướng và mục tiêu tổng thể.
- Đánh giá giá trị của thay đổi bằng sức mạnh tổng thể đạt được, không chỉ bằng mức cải thiện của một thành phần riêng lẻ.

**Đồng bộ** nghĩa là các thành phần phối hợp đúng và trao đổi được với nhau. **Đồng nhất** nghĩa là các thành phần không chỉ phối hợp được mà còn cùng hướng về một kiến trúc, logic, tiêu chuẩn và mục tiêu chung. Đích phát triển là tạo sức mạnh cộng hưởng lớn nhất trong phạm vi có thể.

---

## 4. Quản lý quy tắc và tài liệu

AI phải đọc kỹ và phân biệt quy tắc chung, quy tắc riêng, quy tắc dành cho phát triển Toolkit và quy tắc dành cho xử lý APK. Không được tự ý trộn, đổi nghĩa hoặc bỏ qua quy tắc.

Nhận thức về kiến trúc, module, quan hệ, định hướng, điểm mạnh, điểm yếu và thay đổi quan trọng phải được cập nhật vào `Menh-lenh.md` hoặc tài liệu quản trị tương ứng. Khi thay đổi một thành phần, AI phải xem xét và đồng bộ các tài liệu, cấu hình, giao diện và thành phần phụ thuộc có liên quan.

---

## 5. Xử lý bất thường

AI phải kích hoạt ngay **Cơ chế Phanh An Toàn T1 (Dừng - Bảo lưu - Báo cáo 3 mục - Chờ chỉ thị)** theo [`QUY_TAC_NGUOI_DUNG.md`](file:///data/data/com.termux/files/home/_patchx/QUY_TAC_NGUOI_DUNG.md#ch%E1%BB%89-th%E1%BB%8B-r%C3%B5-r%C3%A0ng-m%E1%BB%9Bi-%C4%91%C6%B0%E1%BB%A3c-l%C3%A0m--nguy%C3%AAn-t%E1%BA%AFc-l%C3%A0m-vi%E1%BB%87c-t%E1%BB%91i-cao-v%C4%A9nh-vi%E1%BB%85n-user-ban-h%C3%A0nh-2026-09-19) khi phát hiện các dấu hiệu đặc thù của Toolkit:

- Yêu cầu có thể đi ngược định hướng hoặc kỳ vọng đã xác định.
- Quy tắc mâu thuẫn, thiếu rõ ràng hoặc áp dụng sai phạm vi (nhầm sang sửa APK/Target).
- Thay đổi có nguy cơ gây lỗi, mất ổn định, mất tương thích hoặc suy giảm chức năng.
- Tối ưu cục bộ có thể làm yếu toàn hệ thống hoặc chia cắt khả năng phối hợp module.
- Tác động ngoài phạm vi, ghi đè, sửa nhầm, xóa nhầm hoặc mất dữ liệu.
- Thiếu căn cứ để xác định chính xác ý định người dùng.

Vấn đề quan trọng phải được dừng tại phần liên quan để chờ chỉ thị rõ ràng. AI không được tự đoán, tự diễn giải sự im lặng hoặc phản hồi chưa đầy đủ thành sự đồng ý.

---

## 6. Tiêu chí kiểm tra và nghiệm thu

### Trước khi phát triển

- [ ] Đã xác định rõ đây là nhiệm vụ Phát triển Toolkit.
- [ ] Đã xác định chính xác thành phần và phạm vi được phép thay đổi.
- [ ] Đã hiểu mục tiêu, kỳ vọng riêng và kết quả người dùng cần.
- [ ] Đã rà soát kiến trúc, quan hệ phụ thuộc và ảnh hưởng liên đới.
- [ ] Đã nhận diện điểm mạnh, điểm yếu, điểm nghẽn và phần chưa ổn định liên quan.
- [ ] Đã xác định thay đổi phù hợp với định hướng tổng thể.
- [ ] Không còn điểm nghi ngờ quan trọng chưa được làm rõ.

### Trong khi phát triển

- [ ] Hành động vẫn đúng phạm vi và đúng đối tượng.
- [ ] Không vô tình chuyển sang sửa APK/Target.
- [ ] Thay đổi không phá vỡ chức năng hoặc khả năng phối hợp hiện có.
- [ ] Không tối ưu cục bộ gây suy yếu toàn hệ thống.
- [ ] Các phát hiện mới đã được đối chiếu với mục tiêu và kỳ vọng người dùng.
- [ ] Bất thường và ảnh hưởng tiêu cực đã được báo cáo đúng lúc.
- [ ] Nhận thức tổng thể và quy tắc vẫn được duy trì, không bị lơ là.

### Nghiệm thu

- [ ] Thay đổi giải quyết đúng điểm yếu, điểm nghẽn hoặc mục tiêu phát triển.
- [ ] Chức năng thay đổi hoạt động đúng kỳ vọng.
- [ ] Không gây suy giảm ngoài dự kiến cho thành phần khác.
- [ ] Các module và công cụ liên quan vẫn tương thích và đồng bộ.
- [ ] Thay đổi góp phần tăng tính đồng nhất về kiến trúc, logic hoặc định hướng.
- [ ] Sức mạnh tổng thể được giữ nguyên hoặc nâng cao, không chỉ làm mạnh một phần riêng lẻ.
- [ ] Kết quả, căn cứ và phạm vi thay đổi có thể truy vết.
- [ ] Tài liệu, cấu hình và `Menh-lenh.md` đã được cập nhật khi cần.
- [ ] Không còn bất thường nghiêm trọng hoặc mâu thuẫn chưa xử lý.

### Không đạt nghiệm thu nếu

- Nhầm nhiệm vụ phát triển Toolkit với sửa APK/Target.
- Thực hiện khi chưa rõ đối tượng, phạm vi hoặc ý định người dùng.
- Tạo cải thiện cục bộ nhưng làm suy yếu toàn hệ thống.
- Bỏ qua điểm nghẽn, phần yếu hoặc ảnh hưởng liên đới đã biết.
- Làm mất đồng bộ, mất ổn định hoặc phá vỡ định hướng chung.
- Không cập nhật tài liệu bắt buộc sau thay đổi.
- Chỉ tuân thủ quy tắc ở đầu nhiệm vụ rồi lơ là trong hoặc sau quá trình.

---

## 7. Tự nhắc bắt buộc

**Trước:** Tôi có đang phát triển Toolkit không? Tôi đang thay đổi phần nào, vì mục tiêu nào và ảnh hưởng tới đâu?  
**Trong:** Thay đổi này có còn đúng kỳ vọng, đúng định hướng và có lợi cho toàn hệ thống không?  
**Sau:** Toolkit có mạnh hơn, ổn định hơn, đồng bộ hơn và tiến gần hơn tới sự đồng nhất không?
