# Peer Review Response - Lab 3

## Thông tin nhóm
- **Thành viên 1**: Nguyễn Thị Tuyết 
- **Thành viên 2**: Cao Minh Hưng 

## Thành viên 1 góp ý cho thành viên 2
- **Nguyễn Thị Tuyết góp ý cho Cao Minh Hưng**: Phần Receiver xử lý tách gói tin theo "hợp đồng" (Key|IV|Len|Cipher) khá tốt. Tuy nhiên, Hưng cần lưu ý bổ sung thêm các trường hợp ngoại lệ (Exception Handling) khi nhận được gói tin bị lỗi hoặc không đúng định dạng để chương trình không bị crash đột ngột. Phần Threat Model cũng cần mô tả chi tiết hơn về rủi ro lộ khóa người dùng.

## Thành viên 2 góp ý cho thành viên 1
- **Cao Minh Hưng góp ý cho Nguyễn Thị Tuyết**: Phần code Sender hoạt động rất ổn định, tạo Key và IV ngẫu nhiên đúng yêu cầu. Tuy nhiên, Tuyết nên tối ưu hóa việc lấy tin nhắn từ biến môi trường (Environment Variable) để thuận tiện hơn khi chạy test tự động trên CI. Phần tài liệu báo cáo cần chú ý định dạng Markdown (bảng biểu, in đậm) để dễ theo dõi hơn.

## Nhóm đã sửa gì sau góp ý
Sau khi thực hiện đánh giá chéo, nhóm đã tiến hành các chỉnh sửa sau:
1. **Phía Receiver**: Cập nhật thêm khối lệnh `try...except` để xử lý lỗi khi bóc tách header độ dài bị sai hoặc gói tin không đủ 20 bytes.
2. **Phía Sender**: Điều chỉnh lại file `sender.py` để ưu tiên lấy tin nhắn từ biến môi trường `MESSAGE`, giúp đồng bộ hoàn toàn với script kiểm thử `test_local_sender_receiver_roundtrip.py`.
3. **Tài liệu**: Bổ sung phần phân tích rủi ro "Endpoint Compromise" (Lộ khóa tại điểm cuối) vào file Threat Model theo đề xuất của Tuyết.
4. **Định dạng**: Kiểm tra và định dạng lại toàn bộ các file báo cáo (.md), đảm bảo tính nhất quán, chuyên nghiệp và dễ đọc khi hiển thị trên GitHub.