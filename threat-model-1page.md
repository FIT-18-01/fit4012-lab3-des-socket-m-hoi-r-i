# Threat Model - Lab 3: Secure Socket with DES

## Thông tin nhóm
- **Thành viên 1**: Nguyễn Thị Tuyết
- **Thành viên 2**: Cao Minh Hưng 

## Assets (Tài sản cần bảo vệ)
1. **Nội dung bản tin (Plaintext)**: Thông tin gốc cần được giữ bí mật tuyệt đối giữa Sender và Receiver.
2. **Khóa đối xứng (DES Key)**: Thành phần cốt lõi dùng để mã hóa và giải mã; nếu lộ khóa, tính bảo mật của toàn bộ hệ thống sẽ bị phá vỡ.
3. **Vector khởi tạo (IV)**: Tham số dùng trong chế độ CBC để đảm bảo tính ngẫu nhiên của bản mã ngay cả khi nội dung gốc giống nhau.
4. **Tính toàn vẹn của gói tin**: Đảm bảo cấu trúc gói tin (Key | IV | Length | Ciphertext) không bị xáo trộn hoặc thay đổi trái phép trên đường truyền.

## Attacker model (Mô hình kẻ tấn công)
Đối tượng tấn công giả định là một **Kẻ tấn công đứng giữa (Man-in-the-Middle - MITM)** nằm trên mạng nội bộ hoặc các nút mạng trung gian. Kẻ tấn công có các khả năng:
- **Sniffing (Nghe lén)**: Sử dụng các công cụ như Wireshark để bắt và đọc các gói tin TCP chạy qua mạng.
- **Tampering (Chỉnh sửa)**: Can thiệp trực tiếp vào luồng dữ liệu, thay đổi các byte trong phần Ciphertext trước khi gói tin tới đích.
- **Spoofing (Giả mạo)**: Giả danh Sender để gửi các gói tin có cấu trúc header hợp lệ nhưng chứa dữ liệu độc hại tới Receiver.

## Threats (Mối đe dọa)
1. **Lộ lọt thông tin nhạy cảm (Information Disclosure)**: Do Key và IV được gửi kèm ngay trong Header mà không được bảo vệ thêm, kẻ tấn công chỉ cần bắt được gói tin là có đủ thông số để giải mã và đọc nội dung Plaintext.
2. **Mất tính toàn vẹn (Integrity Loss)**: Kẻ tấn công có thể sửa đổi bản mã. Vì hệ thống thiếu cơ chế xác thực nguồn gốc (như MAC/HMAC), Receiver sẽ giải mã ra dữ liệu rác mà không có cách nào tự động phát hiện dữ liệu đã bị sửa đổi.
3. **Tấn công phát lại (Replay Attack)**: Kẻ tấn công bắt một gói tin hợp lệ và gửi lại nhiều lần cho Receiver. Do thiếu cơ chế dán nhãn thời gian (Timestamp), Receiver có thể xử lý lại bản tin cũ như một yêu cầu mới.

## Mitigations (Biện pháp giảm thiểu)
1. **Mã hóa khóa (Key Encryption)**: Sử dụng mã hóa bất đối xứng (RSA) để trao đổi khóa an toàn. Thay vì gửi Key trực tiếp, Sender sẽ mã hóa Key bằng Public Key của Receiver.
2. **Xác thực thông báo (Message Authentication)**: Áp dụng cơ chế HMAC kèm theo gói tin. Receiver sẽ tính toán lại mã Hash để đối chiếu, giúp phát hiện ngay lập tức nếu Ciphertext bị chỉnh sửa dù chỉ 1 bit.
3. **Sử dụng TLS/SSL**: Triển khai giao thức TLS để bọc toàn bộ kết nối socket, đảm bảo an toàn cho cả quá trình bắt tay và trao đổi dữ liệu.

## Residual risks (Rủi ro còn lại)
**Tấn công tại điểm cuối (Endpoint Compromise)**: Ngay cả khi kênh truyền được bảo vệ hoàn hảo, rủi ro vẫn tồn tại nếu thiết bị của người dùng bị nhiễm mã độc. Kẻ tấn công có thể đọc trộm nội dung bản tin trực tiếp từ bộ nhớ RAM trước khi nó kịp mã hóa hoặc sau khi đã giải mã xong.