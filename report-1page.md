# Report 1 Page - Lab 3: DES Socket Implementation

## Thông tin nhóm
- **Thành viên 1**: Nguyễn Thị Tuyết 
- **Thành viên 2**: Cao Minh Hưng 

## Mục tiêu
Mục tiêu của bài lab này là xây dựng thành công một hệ thống truyền nhận dữ liệu giữa Sender và Receiver thông qua kết nối TCP Socket. Qua đó, nhóm tìm hiểu cách áp dụng thuật toán mã hóa đối xứng DES ở chế độ CBC (Cipher Block Chaining), quản lý Vector khởi tạo (IV) và kỹ thuật Padding PKCS#7. Đồng thời, bài lab giúp nhận diện các lỗ hổng bảo mật khi thực hiện truyền khóa (Key) trực tiếp trên đường truyền cùng với dữ liệu mã hóa.

## Phân công thực hiện
- **Nguyễn Thị Tuyết (Phụ trách chính Sender)**: 
    - Lập trình luồng gửi dữ liệu trong `sender.py`.
    - Xây dựng cấu trúc đóng gói gói tin (Packet building) trong `des_socket_utils.py`.
    - Thực hiện chạy demo thực tế và trích xuất dữ liệu `logs/` minh chứng.
- **Cao Minh Hưng (Phụ trách chính Receiver)**: 
    - Lập trình luồng nhận và giải mã dữ liệu trong `receiver.py`.
    - Thiết lập, viết và thực thi các bộ kiểm thử tự động trong thư mục `tests/`, bao gồm các trường hợp lỗi như giả mạo dữ liệu và sai khóa.
    - Nghiên cứu các mối đe dọa liên quan đến truyền khóa và dữ liệu mã hóa, đồng thời soạn thảo nội dung phân tích trong `threat-model-1page.md`.
- **Phần làm chung**: Cài đặt thuật toán DES-CBC, cơ chế Padding PKCS#7; thảo luận về các lỗ hổng bảo mật và hoàn thiện báo cáo tổng kết.

## Cách làm
- **Mã hóa DES-CBC**: Sử dụng thư viện `pycryptodome` để thực hiện mã hóa. Dữ liệu được thực hiện Pad (đệm) theo chuẩn PKCS#7 để đảm bảo kích thước bản tin là bội số của 8 byte trước khi mã hóa.
- **Sender**: Tạo khóa DES 8 byte và IV 8 byte ngẫu nhiên. Sau đó mã hóa bản tin và đóng gói theo cấu trúc "hợp đồng": `Key (8B) | IV (8B) | Length (4B) | Ciphertext`.
- **Receiver**: Mở socket lắng nghe kết nối. Receiver bóc tách gói tin theo đúng thứ tự quy định, sử dụng Key và IV nhận được từ header để giải mã và Unpad dữ liệu về bản rõ ban đầu.
- **Kiểm thử (Testing)**: Sử dụng công cụ `pytest` để kiểm tra tính đúng đắn của hàm mã hóa, quy trình gửi nhận và các trường hợp lỗi (Negative tests) như sai khóa hoặc dữ liệu bị giả mạo.

## Kết quả
- **Hệ thống**: Sender và Receiver truyền nhận dữ liệu thành công trên môi trường nội bộ. Bản tin giải mã tại Receiver trùng khớp hoàn toàn với bản tin gốc.
- **Minh chứng**: Các tệp trong thư mục `logs/` đã ghi lại chi tiết quá trình chạy thật, bao gồm các giá trị hex của khóa, IV và dữ liệu đã mã hóa.
- **Kiểm thử tự động**: Toàn bộ **6/6 test cases** trong thư mục `tests/` đều đạt trạng thái **Passed**, bao gồm cả các ca kiểm thử về bảo mật như giả mạo dữ liệu (`tamper`) và sai khóa (`wrong key`).

## Kết luận
- **Bài học kỹ thuật**: Nắm vững quy trình lập trình Socket và cách tích hợp thư viện mật mã học vào ứng dụng thực tế. Hiểu rõ cấu trúc dữ liệu nhị phân (Binary) khi đóng gói gói tin.
- **Bài học bảo mật**: Nhận thức được rủi ro khi truyền Key/IV công khai trên cùng kênh truyền. Đây là tiền đề để hiểu về nhu cầu của các giao thức an toàn hơn như RSA hoặc trao đổi khóa Diffie-Hellman.