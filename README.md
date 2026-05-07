# FIT4012 - Lab 3 - Hệ thống gửi và nhận dữ liệu mã hoá DES qua Socket

[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/XQ0Tagn8)

## Team members
- **Thành viên 1**: Nguyễn Thị Tuyết 
- **Thành viên 2**: Cao Minh Hưng 

## Task division
- **Thành viên 1 (Tuyết) phụ trách chính**: 
    - Lập trình luồng gửi dữ liệu trong `sender.py`.
    - Xây dựng cấu trúc đóng gói gói tin (Build packet) trong `des_socket_utils.py`.
    - Thực hiện chạy demo thực tế và trích xuất dữ liệu minh chứng vào thư mục `logs/`.
- **Thành viên 2 (Hưng) phụ trách chính**: 
    - Lập trình luồng nhận và giải mã dữ liệu trong `receiver.py`.
    - Thiết lập và thực thi các bộ kiểm thử tự động tại thư mục `tests/`.
    - Soạn thảo nội dung phân tích rủi ro bảo mật trong `threat-model-1page.md`.
- **Phần làm chung**: Cài đặt thuật toán DES-CBC, cơ chế Padding PKCS#7; thảo luận về các lỗ hổng bảo mật và hoàn thiện các file báo cáo Markdown.

## Demo roles
- **Nguyễn Thị Tuyết**: Demo Sender, giải thích cấu trúc gói tin (Header 20 bytes) và trình bày các log gửi dữ liệu thành công.
- **Cao Minh Hưng**: Demo Receiver, giải thích quy trình bóc tách gói tin, giải mã dữ liệu và trình bày kết quả `pytest`.
- **Cả hai**: Cùng trả lời các câu hỏi về mô hình tấn công MITM, rủi ro lộ khóa và các nguyên tắc đạo đức (Ethics).

## Cấu trúc repo
- `sender.py`: Tiến trình người gửi.
- `receiver.py`: Tiến trình người nhận.
- `des_socket_utils.py`: Chứa các hàm bổ trợ mã hóa và xử lý gói tin.
- `tests/`: Chứa 5 file kiểm thử tự động (Đã đạt 100% Passed).
- `logs/`: Chứa các file log minh chứng chạy thực tế:
  - `01-happy-path-tuyet.txt`: Tuyết chạy demo happy path.
  - `02-happy-path-hung.txt`: Hưng chạy demo happy path.
  - `03-tamper.txt`, `04-wrong-key.txt`, `05-header-error.txt`: Tuyết chạy các ca kiểm thử lỗi (pytest).
- `threat-model-1page.md`: Tài liệu phân tích mối đe dọa.
- `peer-review-response.md`: Phản hồi và chỉnh sửa sau đánh giá chéo.
- `report-1page.md`: Báo cáo tổng kết bài Lab.

## How to run

### 1) Cài môi trường

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**Linux/Mac:**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Chạy Receiver (Terminal 1)
```bash
python receiver.py
```

### 3) Chạy Sender (Terminal 2)
```bash
python sender.py
```

### 4) Chạy demo local bằng biến môi trường

**Windows — Terminal 1:**
```bash
set SOCKET_TIMEOUT=60 && python receiver.py
```
**Windows — Terminal 2:**
```bash
set MESSAGE=Xin chao FIT4012 && python sender.py
```

**Linux/Mac — Terminal 1:**
```bash
RECEIVER_PORT=6001 python receiver.py
```
**Linux/Mac — Terminal 2:**
```bash
SERVER_IP=127.0.0.1 SERVER_PORT=6001 MESSAGE="Xin chao FIT4012" python sender.py
```

### 5) Chạy toàn bộ test
```bash
pytest tests/ -v
```

## Input / Output

### Input
- Sender nhận bản tin từ bàn phím hoặc từ biến môi trường `MESSAGE`.
- Receiver nhận packet qua TCP socket.

### Output
- Sender in ra: thông báo gửi thành công, `Key`, `IV`, `Ciphertext`.
- Receiver in ra: bản tin gốc sau giải mã.

## Threat-model awareness
Hệ thống hiện tại gửi Key và IV dưới dạng plaintext trên cùng luồng TCP, đây là điểm yếu bảo mật nghiêm trọng nếu triển khai thực tế. Chi tiết phân tích xem tại `threat-model-1page.md`.

## Ethics & Safe use
- Chỉ chạy demo trên máy cá nhân, VM, hoặc mạng nội bộ phục vụ học tập.
- Không quét cổng, không thử nghiệm lên hệ thống không thuộc phạm vi lớp học.
- Không dùng dữ liệu cá nhân thật hoặc dữ liệu nhạy cảm để demo.
- Không trình bày hệ thống này như một giải pháp an toàn sẵn sàng triển khai ngoài đời.
- Nếu tham khảo code/tài liệu, hãy ghi nguồn rõ ràng.
- Tôn trọng nguyên tắc trung thực học thuật.