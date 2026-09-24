# Project structure (powered by Gemini-chan, i'll try coding by myself then):
```
IDS_Packet_Parser/
│
├── main.py                     # Entry point chính của chương trình
├── core/
│   ├── __init__.py
│   ├── capture.py              # Xử lý live capture interface và pcap import
│   ├── pipeline.py             # Điều phối luồng dữ liệu của packet
│   └── logger.py               # Xử lý ghi file output định dạng JSON Lines
│
├── models/
│   ├── __init__.py
│   └── event.py                # Định nghĩa cấu trúc Normalized IDS Event
│
├── parsers/
│   ├── __init__.py
│   ├── network.py              # IPv4 parser
│   ├── transport.py            # TCP, UDP parser
│   ├── app_detector.py         # Nhận diện protocol (Port/Payload-based)
│   └── application/            # Các parser riêng cho HTTP, DNS, SMTP
│       ├── __init__.py
│       ├── http.py
│       ├── dns.py
│       └── smtp.py
│
├── TEST/                       # Thư mục lưu kết quả testcase bắt buộc
├── README.md                   # Thông tin project và khai báo AI usage
└── requirements.txt
```

# Timeline:
- `23-9-2026 10:12AM`: Can detect network protocol. For application protocol didnt implemented payload-based detection yet. Next features: payload-based detection and application parser


# Note 
- Ở `parsers/app_detector.py` chúng ta chỉ cần duyệt port để kiểm tra DNS, vì ở đây đề bài không nhắc gì về DNS over HTTPS, hoặc các dạng DNS khác DNS thông thường (DNS qua UDP/TCP port 53). 