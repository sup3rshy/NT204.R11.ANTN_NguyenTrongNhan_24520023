# Project structure (powered by Gemini-chan, i'll try coding by myself then):
```
Main Project Here/
│
├── main.py                     # Entry point duy nhất của toàn bộ chương trình
├── core/
│   ├── __init__.py
│   ├── capture.py              # Xử lý live capture interface và pcap import
│   ├── pipeline.py             # Điều phối: Parser -> Decoder -> Preprocessor -> Flow Tracker
│   └── logger.py               # Xử lý ghi log JSON Lines
│
├── models/
│   ├── __init__.py
│   ├── event.py                # Dataclass IDSEvent (đã có từ Bài 1)
│   └── flow.py                 # Dataclass Flow / Connection record (yêu cầu mục 5.4 Bài 2)
│
├── parsers/                    # BÀI TẬP 1
│   ├── __init__.py
│   ├── network.py              # IPv4 parser
│   ├── transport.py            # TCP, UDP parser
│   ├── app_detector.py         # Nhận diện HTTP, DNS, SMTP qua Port & Payload
│   └── application/
│       ├── __init__.py
│       ├── http.py
│       ├── dns.py
│       └── smtp.py
│
├── decoder/                    # MODULE 1: Giải mã dữ liệu (BÀI TẬP 2)
│   ├── __init__.py             # Re-export: from .decoder import Decoder
│   ├── url.py                  # T01: HTTP URL / percent-decoding
│   ├── html.py                 # T02: HTML entity decoding
│   ├── mime.py                 # T03: SMTP Base64 & Quoted-Printable
│   └── decoder.py              # Class Decoder điều phối, xử lý T04 safe decode (thay thế main.py)
│
├── preprocessor/               # MODULE 2: Tiền xử lý (BÀI TẬP 2)
│   ├── __init__.py             # Re-export: from .preprocessor import Preprocessor
│   ├── validator.py            # T14: Kiểm tra required fields, port range 0-65535, timestamp
│   ├── normalizer.py           # T05: Chuẩn hóa header, domain, protocol name
│   └── preprocessor.py         # Class Preprocessor điều phối, T06 gán status/action (thay thế main.py)
│
├── flow_tracker/               # MODULE 3: Quản lý luồng (BÀI TẬP 2)
│   ├── __init__.py             # Re-export: from .tracker import FlowTracker
│   ├── tcp_tracker.py          # T07, T09: State machine TCP (HANDSHAKE, ESTABLISHED, CLOSING, CLOSED)
│   ├── udp_tracker.py          # T10: State tracking cho UDP
│   ├── state_table.py          # T11, T12: Bảng băm lưu active flows & xử lý idle timeout
│   └── tracker.py              # Class FlowTracker điều phối: tạo 5-tuple đảo chiều (T08), thống kê (T13)
│
├── TEST/                       # Chứa script test tự động / output testcase T01 -> T14
├── README.md
├── requirements.txt
└── pcap_samples/
```

# Timeline:
- `23-9-2026 10:12AM`: Can detect network protocol. For application protocol didnt implemented payload-based detection yet. Next features: payload-based detection and application parser
- `24-9-2026`: 

# Note 
- Code được em review từng dòng một, không bỏ một dòng nào, tự tay test, samples lấy từ CyberDefenders. Tự đọc logic các packet từ đó rồi kiểm chứng lại, đưa ra giải pháp hợp lí nhất cho từng bài toán. Dùng AI trên web để phát triển từng tính năng một lên (gemini) + Antigravity để review lại codebase. 
- Tại sao em lại biết format của một protocol cụ thể (không dùng AI)? Mở cyberdefenders lên tải vài chall network forensics, rồi ngắm các packet thôi. Ví dụ cụ thể
```
In [33]: hihi = bytes.fromhex('0008021c47aea41f72c2096a08004500004e094140008011c8ce0a040a040a040a840035cff1003abbb08701818000010001
       ⋮ 0000000003646e73086d7366746e63736903636f6d0000010001c00c000100010000000f0004836bffff')
In [35]: hihi = Ether(hihi)

In [36]: hihi.show()
###[ Ethernet ]###
  dst       = 00:08:02:1c:47:ae
  src       = a4:1f:72:c2:09:6a
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 78
     id        = 2369
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = udp
     chksum    = 0xc8ce
     src       = 10.4.10.4
     dst       = 10.4.10.132
     \options   \
###[ UDP ]###
        sport     = domain
        dport     = 53233
        len       = 58
        chksum    = 0xbbb0
###[ DNS ]###
           id        = 34561
           qr        = 1
           opcode    = QUERY
           aa        = 0
           tc        = 0
           rd        = 1
           ra        = 1
           z         = 0
           ad        = 0
           cd        = 0
           rcode     = ok
           qdcount   = 1
           ancount   = 1
           nscount   = 0
           arcount   = 0
           \qd        \
            |###[ DNS Question Record ]###
            |  qname     = b'dns.msftncsi.com.'
            |  qtype     = A
            |  unicastresponse= 0
            |  qclass    = IN
           \an        \
            |###[ DNS Resource Record ]###
            |  rrname    = b'dns.msftncsi.com.'
            |  type      = A
            |  cacheflush= 0
            |  rclass    = IN
            |  ttl       = 15
            |  rdlen     = None
            |  rdata     = 131.107.255.255
           \ns        \
           \ar        \
```
- Ở `parsers/app_detector.py` chúng ta chỉ cần duyệt port để kiểm tra DNS, vì ở đây đề bài không nhắc gì về DNS over HTTPS, hoặc các dạng DNS khác DNS thông thường (DNS qua UDP/TCP port 53). 