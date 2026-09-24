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
- Tại sao tôi lại biết format của một protocol cụ thể (không dùng AI)? Mở cyberdefenders lên tải vài chall network forensics, rồi ngắm các packet thôi. Ví dụ cụ thể
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
