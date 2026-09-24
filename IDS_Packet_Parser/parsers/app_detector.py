from typing import Any 
from scapy.all import * 
from models.event import IDSEvent 

def detect_app_protocol(raw_packet: Any, event: IDSEvent) -> None:
    
    # 1. port-based detection 
    ports = {event.src_port, event.dst_port}
    if 53 in ports and raw_packet.haslayer(DNS):
        # standard DNS uses port 53 (TCP/UDP) 
        # boi vi yeu cau ko noi ve dns over https hoac cac dang dns khac, cung ko yeu cau handle case nay 
        # nen chung ta co the tin tuong dns chi dung port 53 
        event.app_proto = "DNS"
        
    elif 80 in ports:
        event.app_proto = "HTTP"
    elif 587 in ports or 25 in ports: 
        event.app_proto = "SMTP"
        
    

    # 2. payload-based detection - implemented soon:
    if raw_packet.haslayer(Raw):
        payload = raw_packet[Raw].load  
        
        
        # http detect 
        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")):
            event.app_proto = "HTTP"
        
        # SMTP command line detect 
        elif payload.startswith((b"HELO", b"EHLO", b"MAIL FROM", b"RCPT TO", b"DATA", b"QUIT")):
            event.app_proto = "SMTP"
            
        # SMTP reponse code detect (3 digits) 
        elif len(payload) >= 3 and payload[:3].isdigit() and b"\r\n" in payload:
             # Xác nhận thêm dòng kết thúc chuẩn của SMTP
            event.app_proto = "SMTP"