from typing import Any 
from scapy.all import * 
from models.event import IDSEvent 

PORT_MAP = {
    80: "HTTP",
    25: "SMTP", 
    465: "SMTP", # SMTPS
    587: "SMTP", # Message Submission
}

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
        
    for port in ports:
        if port in PORT_MAP:
            event.app_proto = PORT_MAP[port]
            break

    # 2. payload-based detection (DPI - deep packet inspection) - implemented soon:
    if raw_packet.haslayer(Raw):
        payload = raw_packet[Raw].load  
        
        
        # http detect 
        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/")):
            event.app_proto = "HTTP"
            return 
        
        # SMTP command line detect 
        smtp_cmds = (b"HELO ", b"EHLO ", b"MAIL FROM:", b"RCPT TO:", b"DATA\r\n", b"QUIT\r\n", b"AUTH ")
        if payload.upper().startswith(smtp_cmds):
            event.app_proto = "SMTP"
            return
            
        # SMTP reponse code detect (3 digits) 
        elif len(payload) >= 4 and payload[:3].isdigit() and payload[3: 4] in (b' ', b'-') and b"\r\n" in payload:
            event.app_proto = "SMTP"