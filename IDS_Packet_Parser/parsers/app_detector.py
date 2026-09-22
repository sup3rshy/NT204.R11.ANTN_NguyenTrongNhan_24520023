from typing import Any 
from scapy.all import * 
from models.event import IDSEvent 

def detect_app_protocol(raw_packet: Any, event: IDSEvent) -> None:
    
    # 1. port-based detection 
    ports = {event.src_port, event.dst_port}
    if 53 in ports:
        event.transport_proto = "DNS"
        
    elif 80 in ports:
        event.transport_proto = "HTTP"
    elif 587 in ports or 25 in ports: 
        event.transport_proto = "SMTP"
        
    

    # 2. payload-based detection - implemented soon:
    if raw_packet.haslayer(Raw):
        payload = raw_packet[Raw].load  
        