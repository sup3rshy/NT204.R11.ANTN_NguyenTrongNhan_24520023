from typing import Any 
from models.event import IDSEvent 
from scapy.all import Raw 


def parse(raw_packet: Any, event: IDSEvent) -> None: 
    if raw_packet.haslayer(Raw) == False:
        return 
    
    try:
        event.app_data = {}
        payload = raw_packet[Raw].load.decode('utf-8', errors = 'ignore')
        
        split_header = payload.split('\r\n\r\n', 1)
        header = split_header[0]
        body = split_header[1] if len(split_header) > 1 else None 
        
        header_parts = header.split('\r\n')
        first_part = header_parts[0]
        if first_part.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
            request = first_part.split(' ')
            if len(request) >= 2:
                event.app_data["method"] = request[0]
                event.app_data["uri"] = request[1]
                
            if body:
                event.app_data["body"] = body.strip()
                
        elif first_part.startswith("HTTP/"):
            response = first_part.split(' ')
            if len(response) >= 2 and response[1].isdigit():
                event.app_data["status_code"] = int(response[1])
    
    except Exception as e: 
        event.app_data = {"error": str(e)}