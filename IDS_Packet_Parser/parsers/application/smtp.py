from typing import Any 
from models.event import IDSEvent
from scapy.all import * 


def parse(raw_packet: Any, event: IDSEvent) -> None:
    if not raw_packet.haslayer(Raw):
        return
        
    try:
        # Lấy dòng đầu tiên của payload
        payload = raw_packet[Raw].load.decode('utf-8', errors='ignore').strip()
        lines = payload.split('\r\n')
        if not lines:
            return
            
        first_line = lines[0]
        event.app_data = {}
        
        # smtp command
        smtp_command = ("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT")
        if first_line.startswith(("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT")):
            for cmd in smtp_command:
                if first_line.startswith(cmd):
                    event.app_data['command'] = first_line[:len(cmd)]
                    if len(first_line) > len(cmd):
                        event.app_data['argument'] = first_line[len(cmd):].strip()
        
                
        # extract smtp status code
        elif len(first_line) >= 3 and first_line[:3].isdigit():
            event.app_data['status_code'] = int(first_line[:3])
            event.app_data['message'] = first_line[4:].strip()
            
    except Exception as e:
        event.app_data = {"error": f"SMTP Parse Error: {e}"}