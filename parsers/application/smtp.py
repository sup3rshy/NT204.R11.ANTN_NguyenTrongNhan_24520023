from typing import Any 
from models.event import IDSEvent
from scapy.all import * 
import email 


def parse(raw_packet: Any, event: IDSEvent) -> None:
    if not raw_packet.haslayer(Raw):
        event.app_proto = "UNKNOWN" 
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
        smtp_commands = ("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT", "AUTH", "RSET", "NOOP", "VRFY")
        is_command: bool = False 
        
        for cmd in smtp_commands:
            if first_line.startswith(cmd):
                event.app_data['command'] = cmd 
                if len(first_line) > len(cmd):
                    event.app_data['argument'] = first_line[len(cmd):].strip()
        
        if is_command:
            return 
                
        # extract smtp status code
        if len(first_line) >= 4 and first_line[:3].isdigit() and first_line[3: 4] in (' ', '-'):
            event.app_data['status_code'] = int(first_line[:3])
            event.app_data['message'] = first_line[4:].strip()
            return 
        
    
        # mime
        mime_indicators = ["Content-Type:", "Subject:", "From:", "To:", "MIME-Version:"]
        if any(x in payload for x in mime_indicators):
            event.app_data['is_mime'] = True 
            
            msg = email.message_from_string(payload) 
            
            mime_data = {
                'raw_headers': {},
                'decoded_headers': {},
                'decode_status': {
                    'headers_success': True,
                    'body_success': True,
                    'body_encoding': 'none',
                    'errors': []
                }
            }
            
            target_headers = ['Subject', 'From', 'To', 'Content-Type', 'Date', 'Content-Transfer-Encoding']
            for header in target_headers:
                if msg[header]:
                    raw_val = msg[header]
                    header_lower = header.lower()
                    mime_data['raw_headers'][header_lower] = raw_val
                    

            event.app_data['mime_info'] = mime_data
            return
        

        # fallback: data fragment
        event.app_data["data_fragment"] = payload
            

            
            
    except Exception as e:
        event.app_data = {"error": f"SMTP Parse Error: {e}"}