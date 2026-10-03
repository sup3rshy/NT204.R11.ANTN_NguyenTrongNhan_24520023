from typing import Any
from models.event import IDSEvent
from scapy.all import * 
import email 


active_smtp_sessions: dict[tuple, dict[str, Any]] = {} 

def decode_mime_data(raw_email_data: str) -> dict[str, Any]:
    msg = email.message_from_string(raw_email_data)
    mime_data = {
        'headers': {},
        'is_multipart': msg.is_multipart(),
        'body': ""
    }
    
    # header
    target_headers = ['Subject', 'From', 'To', 'Content-Type', 'Date']
    for header in target_headers:
        if msg[header]:
            mime_data['headers'][header.lower()] = msg[header]
            
    # decode content
    try:
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    decoded = part.get_payload(decode=True)
                    if decoded:
                        parts.append(decoded.decode('utf-8', errors='replace'))
            mime_data['body'] = "\n---[Next Part]---\n".join(parts)
        else:
            decoded = msg.get_payload(decode=True)
            if decoded:
                mime_data['body'] = decoded.decode('utf-8', errors='replace')
    except Exception as e:
        mime_data['decode_error'] = str(e)
        
    return mime_data    
    
    
def parse(raw_packet: Any, event: IDSEvent) -> None:
    if not raw_packet.haslayer(Raw):
        event.app_proto = "UNKNOWN" 
        return
        
    try:
        # Lấy dòng đầu tiên của payload
        payload = raw_packet[Raw].load.decode('utf-8', errors='ignore')
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
                is_command = True 
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
            # start new active smtp session 
            event.app_data['is_mime'] = True 
            new_session: tuple = (event.src_ip, event.dst_ip, event.src_port, event.dst_port)
            session: dict[str, Any] = {
                "state": "receive_data",
                "buffer": payload 
            }
            active_smtp_sessions[new_session] = session 
            
            msg = email.message_from_string(payload) 
            mime_data = {}
            target_headers = ['Subject', 'From', 'To', 'Content-Type', 'Date', 'Content-Transfer-Encoding']
            for header in target_headers:
                if msg[header]:
                    mime_data[header.lower()] = msg[header] 

            event.app_data['mime_info'] = mime_data
            return
        
        

        # fallback: smtp/mime data fragment
        
        check_session = (event.src_ip, event.dst_ip, event.src_port, event.dst_port)
        if check_session in active_smtp_sessions:
            session = active_smtp_sessions[check_session] 
            event.app_data['is_mime'] = True 
            event.app_data['is_data_fragment'] = True 
            
            session["buffer"] += payload 
            if "\r\n.\r\n" in payload:
                event.app_data['end_mime'] = True
                # Cắt bỏ phần dấu kết thúc ra khỏi email
                clean_email_data = session["buffer"].split("\r\n.\r\n")[0]
                
                # Tiến hành decode tổng
                event.app_data['decoded_mime_data'] = decode_mime_data(clean_email_data)
                
                # Giải phóng bộ nhớ
                active_smtp_sessions.pop(check_session)
            else:
                event.app_data['buffered_length'] = len(session["buffer"])
            
            
            active_smtp_sessions[check_session] = session
            return
                
                
    except Exception as e:
        event.app_data = {"error": f"SMTP Parse Error: {e}"}