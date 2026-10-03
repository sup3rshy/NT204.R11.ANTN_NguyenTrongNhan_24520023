from typing import Any
from models.event import IDSEvent
from scapy.all import Raw
import email


active_smtp_sessions: dict[tuple, dict[str, Any]] = {}


def extract_raw_mime(raw_email_data: str) -> dict[str, Any]:
    """Phan tich MIME email tho, KHONG thuc hien decode Base64/QP tai parser."""
    msg = email.message_from_string(raw_email_data)
    mime_data: dict[str, Any] = {
        'headers': {},
        'is_multipart': msg.is_multipart(),
        'encoding': msg.get('Content-Transfer-Encoding', '').strip(),
        'body': ""
    }
    
    # Headers
    target_headers = ['Subject', 'From', 'To', 'Content-Type', 'Date', 'Content-Transfer-Encoding']
    for header in target_headers:
        val = msg[header]
        if val:
            mime_data['headers'][header.lower()] = val
            
    # Trich xuat raw body chua decode (decode=False) de chuyen cho Module Decoder xu ly
    try:
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    raw_part_payload = part.get_payload(decode=False)
                    if isinstance(raw_part_payload, str):
                        parts.append(raw_part_payload)
            mime_data['body'] = "\n---[Next Part]---\n".join(parts)
        else:
            raw_payload = msg.get_payload(decode=False)
            if isinstance(raw_payload, str):
                mime_data['body'] = raw_payload
    except Exception as e:
        mime_data['parse_error'] = str(e)
        
    return mime_data


def parse(raw_packet: Any, event: IDSEvent) -> None:
    if not raw_packet.haslayer(Raw):
        event.app_proto = "UNKNOWN" 
        return
        
    try:
        payload = raw_packet[Raw].load.decode('utf-8', errors='ignore')
        lines = payload.split('\r\n')
        if not lines:
            return
            
        first_line = lines[0]
        event.app_data = {}
        
        # 1. SMTP Command
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
                
        # 2. Extract SMTP status code
        if len(first_line) >= 4 and first_line[:3].isdigit() and first_line[3:4] in (' ', '-'):
            event.app_data['status_code'] = int(first_line[:3])
            event.app_data['message'] = first_line[4:].strip()
            return 
        
        # 3. MIME Header detection
        mime_indicators = ["Content-Type:", "Subject:", "From:", "To:", "MIME-Version:"]
        if any(x in payload for x in mime_indicators):
            event.app_data['is_mime'] = True 
            new_session: tuple = (event.src_ip, event.dst_ip, event.src_port, event.dst_port)
            active_smtp_sessions[new_session] = {
                "state": "receive_data",
                "buffer": payload 
            }
            
            raw_mime = extract_raw_mime(payload)
            event.app_data['mime_info'] = raw_mime.get('headers', {})
            event.app_data['mime_encoding'] = raw_mime.get('encoding', '')
            event.app_data['raw_body'] = raw_mime.get('body', '')
            return
        
        # 4. Fallback: SMTP / MIME data fragment & buffer assembly
        check_session = (event.src_ip, event.dst_ip, event.src_port, event.dst_port)
        if check_session in active_smtp_sessions:
            session = active_smtp_sessions[check_session] 
            event.app_data['is_mime'] = True 
            event.app_data['is_data_fragment'] = True 
            
            session["buffer"] += payload 
            if "\r\n.\r\n" in payload:
                event.app_data['end_mime'] = True
                clean_email_data = session["buffer"].split("\r\n.\r\n")[0]
                
                # Chi parse raw MIME structures - de Decoder xu ly Base64/QP
                raw_mime = extract_raw_mime(clean_email_data)
                event.app_data['mime_info'] = raw_mime.get('headers', {})
                event.app_data['mime_encoding'] = raw_mime.get('encoding', '')
                event.app_data['raw_body'] = raw_mime.get('body', '')
                
                active_smtp_sessions.pop(check_session, None)
            else:
                event.app_data['buffered_length'] = len(session["buffer"])
                active_smtp_sessions[check_session] = session
            return
                
    except Exception as e:
        event.app_data = {"error": f"SMTP Parse Error: {e}"}