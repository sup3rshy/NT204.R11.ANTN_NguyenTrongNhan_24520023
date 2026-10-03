import urllib.parse
import html
import base64
import quopri
import logging
from models.event import IDSEvent 

logger = logging.getLogger(__name__)

class Decoder:
    def __init__(self):
        pass

    def decode_event(self, event: IDSEvent) -> None:
        """Xử lý event an toàn, không làm dừng chương trình nếu có lỗi."""
        try:
            # T01: HTTP URL/percent decoding
            if 'uri' in event.app_data:
                event.app_data['uri_decoded'] = urllib.parse.unquote(event.app_data['uri'])

            # T02: HTML entity decoding cho dữ liệu text
            if 'body' in event.app_data:
                event.app_data['body_decoded'] = html.unescape(event_data['body'])

            # T03: SMTP/MIME Base64 và Quoted-Printable
            if event_data.get('app_protocol') == 'SMTP' and 'mime_encoding' in event_data:
                event_data['smtp_body_decoded'], event_data['decode_status'] = self._decode_smtp(
                    event_data.get('smtp_body', ''), 
                    event_data['mime_encoding']
                )

            # T04: Character decoding tối thiểu ASCII và UTF-8
            if 'raw_payload' in event_data:
                event_data['payload_utf8'] = self._safe_utf8_decode(event_data['raw_payload'])
                
        except Exception as e:
            logger.error(f"Decoder error: {e}")
            event_data['decode_error'] = str(e)
            
        return event_data

    def _decode_smtp(self, body, encoding):
        try:
            if encoding.lower() == 'base64':
                return base64.b64decode(body).decode('utf-8', errors='replace'), 'success'
            elif encoding.lower() == 'quoted-printable':
                return quopri.decodestring(body.encode()).decode('utf-8', errors='replace'), 'success'
        except Exception:
            return body, 'failed'
        return body, 'unsupported'

    def _safe_utf8_decode(self, byte_data):
        """Không crash khi gặp byte sequence không hợp lệ."""
        if isinstance(byte_data, bytes):
            return byte_data.decode('utf-8', errors='replace')
        return byte_data