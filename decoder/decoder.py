import logging
from typing import Any
from models.event import IDSEvent
from .url import decode_url, decode_form_urlencoded
from .html import decode_html_entities
from .mime import decode_mime

logger = logging.getLogger(__name__)


class Decoder:
    """MODULE 1: Giải mã dữ liệu (Decoder).
    Chuyển dữ liệu ở dạng mã hóa / biểu diễn sang dạng có thể phân tích,
    không thay đổi ý nghĩa logic của dữ liệu và không làm dừng chương trình khi gặp lỗi.
    """

    def __init__(self) -> None:
        pass

    def decode(self, event: IDSEvent) -> None:
        """Điều phối giải mã toàn diện cho một IDSEvent."""
        try:
            # 1. T04: Safe character decoding cho raw_payload (nếu có)
            if event.raw_payload is not None:
                self._safe_char_decode(event)

            if event.app_data is None:
                event.app_data = {}

            # 2. T01 & T02: Xử lý cho HTTP
            if event.app_proto == "HTTP":
                self._decode_http(event)

            # 3. T03: Xử lý cho SMTP / MIME
            elif event.app_proto == "SMTP":
                self._decode_smtp(event)

            # Nếu chưa có decode_status và không có lỗi, mặc định gán success nếu đã decode
            if not event.decode_status:
                event.decode_status = "success"

        except Exception as e:
            logger.error(f"[Decoder] Lỗi ngoại lệ khi decode packet {event.packet_id}: {e}")
            event.decode_status = "partial"
            event.decode_error = str(e)

    def _safe_char_decode(self, event: IDSEvent) -> None:
        """Xử lý T04: Kiểm tra và giải mã UTF-8/ASCII an toàn."""
        raw = event.raw_payload
        if not isinstance(raw, bytes):
            return

        try:
            # Thử decode nghiêm ngặt để phát hiện invalid bytes
            raw.decode("utf-8")
        except UnicodeDecodeError as ue:
            # T04: Payload không phải UTF-8 hợp lệ -> đánh dấu partial, không crash
            event.decode_status = "partial"
            event.decode_error = f"Invalid UTF-8 sequence: {ue}"
            if event.app_data is None:
                event.app_data = {}
            # Thay thế ký tự lỗi an toàn
            event.app_data["safe_payload_text"] = raw.decode("utf-8", errors="replace")

    def _decode_http(self, event: IDSEvent) -> None:
        app_data = event.app_data
        if not app_data:
            return

        # T01: URI percent decoding (giữ nguyên raw uri, lưu thêm uri_decoded)
        if "uri" in app_data and isinstance(app_data["uri"], str):
            app_data["uri_decoded"] = decode_url(app_data["uri"])

        # T01: Form urlencoded nếu là POST
        headers = app_data.get("headers", {})
        content_type = headers.get("content-type", "").lower() if isinstance(headers, dict) else ""
        if "application/x-www-form-urlencoded" in content_type and "body" in app_data:
            app_data["form_data"] = decode_form_urlencoded(app_data["body"])

        # T02: HTML entity decoding cho text/html body hoặc text bất kỳ
        if "body" in app_data and isinstance(app_data["body"], str):
            app_data["body_decoded"] = decode_html_entities(app_data["body"])

    def _decode_smtp(self, event: IDSEvent) -> None:
        app_data = event.app_data
        if not app_data:
            return

        # T03: SMTP Base64 và Quoted-Printable khi header chỉ ra encoding
        raw_body = app_data.get("raw_body")
        encoding = app_data.get("mime_encoding")

        if raw_body and encoding:
            decoded_text, status = decode_mime(raw_body, encoding)
            app_data["decoded_body"] = decoded_text
            app_data["decode_status"] = status
            event.decode_status = status
            if status == "failed":
                event.decode_error = f"Failed to decode MIME with encoding {encoding}"

