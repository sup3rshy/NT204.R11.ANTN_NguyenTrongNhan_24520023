import logging
from typing import Any
from models.event import IDSEvent
from .validator import validate_event
from .normalizer import normalize_event

logger = logging.getLogger(__name__)


class Preprocessor:
    """MODULE 2: Tiền xử lý (Preprocessor).
    Kiểm tra tính hợp lệ (Validation) và chuẩn hóa (Normalization) dữ liệu
    để các module IDS phía sau nhận một biểu diễn nhất quán.
    """

    def __init__(self, drop_invalid: bool = False) -> None:
        self.drop_invalid = drop_invalid

    def process(self, event: IDSEvent) -> None:
        """Xử lý toàn diện Validation, Normalization, Missing fields cho IDSEvent."""
        try:
            # 1. T14: Validation
            status, reasons = validate_event(event)
            event.preprocess_status = status
            if reasons:
                event.preprocess_reason = "; ".join(reasons)

            # 2. Gán processing_action theo cấu hình
            if status == "invalid":
                event.processing_action = "drop" if self.drop_invalid else "alert"
            else:
                event.processing_action = "forward"

            # 3. T06: Xử lý missing / unsupported data nhất quán, không crash
            self._handle_missing_fields(event)

            # 4. T05: Normalization
            normalize_event(event)

        except Exception as e:
            logger.error(f"[Preprocessor] Lỗi ngoại lệ tại packet {event.packet_id}: {e}")
            event.preprocess_status = "invalid"
            event.preprocess_reason = f"Unhandled preprocessor exception: {e}"
            event.processing_action = "drop" if self.drop_invalid else "alert"

    def _handle_missing_fields(self, event: IDSEvent) -> None:
        """Xử lý T06: Đảm bảo các field thiếu nhận giá trị mặc định nhất quán (None, [], {}), không sinh ngoại lệ."""
        if event.app_data is None:
            event.app_data = {}

        if event.app_proto == "DNS":
            if "response_data" not in event.app_data:
                event.app_data["response_data"] = []
            if "query_domain" not in event.app_data:
                event.app_data["query_domain"] = None

        elif event.app_proto == "HTTP":
            if "headers" not in event.app_data:
                event.app_data["headers"] = {}
            if "body" not in event.app_data:
                event.app_data["body"] = None

        elif event.app_proto == "SMTP":
            if "mime_info" not in event.app_data:
                event.app_data["mime_info"] = {}
            if "raw_body" not in event.app_data:
                event.app_data["raw_body"] = None
