import base64
import quopri
from typing import Tuple


def decode_mime(body: str, encoding: str) -> Tuple[str, str]:
    """Xử lý T03: SMTP Base64 và Quoted-Printable khi header chỉ ra encoding.
    Trả về (decoded_body, decode_status).
    decode_status có thể là: 'success', 'failed', 'unsupported'.
    """
    if not body:
        return body, "success"

    norm_enc = (encoding or "").strip().lower()

    if not norm_enc or norm_enc in ("7bit", "8bit", "binary"):
        return body, "success"

    try:
        if norm_enc == "base64":
            raw_bytes = base64.b64decode(body.strip().encode("ascii", errors="ignore"))
            decoded_text = raw_bytes.decode("utf-8", errors="replace")
            return decoded_text, "success"

        elif norm_enc in ("quoted-printable", "quopri"):
            raw_bytes = quopri.decodestring(body.encode("utf-8", errors="ignore"))
            decoded_text = raw_bytes.decode("utf-8", errors="replace")
            return decoded_text, "success"

        else:
            return body, "unsupported"

    except Exception:
        return body, "failed"

