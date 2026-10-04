import urllib.parse
from typing import Any


def decode_url(uri: str) -> str:
    """Xử lý T01: HTTP URL / percent-decoding.
    Ví dụ: %27%20OR%201%3D1 -> ' OR 1=1
    """
    if not isinstance(uri, str):
        return uri
    try:
        return urllib.parse.unquote(uri)
    except Exception:
        return uri


def decode_form_urlencoded(data: str) -> dict[str, list[str]]:
    """Giải mã dữ liệu form POST application/x-www-form-urlencoded."""
    if not isinstance(data, str):
        return {}
    try:
        return urllib.parse.parse_qs(data, keep_blank_values=True)
    except Exception:
        return {}

