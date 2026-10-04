import html


def decode_html_entities(text: str) -> str:
    """Xử lý T02: HTML entity decoding cho dữ liệu text phù hợp.
    Ví dụ: &lt;script&gt; -> <script>
    """
    if not isinstance(text, str):
        return text
    try:
        return html.unescape(text)
    except Exception:
        return text

