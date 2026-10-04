import re
from typing import Dict, Any
from models.event import IDSEvent


def normalize_protocol_name(proto: str | None) -> str:
    """Chuẩn hóa tên protocol về dạng chữ hoa thống nhất."""
    if not proto:
        return "UNKNOWN"
    norm = proto.strip().upper()
    if norm in ("IPV4", "IP"):
        return "IPv4"
    return norm


def normalize_domain(domain: str | None) -> str | None:
    """Chuẩn hóa domain: chữ thường, loại bỏ dấu chấm kết thúc (FQDN dot)."""
    if not domain or not isinstance(domain, str):
        return None
    return domain.strip().lower().rstrip('.')


def normalize_headers(headers: Dict[str, Any] | None) -> Dict[str, Any]:
    """Chuẩn hóa HTTP header names về chữ thường để tra cứu nhất quán."""
    if not headers or not isinstance(headers, dict):
        return {}
    normalized = {}
    for k, v in headers.items():
        if isinstance(k, str):
            clean_val = v.strip() if isinstance(v, str) else v
            normalized[k.strip().lower()] = clean_val
    return normalized


def normalize_uri_path(uri: str | None) -> str | None:
    """Chuẩn hóa an toàn URI/Path (loại bỏ double slash thừa)."""
    if not uri or not isinstance(uri, str):
        return None
    cleaned = uri.strip()
    # Loại bỏ double slash trùng lặp nhưng giữ lại schema http:// hoặc https://
    if "://" in cleaned:
        schema, rest = cleaned.split("://", 1)
        rest = re.sub(r'/{2,}', '/', rest)
        return f"{schema}://{rest}"
    else:
        return re.sub(r'/{2,}', '/', cleaned)


def normalize_event(event: IDSEvent) -> None:
    """Xử lý T05: Chuẩn hóa toàn bộ các trường trong IDSEvent."""
    # 1. Chuẩn hóa protocol names
    event.network_proto = normalize_protocol_name(event.network_proto)
    event.transport_proto = normalize_protocol_name(event.transport_proto)
    event.app_proto = normalize_protocol_name(event.app_proto)

    # 2. Chuẩn hóa IP
    if event.src_ip:
        event.src_ip = event.src_ip.strip()
    if event.dst_ip:
        event.dst_ip = event.dst_ip.strip()

    # 3. Chuẩn hóa timestamp (làm tròn số thực 6 chữ số thập phân)
    if event.timestamp is not None:
        event.timestamp = round(float(event.timestamp), 6)

    # 4. Chuẩn hóa dữ liệu Application Layer
    if event.app_data and isinstance(event.app_data, dict):
        app_data = event.app_data
        
        # DNS domain normalization
        if "query_domain" in app_data and isinstance(app_data["query_domain"], str):
            app_data["query_domain"] = normalize_domain(app_data["query_domain"])
        if "response_name" in app_data and isinstance(app_data["response_name"], str):
            app_data["response_name"] = normalize_domain(app_data["response_name"])

        # HTTP headers & URI normalization
        if "headers" in app_data and isinstance(app_data["headers"], dict):
            app_data["headers"] = normalize_headers(app_data["headers"])
        if "uri" in app_data and isinstance(app_data["uri"], str):
            app_data["uri"] = normalize_uri_path(app_data["uri"])
        if "uri_decoded" in app_data and isinstance(app_data["uri_decoded"], str):
            app_data["uri_decoded"] = normalize_uri_path(app_data["uri_decoded"])
