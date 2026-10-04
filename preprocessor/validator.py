import ipaddress
from typing import Tuple, List
from models.event import IDSEvent


def validate_event(event: IDSEvent) -> Tuple[str, List[str]]:
    """Xử lý T14: Kiểm tra field bắt buộc, port/range hợp lệ, timestamp, protocol.
    Gắn valid/partial/invalid và danh sách reason.
    """
    reasons: List[str] = []
    
    # 1. Kiểm tra timestamp
    if event.timestamp is None or not isinstance(event.timestamp, (int, float)) or event.timestamp < 0:
        reasons.append("Invalid or missing timestamp")

    # 2. Kiểm tra IP (bắt buộc đối với IPv4 network layer)
    if not event.src_ip or not event.dst_ip:
        reasons.append("Missing source or destination IP")
    else:
        for ip, label in ((event.src_ip, "src_ip"), (event.dst_ip, "dst_ip")):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                reasons.append(f"Invalid IP address format in {label}: {ip}")

    # 3. Kiểm tra Port range (0 - 65535) nếu là TCP hoặc UDP
    if event.transport_proto in ("TCP", "UDP"):
        for port, label in ((event.src_port, "src_port"), (event.dst_port, "dst_port")):
            if port is None:
                reasons.append(f"Missing {label} for transport protocol {event.transport_proto}")
            elif not isinstance(port, int) or port < 0 or port > 65535:
                reasons.append(f"Port out of valid range (0-65535) in {label}: {port}")

    # 4. Xác định status dựa trên kết quả kiểm tra
    if not reasons:
        return "valid", []
    
    # Nếu thiếu IP hoặc port sai dải hoàn toàn -> invalid; nếu chỉ thiếu field phụ -> partial
    critical_errors = [r for r in reasons if "IP" in r or "range" in r]
    if critical_errors:
        return "invalid", reasons
    else:
        return "partial", reasons
