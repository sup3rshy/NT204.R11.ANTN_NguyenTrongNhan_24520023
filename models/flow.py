from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class FlowRecord:
    # 5.4. Thong ke toi thieu tren moi flow (Yeu cau De bai 2)
    flow_id: str
    protocol: str = "UNKNOWN"
    application_protocol: str = "UNKNOWN"
    endpoint_a: tuple[str, int] = ("", 0)
    endpoint_b: tuple[str, int] = ("", 0)

    # Thoi gian
    start_time: float = 0.0
    last_seen: float = 0.0
    duration: float = 0.0

    # Tong the
    packet_count: int = 0
    byte_count: int = 0

    # Hai chieu
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0

    # TCP counters & state
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str = "NEW/HANDSHAKE"

    # Active status
    is_active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)