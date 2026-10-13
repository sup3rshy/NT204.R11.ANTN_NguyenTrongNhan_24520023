from typing import Dict, List, Callable, Tuple
from models.flow import FlowRecord


class FlowStateTable:
    """Xử lý T11, T12: Bảng băm lưu trữ active flows và xử lý timeout."""

    def __init__(self, tcp_idle_timeout: float = 300.0, udp_idle_timeout: float = 30.0) -> None:
        self.active_flows: Dict[str, FlowRecord] = {}
        self.tcp_idle_timeout: float = tcp_idle_timeout
        self.udp_idle_timeout: float = udp_idle_timeout

    def get_or_create(self, flow_id: str, creator_fn: Callable[[], FlowRecord]) -> Tuple[FlowRecord, bool]:
        """T11: Lấy flow hiện có hoặc khởi tạo flow mới."""
        if flow_id in self.active_flows:
            return self.active_flows[flow_id], False
        
        flow = creator_fn()
        self.active_flows[flow_id] = flow
        return flow, True

    def check_timeouts(self, current_time: float) -> List[FlowRecord]:
        """Xử lý T12: Quét và giải phóng các flow đã hết hạn (idle timeout) khỏi active table."""
        expired_flows: List[FlowRecord] = []
        expired_keys: List[str] = []

        for flow_id, flow in self.active_flows.items():
            timeout = self.tcp_idle_timeout if flow.protocol == "TCP" else self.udp_idle_timeout
            # Kiểm tra thời gian không hoạt động
            if (current_time - flow.last_seen) > timeout:
                flow.is_active = False
                expired_flows.append(flow)
                expired_keys.append(flow_id)

        for key in expired_keys:
            del self.active_flows[key]

        return expired_flows

    def remove(self, flow_id: str) -> FlowRecord | None:
        """Loại bỏ thủ công một flow khi đã đóng hoàn toàn."""
        return self.active_flows.pop(flow_id, None) 

    def count(self) -> int:
        return len(self.active_flows)
