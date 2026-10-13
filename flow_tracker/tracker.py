import hashlib
import logging
from typing import Tuple, List, Optional
from models.event import IDSEvent
from models.flow import FlowRecord
from .state_table import FlowStateTable
from .tcp_tracker import update_tcp_state
from .udp_tracker import update_udp_flow

logger = logging.getLogger(__name__)


class FlowTracker:
    """MODULE 3: Quản lý luồng (Flow/Connection Tracker).
    Gom các packet cùng phiên giao tiếp thành flow hai chiều, duy trì trạng thái và thống kê.
    """

    def __init__(self, tcp_idle_timeout: float = 300.0, udp_idle_timeout: float = 30.0) -> None:
        self.state_table = FlowStateTable(tcp_idle_timeout, udp_idle_timeout)

    def generate_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[str, bool]:
        """T08: Tạo flow_id ổn định cho cả hai chiều A->B và B->A.
        Trả về (flow_id, is_canonical_forward).
        """
        endpoint_1 = (src_ip, src_port)
        endpoint_2 = (dst_ip, dst_port)

        # Định chuẩn thứ tự hai đầu để chiều nào cũng ra cùng một flow_id
        if endpoint_1 <= endpoint_2:
            canonical_repr = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
            is_forward = True
        else:
            canonical_repr = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
            is_forward = False

        flow_hash = hashlib.sha256(canonical_repr.encode()).hexdigest()[:16]
        return f"flow_{flow_hash}", is_forward

    def process_event(self, event: IDSEvent) -> Optional[FlowRecord]:
        """Xử lý gắn event vào flow, cập nhật thống kê và trạng thái."""
        if not event.src_ip or not event.dst_ip:
            return None

        proto = event.transport_proto or "OTHER"
        src_port = event.src_port or 0
        dst_port = event.dst_port or 0

        # 1. T08: Nhận diện bidirectional flow_id
        flow_id, is_canonical_forward = self.generate_flow_id(
            event.src_ip, event.dst_ip, src_port, dst_port, proto
        )

        pkt_time = event.timestamp if event.timestamp is not None else 0.0
        pkt_len = event.packet_len or 0

        # Hàm tạo flow mới nếu chưa tồn tại
        def create_new_flow() -> FlowRecord:
            return FlowRecord(
                flow_id=flow_id,
                protocol=proto,
                application_protocol=event.app_proto,
                endpoint_a=(event.src_ip, src_port),
                endpoint_b=(event.dst_ip, dst_port),
                start_time=pkt_time,
                last_seen=pkt_time,
                duration=0.0,
                state="NEW/HANDSHAKE" if proto == "TCP" else "ACTIVE"
            )

        # 2. T11: Lấy hoặc tạo mới flow
        flow, is_new = self.state_table.get_or_create(flow_id, create_new_flow)

        # Xác định direction của packet so với initiator (endpoint_a)
        if event.src_ip == flow.endpoint_a[0] and src_port == flow.endpoint_a[1]:
            direction = "forward"
        else:
            direction = "backward"

        # Gắn metadata vào event
        event.flow_id = flow.flow_id
        event.flow_direction = direction

        # 3. T13: Cập nhật thống kê
        flow.last_seen = pkt_time
        flow.duration = round(max(0.0, flow.last_seen - flow.start_time), 6)
        flow.packet_count += 1
        flow.byte_count += pkt_len

        if direction == "forward":
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += pkt_len
        else:
            flow.bwd_packet_count += 1
            flow.bwd_byte_count += pkt_len

        # Cập nhật application protocol nếu phát hiện sau
        if flow.application_protocol in ("UNKNOWN", None) and event.app_proto != "UNKNOWN":
            flow.application_protocol = event.app_proto

        # 4. T07, T09, T10: Cập nhật state machine  
        if proto == "TCP":
            update_tcp_state(flow, event.transport_flags, direction)
        elif proto == "UDP":
            update_udp_flow(flow)

        # 5. T12: Kiểm tra timeout định kỳ
        self.state_table.check_timeouts(pkt_time)
        
        event.flow_state = flow.state 
        return flow

    def flush_expired(self, current_time: float) -> List[FlowRecord]:
        """Xử lý T12: Giải phóng và xuất các flow hết hạn."""
        return self.state_table.check_timeouts(current_time)