from models.flow import FlowRecord


def update_udp_flow(flow: FlowRecord) -> None:
    """Xử lý T10: Quản lý flow UDP không trạng thái.
    Các gói tin UDP cùng 5-tuple trong thời gian hợp lệ được gom thành một flow.
    """
    flow.state = "ACTIVE"
