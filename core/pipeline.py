from typing import Any 
from datetime import datetime
from models.event import IDSEvent 
from parsers.network import parse_network_layer
from parsers.transport import parse_transport_layer 
from parsers.app_detector import detect_app_protocol
from parsers.application import http, dns, smtp 
from decoder import Decoder
# from preprocessor import Preprocessor
# from flow_tracker import FlowTracker
from core.logger import log_event


# Khởi tạo các module xử lý trung gian
decoder = Decoder()
preprocessor = Preprocessor()
# flow_tracker = FlowTracker()


def process_packet(raw_packet: Any, packet_id: int) -> None:
    # Lấy timestamp chính xác từ packet (nếu là PCAP) hoặc thời gian hiện tại (nếu live)
    if hasattr(raw_packet, "time") and raw_packet.time:
        pkt_time = float(raw_packet.time)
    else:
        pkt_time = datetime.now().timestamp()

    pkt_len = len(raw_packet) if hasattr(raw_packet, "__len__") else 0
    event = IDSEvent(packet_id=packet_id, timestamp=pkt_time, packet_len=pkt_len)
    
    try:
        # === BƯỚC 1: PACKET PARSING (Bài tập 1) ===
        parse_network_layer(raw_packet, event)
        parse_transport_layer(raw_packet, event)
        detect_app_protocol(raw_packet, event)  
        try:
            match event.app_proto:
                case "HTTP":
                    http.parse(raw_packet, event)
                case "DNS":
                    dns.parse(raw_packet, event)
                case "SMTP":
                    smtp.parse(raw_packet, event)
                case _:
                    pass 
        except Exception as e: 
            if event.app_data is None:
                event.app_data = {}
            event.app_data["parser_error"] = str(e)
            
        # === BƯỚC 2: DECODER (Module 1 - T01..T04) ===
        decoder.decode(event)

        # === BƯỚC 3: PREPROCESSOR (Module 2 - T05, T06, T14) ===
        preprocessor.process(event)

        # === BƯỚC 4: FLOW/CONNECTION TRACKER (Module 3 - T07..T13) ===
        # flow_tracker.process_event(event)

    except Exception as e:
        event.app_proto = "UNKNOWN"
        if event.app_data is None:
            event.app_data = {}
        event.app_data["pipeline_error"] = str(e)
        
    finally:
        # Ghi log kết quả chuẩn hóa
        log_event(event)