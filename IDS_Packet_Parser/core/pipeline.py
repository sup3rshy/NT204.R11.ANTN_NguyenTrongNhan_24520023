from typing import Any 
from models.event import IDSEvent 
from parsers.network import parse_network_layer
from parsers.transport import parse_transport_layer 
from parsers.app_detector import detect_app_protocol
from parsers.application import http, dns, smtp 
from core.logger import log_event


def process_packet(raw_packet: Any, packet_id: int) -> None:
    
    event = IDSEvent(packet_id = packet_id)
    
    try:
        parse_network_layer(raw_packet, event)
        parse_transport_layer(raw_packet, event)
        detect_app_protocol(raw_packet, event)  
        
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
        event.app_proto = "UNKNOWN"
        event.app_data = {"error": str(e)}
        
    finally:
        log_event(event)
                