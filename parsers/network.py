from typing import Any
from scapy.all import * 
from models.event import IDSEvent 

def parse_network_layer(raw_packet: Any, event: IDSEvent) -> None: 
    if raw_packet.haslayer(IP):
        event.src_ip = raw_packet[IP].src 
        event.dst_ip = raw_packet[IP].dst 
        
        # this is default 
        event.network_proto = "IPv4" 
            