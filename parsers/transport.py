from typing import Any 
from scapy.all import *
from models.event import IDSEvent


def parse_transport_layer(raw_packet: Any, event: IDSEvent) -> None:
    if raw_packet.haslayer(TCP):
        event.transport_proto = "TCP"
        event.src_port = raw_packet[TCP].sport 
        event.dst_port = raw_packet[TCP].dport 
        
        flags = []
        tcp = raw_packet[TCP]
        
        if tcp.flags & 0x01:
            flags.append("FIN")
        
        if tcp.flags & 0x02:
            flags.append("SYN")
            
        if tcp.flags & 0x04:
            flags.append("RST")
            
        if tcp.flags & 0x08:
            flags.append("PSH")
        
        if tcp.flags & 0x10:
            flags.append("ACK")
        
        if tcp.flags & 0x20:
            flags.append("URG")
            
        event.transport_flags = ' '.join(x for x in flags)
        # parse flags here - not implemented 
        
        
    elif raw_packet.haslayer(UDP):
        event.transport_proto = "UDP"
        event.src_port = raw_packet[UDP].sport 
        event.dst_port = raw_packet[UDP].dport 
        # udp has no flags! 
        