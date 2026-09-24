from typing import Any
from models.event import IDSEvent 
from scapy.all import * 


def parse(raw_packet: Any, event: IDSEvent) -> None: 
    if not raw_packet.haslayer(DNS):
        return 
    
    dns = raw_packet[DNS]
    
    try:
        event.app_data = {}
        
        if dns.qr == 0:
            event.app_data["type"] = "QUERY"
        elif dns.qr == 1:
            event.app_data["type"] = "RESPONSE"
            
        if dns.qdcount:
            event.app_data["query_domain"] = dns.qd.qname.decode('utf-8', errors = "ignore").rstrip('.')
            event.app_data["query_type"] = dns.qd.qtype 
            
        if dns.ancount:
            event.app_data["response_name"] = dns.an[0].rrname.decode('utf-8', errors = "ignore").rstrip('.')
            event.app_data["response_data"] = []
            for i in range(dns.ancount):
                rdata = dns.an[i].rdata 
                if isinstance(rdata, bytes):
                    rdata = rdata.decode('utf-8', errors = "ignore")
                event.app_data["response_data"].append(rdata.rstrip('.'))
        
    except Exception as e:
        event.app_data = {"error": str(e)}
    