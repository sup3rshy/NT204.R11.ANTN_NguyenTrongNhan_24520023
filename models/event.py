from dataclasses import dataclass, asdict 
from typing import Any 

@dataclass 
class IDSEvent:
    packet_id: int 
    timestamp: float | None = None 
    
    # network layer 
    src_ip: str | None = None 
    dst_ip: str | None = None 
    network_proto: str | None = None 
    
    # transport layer 
    src_port: int | None = None 
    dst_port: int | None = None 
    transport_proto: str = "UNKNOWN" 
    transport_flags: str | None = None 
    
    # application layer 
    app_proto: str = "UNKNOWN"
    app_data: dict[str, Any] | None = None 
    
    # use dict in python for compatible with json format output    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)