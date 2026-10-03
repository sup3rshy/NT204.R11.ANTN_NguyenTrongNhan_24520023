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
    
    # packet metadata
    packet_len: int = 0
    raw_payload: bytes | None = None

    # module 1: decoder metadata
    decode_status: str | None = None
    decode_error: str | None = None

    # module 2: preprocessor metadata
    preprocess_status: str | None = None
    processing_action: str | None = None
    preprocess_reason: str | None = None

    # module 3: flow tracker metadata
    flow_id: str | None = None
    flow_direction: str | None = None
    
    # use dict in python for compatible with json format output    
    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("raw_payload"), bytes):
            # serialize bytes for JSON compatibility
            data["raw_payload"] = data["raw_payload"].hex()
        return data