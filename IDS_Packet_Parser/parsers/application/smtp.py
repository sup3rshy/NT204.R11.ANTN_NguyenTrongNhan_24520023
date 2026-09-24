from typing import Any 
from models.event import IDSEvent
from scapy.all import * 


def parser(raw_packet: Any, event: IDSEvent) -> None:
    