from typing import Any 
import logging 
from pathlib import Path 
from scapy.all import *
from core.pipeline import * 


logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self) -> None:
        self._packet_counter: int = 0
        
    def start_live_capture(self, interface: str) -> None:
        logger.info(f"Start live capture on interface = {interface}")
        
        try:
            sniff(iface = interface, prn = self._packet_handler, store = False)
        except Exception as e:
            logger.error(f"sniff failed with error: {e}")
            
    
    
    def start_pcap_import(self, pcap_file: Path) -> None:
        if pcap_file.exists() == False:
            logger.info(f'File {pcap_file} not exists')
            
        
        logger.info(f"Start reading pcap file = {pcap_file}")
        
        from scapy.utils import PcapReader 
        with PcapReader(str(pcap_file)) as pcap_reader:
            for packet in pcap_reader:
                self._packet_handler(packet)
    
    def _packet_handler(self, raw_packet: Any) -> None:
        # IPv4 only 
        if raw_packet.haslayer(IP):
            self._packet_counter += 1 
            process_packet(raw_packet, self._packet_counter)
            