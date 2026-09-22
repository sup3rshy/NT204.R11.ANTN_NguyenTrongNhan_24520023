import logging 
from pathlib import Path 

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self) -> None:
        self._packet_counter: int = 0
        
    def start_live_capture(self, interface: str) -> None:
        logger.info(f"Start live capture on interface = {interface}")
        pass # Not implemented
    
    
    def start_pcap_import(self, pcap_file: Path) -> None:
        if pcap_file.exists() == FALSE:
            logger.info(f'File {pcap_file} not exists')
            
        
        logger.info(f"Start reading pcap file = {pcap_file}")
        
        pass # Not implemented 
    
    def _packet_handler(self, raw_packet: Any) -> None:
        self._packet_counter += 1 
        # process packet here, not implemented 
        pass # not implemented 