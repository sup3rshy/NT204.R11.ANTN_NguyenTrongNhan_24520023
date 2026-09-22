#!/usr/bin/python3 
import argparse 
from core.capture import PacketCapture 
from pathlib import Path 

def main() -> None:
    parser = argparse.  ArgumentParser()
    
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument("--interface", type = str, help = "interface name for live capture")
    group.add_argument("--pcap", type = Path, help = "path to pcap file") 
    
    args = parser.parse_args()
    capture_module = PacketCapture() 
    
    if args.interface:
        capture_module.start_live_capture(args.interface)
        
    elif args.pcap:
        capture_module.start_pcap_import(args.pcap) 
    

if __name__ == "__main__": 
    main() 