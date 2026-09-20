#!/usr/bin/python3 
import argparse 

def main():
    parser = argparse.ArgumentParser()
    
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument("--interface", type = str, help = "interface name for live capture")
    group.add_argument("--pcap", type = str, help = "path to pcap file") 
    
    args = parser.parse_args()
    if args.interface:
        pass
    elif args.pcap:
        pass 
    

if __name__ == "__main__": 
    main() 