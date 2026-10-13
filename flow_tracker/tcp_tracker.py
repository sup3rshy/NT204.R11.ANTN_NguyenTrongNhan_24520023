from models.flow import FlowRecord 


def update_tcp_state(flow: FlowRecord, tcp_flags: str | None, direction: str) -> None: 
    if not tcp_flags:
        return 
    
    if flow._fin_directions is None:
        flow._fin_directions = set() 
        
    if "SYN" in tcp_flags:
        flow.syn_count += 1
    if "ACK" in tcp_flags:
        flow.ack_count += 1
    if "FIN" in tcp_flags:
        flow.fin_count += 1 
        if direction:
            flow._fin_directions.add(direction)
        
    if "RST" in tcp_flags:
        flow.rst_count += 1 
        
    
    
    if "RST" in tcp_flags:
        flow.state = "CLOSED/RESET"
        return 
    
    cur_state = flow.state 
    if cur_state == "NEW/HANDSHAKE":
        if "ACK" in tcp_flags and "SYN" not in tcp_flags and flow.syn_count >= 1:
            flow.state = "ESTABLISHED"
        
    elif cur_state == "ESTABLISHED":
        # not close yettt !!! waiting for ACK 
        if "FIN" in tcp_flags:
            flow.state = "CLOSING"
            

    elif cur_state == "CLOSING":
        if len(flow._fin_directions) >= 2:
            flow.state = "CLOSED/RESET"