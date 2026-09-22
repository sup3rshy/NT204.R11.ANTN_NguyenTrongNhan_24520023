import json
from pathlib import Path 
from models.event import IDSEvent 
from datetime import datetime 


current_time = datetime.datetime().now().strftime("%Y%m%d_%H%M%S")

LOG_FILE = Path(f'ids_output_{current_time}.json') 

def log_event(event: IDSEvent) -> None:
    
    with LOG_FILE.open(mode = "a", encoding = "utf-8") as f:
        f.write(json.dumps(event.to_dict()) + '\n') 