import os
import requests
import urllib3
import logging
from datetime import datetime, timezone

logging.basicConfig(
    filename="/home/haw/newbehaviour.log",
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)

urllib3.disable_warnings()

indexer_auth = (os.environ["INDEXER_USER"], os.environ["INDEXER_PASSWORD"])
seen_at = datetime.now(timezone.utc).isoformat()

query = {
    "size": 0,
    "aggs": {
        "commands": {
            "terms": {"field": "data.input", "size": 1000}
        }
    }
}

alerts_url = "https://localhost:9200/wazuh-alerts-*/_search"

alerts_response = requests.post(alerts_url, auth=indexer_auth, json=query, verify=False, timeout=10)
alerts_data = alerts_response.json()
commands = alerts_data["aggregations"]["commands"]["buckets"]

logging.info(f"Found {len(commands)} distinct commands")

seen_url = "https://localhost:9200/honeypot-seen/_search"

seen_query ={
    "size": 0,
    "aggs": {
        "known": {
            "terms": {"field": "command", "size": 10000}
                }
    }
}    

seen_response = requests.post(seen_url, auth=indexer_auth, json=seen_query, verify=False, timeout=10)
seen_data = seen_response.json()
seen_buckets = seen_data["aggregations"]["known"]["buckets"]

known_commands = set()

for bucket in seen_buckets:
    known_commands.add(bucket["key"])
    
logging.info(f"{len(known_commands)} commands already known")

for bucket in commands:
    command = bucket["key"]
    times_run = bucket["doc_count"]
    if command in known_commands:
        continue
    logging.warning(f"NEW COMMAND: {command} (run {times_run} times)")
    record = {
        "command": command,
        "first_seen": seen_at,
        "times_run": times_run
    }
    requests.post("https://localhost:9200/honeypot-seen/_doc", auth=indexer_auth, json=record, verify=False, timeout=10)