import os
import requests
import urllib3
import logging
from datetime import datetime, timezone

logging.basicConfig(
    filename="/home/haw/enrich.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

urllib3.disable_warnings()

indexer_url = "https://localhost:9200/wazuh-alerts-*/_search"
indexer_auth = (os.environ["INDEXER_USER"], os.environ["INDEXER_PASSWORD"])
abuseipdb_api_key = os.environ["ABUSEIPDB_KEY"]
abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
ipinfo_token = os.environ["IPINFO_TOKEN"]
collected_at = datetime.now(timezone.utc).isoformat()

query = {
    "size": 0,
    "query": {"match": {"rule.groups": "cowrie"}},
    "aggs": {
        "attacker_ips": {
            "terms": {"field": "data.src_ip", "size": 500}
        }
    }
}

indexer_response = requests.post(indexer_url, auth=indexer_auth, json=query, verify=False)
indexer_data = indexer_response.json()
buckets = indexer_data["aggregations"]["attacker_ips"]["buckets"]

ips = []

for bucket in buckets:
    if bucket["doc_count"] >= 100:
        ips.append(bucket)
    
logging.info(f"Enriching {len(ips)} IPs")   

for bucket in ips:
    ip = bucket["key"]
    event_count = bucket["doc_count"]
    ipinfo_url = f"https://api.ipinfo.io/lite/{ip}?token={ipinfo_token}"
    headers = {"Key": abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        abuseipdb_response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=10)
        abuseipdb_data = abuseipdb_response.json()
        
        ipinfo_response = requests.get(ipinfo_url, timeout=10)
        ipinfo_data = ipinfo_response.json()
    except Exception as error:
        logging.error(f"Lookup failed for {ip}: {error}")
        continue    

    if "data" not in abuseipdb_data:
        logging.warning(f"AbuseIPDB failed for {ip}: {abuseipdb_data}")
        continue
    
    abuseipdb_info = abuseipdb_data["data"]

    

    record = {
    "ip": ip,
    "abuse_confidence": abuseipdb_info.get("abuseConfidenceScore", -1),
    "usage_type": abuseipdb_info.get("usageType", "unknown"),
    "isp": abuseipdb_info.get("isp", "unknown"),
    "total_reports": abuseipdb_info.get("totalReports", -1),
    "asn": ipinfo_data.get("asn", "unknown"),
    "as_name": ipinfo_data.get("as_name", "unknown"),
    "country_code": abuseipdb_info.get("countryCode", "unknown"),
    "event_count": event_count,
    "collected_at": collected_at,
    }

    logging.info(f"Indexed {ip}")
    
    requests.post("https://localhost:9200/honeypot-auto/_doc", auth=indexer_auth, json=record, verify=False, timeout=10)
    


