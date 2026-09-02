# Honeypot Automation

Two daily scripts and two dashboards. Enrichment that would otherwise be manual, and detection of behaviour that hasn't been seen before.

**Runs on:** Wazuh VM - where the alerts, the indexer and dashboards are.
**Schedule:** cron, daily.

---

## Why these three things

| Need | Built as | Why |
|---|---|---|
| Context on attacking IPs | `enrich.py` | Requires external APIs. A dashboard can't call out. |
| Spot new attacker behaviour | `newbehaviour.py` | A dashboard can't compare periods and surface what's new. |
| Daily situational view | Dashboards | Live, filterable, no code needed. |

**There is no daily summary script.** A dashboard filtered to the last 24 hours *is* the summary. Writing a script to compute the same figures and dump them somewhere produces a worse copy of what's already on screen.

The two scripts exist because each does something a dashboard structurally cannot.

---

## Data flow

```
wazuh-alerts-*  ->  enrich.py        ->  honeypot-auto  ->  enrichment dashboard
                    AbuseIPDB + ipinfo

wazuh-alerts-*  ->  newbehaviour.py  ->  honeypot-seen  ->  WARNING in log
                    compare against baseline

wazuh-alerts-*  ->  activity dashboard
```

---

## enrich.py

Replaces the manual lookup work done during triage: pasting each source IP into AbuseIPDB and ipinfo and recording ASN, org, country, and abuse score by hand.

| Step | Detail |
|---|---|
| 1 | Terms aggregation on `data.src_ip`, filtered `rule.groups: cowrie` |
| 2 | Keep IPs at or above the event threshold |
| 3 | AbuseIPDB - abuse score, usage type, ISP, report count |
| 4 | ipinfo - ASN number and name |
| 5 | Write one document per IP to `honeypot-auto` |

**Aggregation, not document retrieval.** An aggregation groups by source IP and returns only the list of IPs and their counts. Document retrieval returns every matching alert in full, leaving the script to loop through them and tally the IPs itself - thousands of documents across the network to produce a few hundred lines.

### The event threshold

The aggregation returns every source IP that has ever hit the honeypot. Most have a handful of events - a connect and a disconnect, no session, no commands.

Enriching all of them spends the AbuseIPDB free tier (1,000 checks/day) in two runs, on IPs that did nothing. The threshold keeps the sources carrying real traffic and discards background noise. It also drops the testing IP, which sits well below it.

### Two sources, deliberate overlap

| Field | AbuseIPDB | ipinfo |
|---|---|---|
| org name | `isp` | `as_name` |
| country | `countryCode` | `country_code` |
| ASN number | - | `asn` |
| abuse score | `abuseConfidenceScore` | - |
| usage type | `usageType` | - |

ipinfo only adds the ASN number outright. The rest duplicates AbuseIPDB - but not always. Layered registration is deliberate in bulletproof hosting, and the disagreement between the two fields is what exposes it.

Storing one field would look tidier and lose the finding. Both are kept, named after their source.

### Record shape

```
ip, abuse_confidence, usage_type, isp, total_reports,
asn, as_name, country_code, event_count, collected_at
```

`collected_at` is set once per run, so every document from one run shares a timestamp and a batch can be filtered as a unit.

`event_count` is the count at collection time, carried through from the aggregation rather than looked up separately.

---

## newbehaviour.py

The activity dashboard lists every command ever run on the honeypot. It cannot say which one appeared for the first time this morning - that needs a record of what was already known.

| Step | Detail |
|---|---|
| 1 | Terms aggregation on `data.input` |
| 2 | Read every command already in `honeypot-seen` into a set |
| 3 | Anything not in the set is logged at WARNING and written to `honeypot-seen` |

**New commands are logged at WARNING**, everything routine at INFO, so they can be pulled out on their own:

```bash
grep WARNING /home/haw/newbehaviour.log
```

**The first run flags everything.** That establishes the baseline. Runs after it are silent unless something genuinely new arrives.

### Record shape

```
command, first_seen, times_run
```

`command` is mapped as `keyword`, not `text`. The comparison needs exact matching, and `text` would break commands into words.

`times_run` is a snapshot from the day of discovery and never updates. The field answers *when this appeared*, not how often it happened.

---

## Dashboards

Two index patterns: `honeypot-auto` on `collected_at`, `wazuh-alerts-*` on `timestamp`. One time picker per dashboard controls every panel.

### Honeypot enrichment - who

| Panel | Metric | Bucket |
|---|---|---|
| Top ASNs by event volume | Sum `event_count` | `as_name` |
| IPs per ASN | Unique count `ip` | `as_name` |
| Events by country | Sum `event_count` | `country_code` |
| Events by usage type | Sum `event_count` | `usage_type` |
| Unreported infrastructure | Sum `event_count` | `ip`, filtered `abuse_confidence: 0` |

**The two bar charts answer one question between them.** Volume alone can't distinguish a single machine hammering the honeypot from a dozen addresses splitting the same load. Same X-axis, different metric: one sums events, the other counts distinct IPs. High volume with one IP is a dedicated brute-forcer; high volume across many is rotation to avoid per-IP blocking.

**Unreported infrastructure is the panel worth checking.** Nearly every enriched IP comes back at maximum abuse confidence, which only confirms the honeypot is being swept by known scanners. A zero means nobody has reported that address yet - either new infrastructure or a narrow target set.

### Honeypot activity - what happened

| Panel | Type | Bucket |
|---|---|---|
| Total events | Metric | - |
| Events over time | Line | Date histogram, `timestamp` |
| Alerts by rule | Horizontal bar | `rule.description` |
| Top source IPs | Data table | `data.src_ip` |
| Commands executed | Data table | `data.input` |
| High severity | Data table | `rule.description` and `data.src_ip`, filtered `rule.level >= 12` |

**Alerts by rule** shows which detections fire against real traffic. A rule that has never matched is either wrong or waiting - both worth knowing.

**High severity** is post-access behaviour only: file transfers, immutability tampering, key manipulation, log cleanup. Everything in it is someone who got in and did something.

---

## Setup

### 1. Restricted OpenSearch user

The scripts don't run as `admin`, which can read, write, delete and reconfigure the entire cluster. Role `index_user`, no cluster permissions:

| Index pattern | Action groups |
|---|---|
| `wazuh-alerts-*` | `read` |
| `honeypot-auto`, `honeypot-seen` | `read`, `write` |

### 2. Indices

Created with explicit mappings rather than letting OpenSearch infer them on first write. 

```bash
curl -k -u 'admin:PASSWORD' -X PUT "https://localhost:9200/honeypot-auto" \
  -H 'Content-Type: application/json' \
  -d '{"mappings":{"properties":{
    "ip":{"type":"ip"},
    "abuse_confidence":{"type":"integer"},
    "usage_type":{"type":"keyword"},
    "isp":{"type":"keyword"},
    "total_reports":{"type":"integer"},
    "asn":{"type":"keyword"},
    "as_name":{"type":"keyword"},
    "country_code":{"type":"keyword"},
    "event_count":{"type":"integer"},
    "collected_at":{"type":"date"}
  }}}'
```

```bash
curl -k -u 'admin:PASSWORD' -X PUT "https://localhost:9200/honeypot-seen" \
  -H 'Content-Type: application/json' \
  -d '{"mappings":{"properties":{
    "command":{"type":"keyword"},
    "first_seen":{"type":"date"},
    "times_run":{"type":"integer"}
  }}}'
```

### 3. Credentials

```bash
export INDEXER_USER='index_user'
export INDEXER_PASSWORD='...'
export ABUSEIPDB_KEY='...'
export IPINFO_TOKEN='...'
```

Nothing is hardcoded. The values live in /home/haw/.honeypot-env, readable only by the owner (chmod 600), and the shell loads them into the environment before starting the script.

### 4. Cron

```
0 11 * * * . /home/haw/.honeypot-env && /usr/bin/python3 /home/haw/enrich.py
10 11 * * * . /home/haw/.honeypot-env && /usr/bin/python3 /home/haw/newbehaviour.py
```

Cron starts with almost nothing set - no API keys, no PATH worth relying on. That's why each line loads the env file first and calls python by its full path.

The schedule is late morning because the VM is started by hand.

---

## Error handling

Both scripts run unattended, so a failure has to be survivable and recorded.

| Failure | Handling |
|---|---|
| Network drop, timeout | `try`/`except` with a 10s timeout, skip that IP, continue |
| API quota exceeded | Checked separately - a rejection is a successful HTTP response that `try` won't catch |
| Missing field in a response | `.get()` with a fallback: `unknown` for text, `-1` for integers |

---

## Files

| File | Contents |
|---|---|
| `enrich.py` | IP enrichment |
| `newbehaviour.py` | First-seen command detection |
| `.honeypot-env.example` | Variable names, placeholder values |
| `activity-dashboard.png` | Alerts, volume, commands run |
| `enrichment-dashboard.png` | ASN, country, usage type, abuse score |