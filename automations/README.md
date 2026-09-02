# Honeypot Automation

Two daily scripts and two dashboards. Enrichment that would otherwise be manual, and detection of behaviour that hasn't been seen before.

**Runs on:** Wazuh VM. The VPS has deny-by-default egress and can't reach the enrichment APIs.
**Schedule:** cron, daily.

---

## Why these three things

| Need | Built as | Why |
|---|---|---|
| Context on attacking IPs | `enrich.py` | Requires external APIs. A dashboard can't call out |
| Spot new attacker behaviour | `newbehaviour.py` | Requires memory of yesterday. A dashboard only sees now |
| Daily situational view | Dashboards | Live, filterable, no code needed |

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

**Aggregation, not document retrieval.** Asking for the alerts and counting them in Python means pulling tens of thousands of documents to produce a list of a few hundred. The indexer does the grouping and returns only the result.

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

ipinfo only adds the ASN number outright. The rest duplicates AbuseIPDB - but not always. `isp` is who the block is registered or leased to; `as_name` is who routes it. Layered registration is deliberate in bulletproof hosting, and the disagreement between the two fields is what exposes it.

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

**A set, not a list.** Every command from the aggregation is checked against the baseline. Set membership is constant time; a list would be scanned end to end on every check.

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

`times_run` is a snapshot from the day of discovery and never updates. The field answers *when this appeared*, not how often it happens - that's what the dashboards are for.

### No rule filter

Filtering to `rule.id: 100303` returns only the commands that matched **none** of the specific rules. Rules 100306-100313 also match on `data.input`, and Wazuh fires the most specific rule, so the parent only catches the leftovers.

No filter is needed. Nothing else in the index has a `data.input` field, so the aggregation is already scoped.

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

Created under **Security -> Roles**, then mapped to a user from the role's **Mapped users** tab. The role does nothing until it's mapped.

```bash
curl -k -u 'index_user:PASSWORD' "https://localhost:9200/honeypot-seen/_count"   # count
curl -k -u 'index_user:PASSWORD' "https://localhost:9200/_cat/indices"           # 403
```

### 2. Indices

Created with explicit mappings rather than letting OpenSearch infer them on first write. Inferred text fields split into words and can't be aggregated; inferred dates arrive as strings and the dashboard time filter won't work.

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

Copy `.honeypot-env.example`, fill it in, `chmod 600`. Single quotes, no spaces around `=`.

```bash
export INDEXER_USER='index_user'
export INDEXER_PASSWORD='...'
export ABUSEIPDB_KEY='...'
export IPINFO_TOKEN='...'
```

Read by the shell, not by Python. The scripts only ever look at their own environment, so swapping the source later - Docker, systemd, a secrets manager - changes nothing in the code.

Environment variables are visible to anything running as the same user. Better hygiene than hardcoding, not a security boundary.

### 4. Cron

```
0 11 * * * . /home/haw/.honeypot-env && /usr/bin/python3 /home/haw/enrich.py
10 11 * * * . /home/haw/.honeypot-env && /usr/bin/python3 /home/haw/newbehaviour.py
```

Cron gets a near-empty environment and reads no startup files, so each entry sources the env file itself. Absolute paths throughout for the same reason.

Scheduled late morning because the VM is started manually. **Cron doesn't catch up on missed runs** - a day with the machine off has no data. The gap stays visible rather than hidden, since `collected_at` is per-run.

---

## Error handling

Both scripts run unattended, so a failure has to be survivable and recorded.

| Failure | Handling |
|---|---|
| Network drop, timeout | `try`/`except` with a 10s timeout, skip that IP, continue |
| API quota exceeded | Checked separately - a rejection is a successful HTTP response that `try` won't catch |
| Missing field in a response | `.get()` with a fallback: `unknown` for text, `-1` for integers |

Fallbacks match the mapping type. `"unknown"` written into an integer field is rejected, and the write response isn't checked, so it would fail silently.

Both scripts log to file via Python's `logging` - timestamp and level on every line. Under cron, printed output goes nowhere.

---

## Files

| File | Contents |
|---|---|
| `enrich.py` | IP enrichment |
| `newbehaviour.py` | First-seen command detection |
| `.honeypot-env.example` | Variable names, placeholder values |

Logs at `/home/haw/enrich.log` and `/home/haw/newbehaviour.log`. Not rotated.
