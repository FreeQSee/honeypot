# Honeypot Traffic Analysis

Structured triage of SSH honeypot data, reducing ~10,000 events to the handful worth human attention.

**Collection window:** 22 Aug 2026 17:00 - 23 Aug 2026 22:00 GMT+3
**Sensor:** Cowrie SSH honeypot on a public VPS, logs shipped to Wazuh over WireGuard

---

## Method

Four layers, each narrowing the field so the next is affordable:

| Layer | Question | Unit |
|---|---|---|
| 1 | How much of what? | Events |
| 2 | Who is doing it? | Source IPs |
| 3 | What do they do once in? | Sessions |
| 4 | What's in the interesting ones? | Commands |

10,028 events -> 2,012 sessions -> 49 with commands -> 1 real intrusion.

---

## Layer 1 - Volume

| eventid | Count | Share |
|---|---|---|
| cowrie.session.connect | 2,025 | 20.2% |
| cowrie.session.closed | 2,024 | 20.2% |
| cowrie.client.version | 1,912 | 19.1% |
| cowrie.client.kex | 1,903 | 19.0% |
| cowrie.login.failed | 1,836 | 18.3% |
| cowrie.login.success | 78 | 0.8% |
| cowrie.command.input | 49 | 0.5% |
| cowrie.direct-tcpip.request | 23 | 0.2% |
| cowrie.session.file_upload | 7 | 0.1% |
| *(remaining types)* | 171 | 1.7% |

**97% is connection mechanics** - knocking, failing, disconnecting.

**4% login success rate.** Cowrie's `userdb.txt` was restricted to six common credentials before collection started, so failures are real refusals rather than an artifact of a permissive default.

---

## Layer 2 - Sources

**100 distinct IPs. 10,002 events across 2,012 sessions.**

The 26-event gap against Layer 1 is event types that carry no source IP field.

| | Share of events |
|---|---|
| Top 1 | 50.5% |
| Top 5 | 78.2% |
| Top 10 | 92.4% |
| Top 15 | 95.3% |
| Top 20 | 96.4% |

A single source, `45.153.34.149`, accounts for half of all traffic. Ten sources produce over 90%.

One address in the set, `81.196.141.92` (18 events, rank 19), is my own - testing the honeypot during setup. Left in rather than removed.

### Infrastructure

The top 15 sources were enriched. All returned **100% abuse confidence** on AbuseIPDB, and none showed VPN, Tor, proxy, or relay indicators.

Sources concentrate by ASN more than by address:

| ASN | Organisation | Type | IPs | Share |
|---|---|---|---|---|
| AS197170 | TechTies Inc. | hosting | 1 | 50.5% |
| AS48090 | TECHOFF SRV LIMITED | hosting | 5 | 24.2% |
| AS47890 | UNMANAGED LTD | hosting | 4 | 15.7% |
| AS680 | DFN (German research network) | education | 1 | 1.8% |
| AS154383 | ZORNTECH WEB SOLUTIONS | hosting | 1 | 1.3% |
| AS7552 | Viettel Group | isp | 2 | 1.2% |
| AS20115 | Charter Communications | isp | 1 | 0.5% |

Three hosting providers account for **90% of traffic across ten addresses**. Addresses rotate more easily than providers, so the ASN is the more durable identifier.

Hosting infrastructure is **91.8% of traffic** - rented capacity, bought to run scans. The remaining four sources sit on networks ipinfo classifies as ISP or education: two Viettel addresses in Vietnam, one Charter address in the US, and one on the German research network. Their traffic pattern is the same as the rest.

Sources are recorded by ASN, with country noted but not relied on - ASN reflects who routes the block, while ISP and location fields vary between providers.

---

## Layer 3 - Sessions

**2,012 sessions. 49 ran commands - 2.4%.**

Every one of those 49 ran **exactly one command**. No session progressed to a second.

---

## Layer 4 - Commands

Nine distinct commands across 49 sessions and 14 IPs:

| Count | Command |
|---|---|
| 28 | Honeypot-detection and profiling script *(see [full text](honeypot-detect-script.txt))* |
| 7 | `uname -s -v -n -r -m` |
| 7 | `/bin/./uname -s -v -n -r -m` |
| 2 | `uname -a` |
| 1 | `uptime` |
| 1 | `ls -la /` |
| 1 | `exit` *(mine)* |
| 1 | `echo "test"` |
| 1 | RedTail deployment chain *(see [redtail/](../redtail/))* |

**46 of 49 are reconnaissance.** Fingerprint, then leave.

### Two techniques worth noting

**`/bin/./uname`** - the `/.` is functionally meaningless. It exists to defeat naive string matching on `uname` in monitoring tools. Deliberate evasion.

**The detection script** - 28 sessions ran a single command that probes the shell's *error messages*: running a nonexistent file, running a nonexistent command, and writing then executing a temporary script. It's checking whether the shell is real. Cowrie's emulated filesystem is where that check fails, which explains why nothing followed.

---

## Proxy attempts

23 `direct-tcpip` requests from **three source IPs**:

| Source | Destination | Port |
|---|---|---|
| 176.53.159.196 | 1.1.1.1 | 53 |
| 195.178.110.137 | 8.8.8.8 | 443 |
| 79.124.58.202 | httpbin.org | 80 |

`direct-tcpip` is an SSH port-forwarding request. If the server honours it, the attacker relays traffic through the host - their traffic, the host's IP and network position.

All destinations were connectivity checks rather than targets: two public DNS resolvers and httpbin.org, which echoes requests back. Cowrie logs the request without forwarding, so none succeeded.

All three gained access with common credentials, two on the first attempt - a function of the honeypot's accept-list, not prior knowledge.

Outbound on the VPS is deny-by-default, permitting only DNS, NTP, and the WireGuard tunnel, so forwarding would have failed at the firewall regardless. Verified by establishing a SOCKS proxy through the host and confirming outbound HTTPS was blocked.

---

## File uploads

7 `file_upload` events, all from a single session. All belong to the RedTail cryptomining campaign - **[full analysis](../redtail/)**.

---

## Conclusions

**The threat landscape is commodity.** Every enriched source was flagged as known-abusive, and 92% of traffic came from rented hosting on three providers. No targeting, no adaptation, no human in the loop.

**Attackers profile defenders.** 28 of 49 command sessions were checking whether the host was a honeypot before committing a payload - the single most common behaviour observed.

**Access has several markets.** RedTail wanted CPU for mining. The proxy attempts wanted network position and a clean IP. The mass brute-forcers wanted credentials, use unknown.

---

## Files

| File | Contents |
|---|---|
| `events-type.csv` | Layer 1 breakdown, all 16 event types |
| `attacker-ips.csv` | Top 15 sources, enriched - ASN, org, type, country, abuse score |
| `commands.csv` | All 49 command events |
| `honeypot-detect-script.txt` | The full profiling script |
| `screenshots/` | Dashboard views |

### Screenshots

| File | Shows |
|---|---|
| `01-event-types.png` | Layer 1 event breakdown |
| `02-top-attackers.png` | Layer 2 source table |
| `03-command-sessions.png` | The 49 command sessions |
| `04-proxy-attempts.png` | direct-tcpip requests |
| `05-ipinfo-enrichment.png` | Example enrichment lookup |
