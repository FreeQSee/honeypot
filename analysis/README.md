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

10,002 events -> 2,012 sessions -> 49 with commands -> 1 real intrusion.

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

**4% login success rate.** Cowrie's `userdb.txt` was restricted to six common credentials mid-collection; before that it accepted anything.

---

## Layer 2 - Sources

**99 distinct IPs. 9984 events across 2,012 sessions.**

| | Share of events |
|---|---|
| Top 1 | 50.5% |
| Top 5 | 78.2% |
| Top 10 | 92.4% |
| Top 20 | 96.4% |

A single source, `45.153.34.149`, accounts for half of all traffic. Ten sources produce over 90%.

### Infrastructure

Every enriched IP shared three properties:

- **Hosting infrastructure**, never residential or mobile
- **No anonymization** - no VPN, Tor, proxy, or relay detected
- **100% abuse confidence** on AbuseIPDB

No compromised home devices. This is **rented scanning capacity** - servers paid for deliberately, on providers chosen for weak abuse enforcement.

### On attribution by geography

ASN and ISP data disagreed between sources. One IP returned Euro Crypt EOOD (Bulgaria) from ipinfo and AS197170 TechTies Inc. (Netherlands) from VirusTotal. ASN reflects who routes the block; ISP fields often reflect who it's leased to. Sources are recorded by ASN, with country noted but not relied on.

---

## Layer 3 - Sessions

**2,012 sessions. 49 ran commands - 2%.**

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
| 1 | `exit` |
| 1 | `echo "test"` |
| 1 | RedTail deployment chain *(see [redtail/](../redtail/))* |

**46 of 49 are reconnaissance.** Fingerprint, then leave.

### Two techniques worth noting

**`/bin/./uname`** - the `/.` is functionally meaningless. It exists to defeat naive string matching on `uname` in monitoring tools. Deliberate evasion.

**The detection script** - 28 sessions ran a single command that probes the shell's *error messages*: running a nonexistent file, running a nonexistent command, and writing then executing a temporary script. It's checking whether the shell is real. Cowrie's emulated filesystem is where that check fails, which explains why nothing followed.

---

## Proxy attempts

23 `direct-tcpip` requests from **three source IPs**, all to connectivity-test destinations:

| Destination | Port |
|---|---|
| 1.1.1.1 | 53 |
| 8.8.8.8 | 53 |
| httpbin.org | 80, 443 |

`direct-tcpip` is an SSH port-forwarding request. If the server honours it, the attacker relays traffic through the host - their traffic, the host's IP and network position.

All destinations were connectivity checks rather than targets: two public DNS resolvers and httpbin.org, which echoes requests back. Cowrie logs the request without forwarding, so none succeeded.

All three gained access with common credentials, two on the first attempt - a function of the honeypot's accept-list, not prior knowledge.

Cowrie logs the request without forwarding, so all three received nothing.

**This attack was anticipated.** The VPS runs deny-by-default egress, permitting only DNS, NTP, and the WireGuard management tunnel - verified by establishing a SOCKS proxy through the host and confirming outbound HTTPS was blocked at the firewall.

---

## File uploads

7 `file_upload` events, all from a single session. All belong to the RedTail cryptomining campaign - **[full analysis](../redtail/)**.

---

## Conclusions

**The threat landscape is commodity.** Every source was known-abusive rented hosting running fixed scripts. No targeting, no adaptation, no human in the loop.

**Attackers profile defenders.** 28 of 49 command sessions were checking whether the host was a honeypot before committing a payload - the single most common behaviour observed.

**Access has several markets.** RedTail wanted CPU for mining. The proxy attempts wanted network position and a clean IP. The mass brute-forcers wanted credentials, use unknown.

---

## Files

| File | Contents |
|---|---|
| `event-types.csv` | Layer 1 breakdown |
| `attacker-ips.csv` | Enriched source data - ASN, org, country, abuse score |
| `commands.csv` | All 49 command events |
| `honeypot-detect-script.txt` | The full profiling script |
| `screenshots/` | Dashboard views |
