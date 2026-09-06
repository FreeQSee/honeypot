# SSH Honeypot

A public SSH honeypot feeding a self-hosted SIEM, with custom detection rules, automated enrichment, and malware analysis of what the attackers dropped.

**Status:** running since August 2026. Still collecting.

---

## What this is

A Cowrie SSH honeypot on a public VPS, shipping logs to a Wazuh manager on private hardware. Everything past the raw logs is built here - the decoder, the rules, the enrichment, the dashboards, the analysis.

---

## Architecture

```
   PUBLIC VPS                          PRIVATE NETWORK
   
   Cowrie  ->  cowrie.json  ->  Wazuh agent
                                    |
                                WireGuard
                                    |
                                    v
                              Wazuh manager  ->  custom rules
                                    |          ->  dashboards
                                    |
                              enrich.py  ->  AbuseIPDB + ipinfo
                              newbehaviour.py
```

**The manager is not on the VPS.** The honeypot is a machine designed to be broken into. Putting the SIEM on it would mean the attacker and the evidence share a host. Logs leave over WireGuard as they are written; nothing of value stays on the box.

**Egress is deny-by-default.** Only DNS, NTP and the management tunnel are permitted, enforced at the cloud firewall rather than on the box - a compromised host can't rewrite a rule it can't reach. Cowrie emulates rather than executes, but that is one layer, not the only one.

**Cowrie runs as its own system user**, installed from source, isolated from the OS. Real SSH is on a high non-standard port; Cowrie has 22.

**Wazuh 4.14.7.**

---

## Design decisions

| Decision | Why |
|---|---|
| SIEM off the sensor | The sensor is meant to be compromised. Evidence lives elsewhere. |
| Deny-by-default egress | Protect the VPs from getting abuse complaints and blocking any chance of being used by attackers. |
| Cloud firewall, not on-box | Survives compromise of the host it protects. |
| Own decoder and rules | No official Wazuh ruleset for Cowrie exists. |
| Restricted credential list | `userdb.txt` accepted anything at first, which inflated login success. Narrowed to six common pairs mid-collection to compare those who brute-force from those who get lucky with first credentials pair. |
| Automation on the manager | That is where the data is. Also the only side that can reach the enrichment APIs. |

---

## The repo

| Folder | Contents |
|---|---|
| **[analysis/](analysis/)** | Structured triage of the first 28 hours - 10,002 events reduced to the one intrusion worth analysing |
| **[rules/](rules/)** | 17 custom Wazuh rules written from observed behaviour, with the reasoning for each |
| **[automations/](automations/)** | Daily IP enrichment, first-seen command detection, two dashboards |
| **[redtail/](redtail/)** | Full analysis of the RedTail cryptomining campaign - delivery chain, unpacking, payload |
| **[attack-mapping.md](attack-mapping.md)** | Observed techniques across all campaigns, mapped to MITRE ATT&CK |

---

## What came out of it

**The traffic is commodity.** 99 source IPs in the first 28 hours, every enriched one on rented hosting at maximum abuse confidence. No residential addresses, no anonymisation, no human in the loop.

**Attackers profile defenders first.** 28 of 49 command sessions ran a script probing the shell's error messages to detect a honeypot, then left without dropping anything. The single most common behaviour observed.

**One operator stayed.** The RedTail campaign returned thirteen times across twelve days, re-uploading its full seven-file payload set every session and running an identical scripted chain each time.

**Its SSH backdoor key is from 2023.** Byte-identical to the key in write-ups published years earlier. The miner binaries get rebuilt; the key does not. 

**It ships a RISC-V build.** Five architectures, one of which appears in no published analysis of this family.

---

## A note on what's published here

The honeypot is live, so operational detail is deliberately absent - no addresses, ports, paths, or firewall specifics. What is here is the reasoning, the rules, the code, and the findings.
