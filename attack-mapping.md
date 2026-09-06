# MITRE ATT&CK Mapping

Observed behaviour from the honeypot, mapped to ATT&CK.

**Coverage:** 22 Aug 2026 - 3 Sep 2026

**Sources:** [analysis](analysis/) - first 28 hours, all traffic. [redtail](redtail/) - the RedTail campaign across the full window.

---

## Reconnaissance

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Active Scanning | T1595 | All | 99 distinct IPs, 2,012 sessions, 1,836 failed logins |
| Gather Victim Host Information | T1592 | Recon cluster | `uname -s -v -n -r -m`, `uname -a`, `uptime`, `ls -la /` - 18 sessions |

---

## Resource Development

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Acquire Infrastructure: Virtual Private Server | T1583.003 | All | Every enriched source is hosting, none residential, all 100% abuse confidence |
| Obtain Capabilities: Malware | T1588.001 | RedTail | XMRig-derived miner, five architectures |

---

## Initial Access

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Valid Accounts | T1078 | RedTail, dj@vanta | `root` login following credential guessing |

---

## Execution

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Command and Scripting Interpreter: Unix Shell | T1059.004 | RedTail | `sh clean.sh`, `sh setup.sh`, chained in one session command |

---

## Persistence

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Account Manipulation: SSH Authorized Keys | T1098.004 | RedTail | RSA key `rsa-key-20230629` written to `~/.ssh/authorized_keys` |
| Account Manipulation: SSH Authorized Keys | T1098.004 | dj@vanta | ed25519 and RSA keys written to `/root/.ssh/authorized_keys` |

---

## Defense Evasion

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Obfuscated Files or Information: Software Packing | T1027.002 | RedTail | UPX 5.2.0 on all five miner binaries |
| Obfuscated Files or Information | T1027.010 | dj@vanta | Key written via `echo … \| base64 -d` rather than plaintext |
| Indicator Removal: File Deletion | T1070.004 | RedTail | `rm -rf clean.sh`, `rm -rf setup.sh`, `rm -rf redtail.*` after execution |
| Hide Artifacts: Hidden Files and Directories | T1564.001 | RedTail | Payload renamed to 4-35 random characters prefixed with `.` |
| File and Directory Permissions Modification: Linux File Attributes | T1222 | RedTail | `chattr -ia` to strip immutability, `chattr +ai` to set it |
| Masquerading | T1036 | Recon cluster | `/bin/./uname` - the `/.` defeats naive string matching on `uname` |
| Virtualization/Sandbox Evasion | T1497.001 | Recon cluster | 28 sessions ran a script probing shell error messages to detect a honeypot |
| Impair Defenses | T1562 | RedTail | `clean.sh` filters download and shell keywords out of every cron path |

---

## Credential Access

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Brute Force: Credential Stuffing | T1110.004 | Unattributed | `cowrie.client.fingerprint` - public keys offered before authentication, sweeping for hosts that already accept them |

---

## Discovery

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| System Information Discovery | T1082 | RedTail | `uname -mp` for architecture selection, `uname -a` after the chain, `findmnt -rn -O noexec -o TARGET` to enumerate noexec mounts |
| File and Directory Discovery | T1083 | RedTail | `find / -type d -user $(whoami) -perm -u=rwx` for a writable, executable directory |

---

## Command and Control

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Proxy | T1090 | Proxy cluster | 23 `direct-tcpip` requests from 3 IPs to 1.1.1.1:53, 8.8.8.8:53, httpbin.org:80/443 |

---

## Impact

| Technique | ID | Actor | Evidence |
|---|---|---|---|
| Resource Hijacking: Compute Hijacking | T1496.001 | RedTail | XMRig Monero miner, stratum protocol, five architectures |
| Service Stop | T1489 | RedTail | `systemctl stop`/`disable` on `c3pool_miner` and `bot.service` |
| Data Destruction | T1485 | RedTail | `/tmp`, `/var/tmp`, `/dev/shm` emptied; `authorized_keys` overwritten with `>` |

---

## Notes on method

**One row per observed behaviour, not per capability.** The miner supports configuration by environment variable and command line, but only the `ssh` argument was seen, so nothing is mapped for the rest.

**Sub-techniques where the evidence supports them, parent techniques where it doesn't.** Where the data shows the specific method, the sub-technique is used. Where it only shows the general behaviour, the parent is.

**Two actors, one table.** RedTail and the `dj@vanta` cluster both wrote SSH keys for persistence, using different key types and different paths. They are listed as separate rows against the same technique rather than merged.
