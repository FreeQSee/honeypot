# RedTail Cryptominer

Twelve days of repeated intrusion by one operator - how they got in, what they ran, and static analysis of what they left.

**Collection window:** 22 Aug 2026 17:00 - 3 Sep 2026 20:27 GMT+3
**Sensor:** Cowrie SSH honeypot on a public VPS, alerts in Wazuh - see [analysis](../analysis/), which covers the first 28 hours only
**Sources:** `130.12.180.51`, `77.90.185.20`
**Analysis environment:** Network-isolated VM, samples copied, originals preserved. Nothing executed.

Detection is by custom Wazuh rules `100303`, `100310`, `100311`. The rules and dashboards live in [automations](../automations/); the raw alert exports are not reproduced here.

---

## Method

Session data first, files second. The logs say who, how, and how often; the binaries say what.

| Layer | Question | Unit |
|---|---|---|
| 1 | Who keeps coming back? | Sessions |
| 2 | How did they get in? | Login attempts |
| 3 | What do they run? | Command chain |
| 4 | What did they leave? | Files |
| 5 | What is the payload? | Strings |

13 sessions -> 2 IPs -> 7 files uploaded every time -> 1 miner, five architectures.

**No disassembly was needed for any of this.** Ghidra is queued, but everything below came from Cowrie logs and four command-line tools.

---

## Layer 1 - Who

| IP | ASN | Org | Country | Abuse | Type |
|---|---|---|---|---|---|
| `130.12.180.51` | [AS202412](https://ipinfo.io/AS202412) | Omegatech LTD | Germany | 100% | Hosting |
| `77.90.185.20` | [AS213790](https://ipinfo.io/AS213790) | Limited Network LTD | Lithuania | 100% | Hosting |

Different ASNs, different countries, both rented hosting at maximum abuse confidence. Neither is residential and neither is anonymised - consistent with every other source in the [first-window analysis](../analysis/).

| IP | Sessions | Files uploaded per session |
|---|---|---|
| `130.12.180.51` | 12 | 7 |
| `77.90.185.20` | 1 | 7 |

**One source dominates.** `130.12.180.51` returned twelve times over twelve days. `77.90.185.20` appeared once, on 29 Aug, and never again.

### The two IPs deliver the same kit

`77.90.185.20` uploaded **all seven of the same files** as `130.12.180.51` - identical SHA-256s, not merely the same malware family.

That diverges from published RedTail observation. SANS' 2024 analysis found payload hashes were unique per batch submission and never reused between IPs. Here one build is served from two ASNs in two countries across a week.

### Timeline

| Date | Session | Source | Rule |
|---|---|---|---|
| 23 Aug 19:21 | `2164f7c342d1` | `130.12.180.51` | 100303 |
| 23 Aug 23:15 | `4f93cc74f36d` | `130.12.180.51` | 100303 |
| 24 Aug 19:23 | `4c3ad9299be1` | `130.12.180.51` | 100303 |
| 28 Aug 06:33 | `bd5183b86afd` | `130.12.180.51` | 100311 |
| 29 Aug 15:21 | `4274139047bb` | `77.90.185.20` | 100311 |
| 29 Aug 17:13 | `fe80d6d8ba2d` | `130.12.180.51` | 100311 |
| 31 Aug 18:39 | `9be203343aad` | `130.12.180.51` | 100311 |
| 31 Aug 20:00 | `cc9fd4c7b78f` | `130.12.180.51` | 100311 |
| 1 Sep 13:45 | `3913e33d1831` | `130.12.180.51` | 100311 |
| 2 Sep 15:51 | `b39bc4d26a4c` | `130.12.180.51` | 100311 |
| 2 Sep 18:54 | `c3f1198a50d3` | `130.12.180.51` | 100311 |
| 3 Sep 14:42 | `5ebc36734b58` | `130.12.180.51` | 100311 |
| 3 Sep 20:27 | `57aeb1316f54` | `130.12.180.51` | 100311 |

**Roughly one session a day, no pattern in the hour.** Automated, unattended, and indifferent to whether the previous attempt succeeded.

**Every session re-uploads the full seven-file set before running the chain.** No session checks whether the payload is already present, and no session skips a file. The routine is fixed and stateless - it behaves the same on a host it visited yesterday as on one it has never seen.

**The rule change on 28 Aug is mine, not theirs.** Earlier sessions match generic rule `100303` (*attacker executed command*); later ones match custom rule `100311` (*SSH backdoor with immutable protection*), written from the first-window findings. Attacker behaviour is unchanged across that boundary - the detection improved.

---

## Layer 2 - Access

Both IPs brute-forced. The difference is how quickly they hit a pair the honeypot accepts.

| IP | Credentials that worked | Failed attempts | Succeeded on |
|---|---|---|---|
| `130.12.180.51` | `root` / `admin` | 0 | 1st attempt |
| `77.90.185.20` | `root` / `password123` | 151 | 152nd attempt |

**The gap is wordlist ordering, not capability.** `root`/`admin` sits at the top of most dictionaries and is in Cowrie's accept-list here, so `130.12.180.51` landed immediately. `77.90.185.20` worked through 151 pairs before reaching one the honeypot would take. Neither had prior knowledge of the host.

**That makes the attempt count a property of my configuration, not of the attacker.** Against a real host with different credentials, both would have behaved the same way and probably failed. The figure is recorded because it is what happened, not because it distinguishes the two sources.

Both succeeded as `root`. Whether `77.90.185.20` also tried other usernames was not checked.

---

## Layer 3 - The chain

One command, run in full, every session:

```bash
chmod +x clean.sh; sh clean.sh; rm -rf clean.sh
chmod +x setup.sh; sh setup.sh; rm -rf setup.sh
mkdir -p ~/.ssh
chattr -ia ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2E...UMRr rsa-key-20230629" > ~/.ssh/authorized_keys
chattr +ai ~/.ssh/authorized_keys
uname -a
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

Four stages: **clear competitors, install miner, backdoor, confirm.**

**Persistence is not in the uploaded files.** It is typed into the session. That is why neither script contains a cron entry or a systemd unit - the backdoor is an SSH key, written directly.

**`>` overwrites, it does not append.** Every existing key on the host is destroyed. The operator is not sharing access.

**`chattr -ia` then `chattr +ai`** - strip whatever immutability a previous actor set, write, then set immutable and append-only so the next one can't. The same technique `clean.sh` uses against rival miners, turned on the backdoor itself.

**The last line is `auth_ok\n` in hex escapes.** A success beacon obfuscated against string matching on the operator's own output. Costs nothing, defeats naive grep.

### The key is 2.5 years old

The RSA key is **byte-identical** to the one recorded in SANS ISC's February 2024 honeypot analysis of RedTail. Same modulus, same comment: `rsa-key-20230629`.

That comment is PuTTYgen's default naming - the keypair was generated **29 June 2023**.

**The payload gets rebuilt. The key does not.** Hash IOCs for the binaries have a shelf life measured in months; this key has held across two and a half years and multiple independent honeypots. It is the most durable indicator in the campaign.

---

## Layer 4 - The files

Seven artifacts, the same set from both IPs, in every session:

| SHA-256 | Role |
|---|---|
| `1e70b634…` | `setup.sh` - installer |
| `3f3a11ba…` | `clean.sh` - competitor removal |
| `f0aa83bb…` | miner, x86-64 |
| `8e1a67a5…` | miner, i386 |
| `d1cac82f…` | miner, aarch64 |
| `d70f917e…` | miner, ARM |
| `3f3bf218…` | miner, RISC-V 64 |

Two scripts, five miner binaries, one per architecture.

### Packing

`file` reported **no section header** on every miner binary. The ELF section header table maps the file's parts; compilers always emit it, and UPX discards it because after compression there are no separate sections left to describe. First signal, one command.

`strings` confirmed the packer - `UPX!` on the first line, then 4-6 character fragments of compressed data. UPX writes its marker three times and makes no attempt to hide.

One pass classified the folder:

```bash
for f in *; do echo -n "$f: "; strings "$f" | grep -c "UPX!"; done
```

**Every file reporting no section header returned a non-zero count. Every other file returned zero.** Two independent signals, same answer.

### What packing costs the defender

| | Packed | Unpacked |
|---|---|---|
| Strings, min length 10 | 75 | 6,593 |

A third of the size, and effectively nothing readable. Signatures don't match the original binary and string triage returns noise.

### Unpacking

| SHA-256 | Format | Packed | Unpacked | Ratio | Result |
|---|---|---|---|---|---|
| `f0aa83bb…` | linux/amd64 | 1,989,056 | 5,199,952 | 38.25% | ok |
| `8e1a67a5…` | linux/i386 | 1,838,060 | 5,238,428 | 35.09% | ok |
| `d1cac82f…` | linux/arm64 | 1,696,412 | 4,199,936 | 40.39% | ok |
| `d70f917e…` | linux/arm | 1,448,252 | 3,928,888 | 36.86% | ok |
| `3f3bf218…` | linux/riscv64 | 1,759,768 | 3,570,216 | 49.29% | ok *(see below)* |

### The build stamp

UPX writes its own version into the decompression stub. **All five report UPX 5.2.0**, released **08 June 2026**.

One packer version across five architectures means one build run on one toolchain. And the same hashes appear from 23 Aug to 1 Sep, from two ASNs - **no rebuild during the observation window.** The build is recent; the operator is not iterating on it weekly.

---

## The RISC-V build

`upx -d` failed at first:

```
CantUnpackException: unknown format 45
```

**This looked like anti-analysis and wasn't.** Format 45 is `linux/riscv64`, added upstream in UPX 5.1.0 (07 Jan 2026). The installed unpacker was UPX 4.2.2 from the Ubuntu repo, dated January 2024 - two years older than the format. UPX 5.2.1 unpacked it cleanly and named the format itself, rather than leaving it to inference.

**No published RedTail analysis documents a RISC-V build.** Reporting from 2024 through mid-2026 lists four architectures: x86_64, i686, arm7/armv7, arm8/aarch64. `setup.sh` here has five branches, and the matching binary was uploaded in every session.

The unpacked RISC-V binary is the smallest of the set with the worst compression ratio - consistent with its instruction encoding and fewer architecture-specific OpenSSL assembly routines. The payload itself is unremarkable. **The finding is the targeting, not the code.**

---

## Layer 5 - Payload

All five unpacked binaries are **XMRig-derived Monero miners**, statically linked and stripped.

| Evidence | String |
|---|---|
| Mining protocol | `stratum+tcp://`, `stratum+ssl://` |
| Stock XMRig | `donate.ssl.xmrig.com`, `donate.v2.xmrig.com`, `xmrig.com/wizard` |
| Config keys | `donate-level`, `donate-over-proxy` |
| Environment variables | `XMRIG_CWD`, `XMRIG_EXE`, `XMRIG_VERSION`, `XMRIG_KIND` |
| Async I/O library | `uv_fs_open`, `uv__check_before_write` |
| Static linking | OpenSSL CRYPTOGAMS assembly banners |

**Most of 6,593 strings are library noise.** Static linking pulls in OpenSSL, libuv and libc wholesale, including their test data - the binary contains Lorem ipsum. Separating the author's strings from the libraries' is the work.

### Nothing to pivot on

The binaries contain **no pool address, no wallet, no C2, no attacker domain**. Every domain recovered belongs to stock XMRig or a linked library. The only IP is `127.0.0.1`, XMRig's default API bind.

`stratum+ssl://%s` explains it - `%s` is a format placeholder, so the pool URL is assembled at runtime from a value supplied externally. The `XMRIG_*` environment variable names support that.

**For defenders:** IOCs taken from the miner binary will not lead to the operator's infrastructure. Pool and wallet have to come from process arguments or network telemetry.

### Cross-architecture

IOC-shaped strings compared across all five builds. The sets match. One payload, five compilation targets, no per-architecture configuration.

---

## The scripts

### `setup.sh` - installer, 93 lines

**Architecture detection.** `uname -mp` maps to `x86_64`, `i686`, `arm8`, `arm7`, `riscv`. Unrecognised systems set `NOARCH=true` and every build is attempted in sequence.

**noexec is detected and bypassed:**

```bash
findmnt -rn -O noexec -o TARGET
```

The result becomes `-not -path` exclusions, then the script searches the filesystem for directories owned by the current user with `rwx`, skipping those mounts. Mounting `/tmp` noexec doesn't block this - it redirects it.

**Writability is proven, not assumed.** Candidates get a 2 MB test file via `dd`, falling back to `truncate`. That checks quota and free space against the payload's real size. Permissions passing `find` isn't the same as a write succeeding.

**Anti-forensics.** The payload is copied with `cat >` rather than moved, breaking the link to the uploaded file. The destination name is 4-35 random characters prefixed with `.`. Architecture-named originals are deleted afterwards.

The random-name generator falls back through `openssl rand`, `/dev/urandom` and `$RANDOM`. If all three fail it returns the literal string `redtail` - the author's own name for the malware, left in the code.

**One thing unexplained.** The payload is invoked as `./$FILENAME ssh`. Published samples run it with no argument.

### `clean.sh` - competitor removal, 43 lines

Removes rival miners. Installs nothing.

```bash
chattr -ia "$1"
grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' "$1" >/tmp/clean_file
mv -f /tmp/clean_file "$1"
```

Only lines containing download or shell-spawn keywords are removed. Legitimate cron entries survive, so nothing visibly breaks for the administrator. The keyword list is a fingerprint of how competing miners fetch payloads.

**The `chattr -ia` is the point.** Rival miners set immutable and append-only flags on their persistence entries specifically so root can't remove them. This strips the protection first - the same move the chain later uses to seize `authorized_keys`.

**Coverage:** user crontabs, `/etc/crontab`, `/etc/crontabs`, `/etc/cron.{hourly,daily,weekly,monthly,d}`, `/etc/anacrontab`, the live crontab, `~/.bashrc`, `~/.bash_profile`, `~/.profile`.

**Named competitors:** `c3pool_miner` and `bot.service`, stopped and disabled.

**Temp wipe.** `/tmp`, `/var/tmp` and `/dev/shm` emptied entirely, with a guard skipping the directory the script runs from. Surgical on cron, indiscriminate here.

---

## Not RedTail

Artifacts recovered in the same period that belong to other activity. Recorded so they aren't mistaken for part of this campaign.

### The `dj@vanta` cluster

Two IPs, one identity, same key comment, different delivery:

| IP | Sessions | Technique |
|---|---|---|
| `195.226.92.124` | 2 | Plaintext `echo`, plus the key uploaded as a file (`1d61bbb0…`) |
| `87.58.204.98` | 3 | Base64-encoded `echo … \| base64 -d`, plus one file download |

Both append `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKmYl4Yh… dj@vanta` to `/root/.ssh/authorized_keys`. `87.58.204.98` also deploys a second, different RSA key under the same comment, and at one point runs `rm -f /root/.ssh/authorized_keys` before rewriting - the same exclusivity behaviour RedTail shows, from a different actor.

**Distinguishing features:** ed25519 not RSA, `/root/.ssh/` not `~/.ssh/`, `chmod 600` not `chattr +ai`, verification with `grep -c` after writing, and no payload at all.

### `94f2e4d8…`

An ELF x86-64, dynamically linked, stripped, **not packed** - intact section headers and a BuildID. Uploaded by three unrelated IPs (`194.225.131.66`, `103.107.159.75`, `89.126.222.163`), none of which touched RedTail. Unanalysed.

---

## Indicators

**Durable - survives rebuilds**

| Indicator |
|---|
| SSH key `…UMRr rsa-key-20230629` in `authorized_keys` - unchanged since 2023, seen in 2024 reporting |
| `chattr -ia` on `authorized_keys`, write, then `chattr +ai` |
| `authorized_keys` overwritten rather than appended |
| `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"` - hex-escaped `auth_ok` beacon |
| Sequence: `clean.sh` then `setup.sh`, each `rm -rf`'d immediately |

**Behavioural**

| Indicator |
|---|
| Hidden executable, random 4-35 char name, in a user-writable directory outside noexec mounts |
| Process invoked with the single argument `ssh` |
| `c3pool_miner` / `bot.service` stopped and disabled |
| `chattr -ia` on cron paths followed by selective line removal |
| `/tmp`, `/var/tmp`, `/dev/shm` emptied |
| `.testfile` / `.testfile2` created and deleted, 2 MB, across writable directories |

**Network** - stratum egress, TCP or TLS, non-standard port. Pool address not recoverable from the binary.

**Fragile** - the seven SHA-256 values. Held steady for twelve days here, but 2024 reporting shows them rotating per batch.

**Detect on the chain, not the payload.** The key, the `chattr` pattern and the hex beacon have outlived multiple payload rebuilds. The hashes will not.

---

## Conclusions

**One kit, two rented hosts.** Both IPs delivered byte-identical files and both brute-forced their way in. Different ASNs, different countries, same payload - infrastructure rented separately to run the same operation.

**The infrastructure is older than the payload.** Binaries packed with a UPX release from June 2026; the SSH backdoor key generated in June 2023 and still in use, byte-identical to a 2024 SANS capture. Tooling gets rebuilt, identity doesn't.

**Access is exclusive, not shared.** `authorized_keys` is overwritten and locked immutable, competing miners are stripped out of cron, and `/tmp`, `/var/tmp` and `/dev/shm` are emptied. Most of the effort goes into denying the host to anyone else.

**The binary is a dead end for attribution.** No pool, no wallet, no C2. Configuration is external by design, so static analysis alone cannot reach the operator.

**A RISC-V build is being deployed that published analysis has not recorded**, in every session, alongside the four documented architectures.

**The one apparent anti-analysis measure was my own tooling.** The RISC-V unpack failure looked deliberate and was a two-year-old copy of UPX. Nothing in the sample set resists analysis beyond the packing itself.

---

## Still open

| Item | Needs |
|---|---|
| Usernames tried by `77.90.185.20` | Only the successful `root` login was checked - the full attempt list wasn't reviewed |
| The `ssh` argument | Ghidra, argument handling |
| Where configuration comes from | Dynamic analysis |
| Pool, wallet, C2 | Instrumented sandbox |
| `94f2e4d8…` | Static triage - unpacked and dynamically linked, so cheaper than the rest |
| MITRE ATT&CK mapping | - |

**The honeypot is still collecting.** The same hashes have held for twelve days; 2024 reporting shows this family rotating hashes per batch, so a rebuild is expected. Sample hashes, packer versions and the SSH key will be tracked across future sessions to establish the rebuild cadence and catch further architecture additions.

---

## Files

*(pending)*
