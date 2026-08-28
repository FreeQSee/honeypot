# Detection Rules

Custom Wazuh rules written from behaviour observed on the honeypot.

Rules 100300-100305 classify Cowrie events by type. Rules 100306-100316 identify specific attacker techniques seen in the first 28 hours of collection - see [analysis/](../analysis/).

All rules live in `<group name="local,cowrie,honeypot,">`.

---

## Base rules

| ID | Fires on | Level | MITRE |
|---|---|---|---|
| 100300 | Any Cowrie event *(parent)* | 3 | - |
| 100301 | Failed login | 5 | - |
| 100302 | Successful login | 10 | - |
| 100303 | Command executed | 8 | - |
| 100304 | File downloaded | 12 | T1105 |
| 100305 | Brute force, 20+ failures in 60s from same IP | 10 | T1110 |

100300 matches on `^cowrie\.` - the prefix every Cowrie eventid carries. Everything else is a child of it, so the honeypot check happens once.

Rules 100306-100313 are children of 100303, since they match command content. Rules 100314-100316 are children of 100300, since they match event types.

---

## A note on levels

Severity here reflects what a **honeypot** is for, not what a production host would need.

On a production system the priorities invert: a successful brute force should trigger isolation immediately, and everything after it becomes informational because the response has already fired.

Same events, different levels.

---

## Rules

### 100306 - System check

```xml
<rule id="100306" level="11">
  <if_sid>100303</if_sid>
  <field name="input">===SHELL_BEHAVIOR===</field>
  <description>Cowrie: system check</description>
  <mitre><id>T1497.001</id></mitre>
</rule>
```

28 of 49 command sessions ran a script that probes the shell's error messages - running a nonexistent file, running a nonexistent command, then writing and executing a temporary script. It is checking whether the shell is real before committing a payload.

**Level 11.** Because this is a honeypot, my goal is to understand attackers and what they are after. This matters more than a brute force succeeding, when `userdb.txt` contains six of the most common passwords.

In a real environment I would treat this as informational - after a successful brute force the affected system should be isolated immediately.

**Match:** `===SHELL_BEHAVIOR===` is a marker the script prints. Highly specific to this tooling. If the operators rename it the rule stops firing, which is itself information.

---

### 100307 - Command obfuscation

```xml
<rule id="100307" level="11">
  <if_sid>100303</if_sid>
  <field name="input">/\./</field>
  <description>Cowrie: command obfuscation</description>
  <mitre><id>T1027.010</id></mitre>
</rule>
```

`/bin/./uname` runs the same binary as `/bin/uname` - the `.` resolves to the current directory and changes nothing. It exists to defeat string matching in monitoring tools looking for `/bin/uname`.

**Match:** `/\./` catches the technique anywhere, not just on `uname`. Because this is a honeypot no one uses, there are no legitimate commands to generate false positives. In a normal environment this pattern would fire constantly.

The `\.` is an escaped dot - unescaped, `.` is a regex wildcard.

---

### 100308 - System discovery

```xml
<rule id="100308" level="5">
  <if_sid>100303</if_sid>
  <field name="input">uname|uptime|whoami|hostname</field>
  <description>Cowrie: system discovery</description>
  <mitre><id>T1082</id></mitre>
</rule>
```

Basic reconnaissance grouped into one rule. Individually these tell you nothing, and they were the most common commands after the detection script.

**Level 5.** Informational, below the generic command rule.

`ls` and `id` were considered and dropped - both match as substrings inside unrelated words (`tools`, `false`, `uuid`, `android`), and Wazuh's default regex engine does not support word boundaries without switching to PCRE2.

---

### 100309 - Attribute tampering

```xml
<rule id="100309" level="12">
  <if_sid>100303</if_sid>
  <field name="input">chattr</field>
  <description>Cowrie: attribute tampering</description>
  <mitre><id>T1222</id></mitre>
</rule>
```

`chattr` changes file attributes below the permission layer. `+i` makes a file immutable - unmodifiable and undeletable, even by root. `-i` removes that protection.

Hardening guides recommend `chattr +i` on sensitive files. An attacker running `chattr -i` knows that and is stripping it.

---

### 100310 - SSH persistence

```xml
<rule id="100310" level="12">
  <if_sid>100303</if_sid>
  <field name="input">authorized_keys</field>
  <description>Cowrie: SSH persistence</description>
  <mitre><id>T1098.004</id></mitre>
</rule>
```

Writing to `~/.ssh/authorized_keys` installs a key that grants password-free access. Changing the password afterwards does not remove it.

---

### 100311 - SSH backdoor with immutable protection

```xml
<rule id="100311" level="13">
  <if_sid>100309</if_sid>
  <field name="input">authorized_keys</field>
  <description>Cowrie: SSH backdoor with immutable protection</description>
  <mitre><id>T1098.004</id><id>T1222</id></mitre>
</rule>
```

A child of 100309, so it only evaluates when `chattr` already matched, then additionally requires `authorized_keys`.

The combination is worse than either part: strip the immutable flag, write the key, lock the file again. The key cannot then be removed by normal means - `rm` fails, editing fails, even as root, until someone knows to run `chattr -ia` first.

Observed once, in the [RedTail](../redtail/) intrusion.

**Why three rules instead of one.** `chattr` and `authorized_keys` appear independently in real attacks - RedTail's `clean.sh` used `chattr` on crontabs with no key involved. Separate rules catch each technique on its own; the child catches the combination and wins when both are present, so the alert count stays at one.

---

### 100312 - Obfuscation

```xml
<rule id="100312" level="9">
  <if_sid>100303</if_sid>
  <field name="input">echo -e \\x</field>
  <description>Cowrie: obfuscation</description>
  <mitre><id>T1027.010</id></mitre>
</rule>
```

`echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"` prints `auth_ok` - a success beacon the attacker's automation reads to confirm the command chain executed.

Written in hex so a defender grepping logs for `auth_ok` finds nothing.

---

### 100313 - Evidence destruction

```xml
<rule id="100313" level="12">
  <if_sid>100303</if_sid>
  <field name="input">rm -rf</field>
  <description>Cowrie: evidence destruction</description>
  <mitre><id>T1070.004</id></mitre>
</rule>
```

If an attacker runs `rm -rf` they want to hide something. That is worth checking every time.

Seen in the RedTail chain, deleting `clean.sh` and `setup.sh` immediately after executing them.

---

### 100314 - File upload

```xml
<rule id="100314" level="12">
  <if_sid>100300</if_sid>
  <field name="eventid">^cowrie\.session\.file_upload$</field>
  <description>Cowrie: attacker uploaded file to honeypot</description>
  <mitre><id>T1105</id></mitre>
</rule>
```

Payload delivery. All 7 uploads in the collection window came from the RedTail session - two shell scripts and five architecture-specific binaries.

---

### 100315 - Proxy abuse attempt

```xml
<rule id="100315" level="6">
  <if_sid>100300</if_sid>
  <field name="eventid">^cowrie\.direct-tcpip\.request$</field>
  <description>Cowrie: proxy abuse attempt</description>
  <mitre><id>T1090</id></mitre>
</rule>
```

An SSH port-forwarding request. If honoured, the attacker relays traffic through the host - their traffic, the host's IP and network position.

**Level 6.** Being a honeypot, outbound firewall rules already stop attackers using it as a proxy, so the event is informational.

The parent technique is used rather than a sub-technique: the attempt was blocked, so what they intended to reach is unknown.

---

### 100316 - Credential stuffing

```xml
<rule id="100316" level="6">
  <if_sid>100300</if_sid>
  <field name="eventid">^cowrie\.client\.fingerprint$</field>
  <description>Cowrie: credential stuffing</description>
  <mitre><id>T1110.004</id></mitre>
</rule>
```

The attacker offers an SSH public key and the server replies whether it is listed in `authorized_keys` - before any authentication happens. That answer is free.

Used to find hosts where a key they already control is installed: malware plants a key, the operator later sweeps the internet offering it, and anything that says yes is still theirs. The RedTail campaign has reused the same key since 2023.

Not spraying - they are testing one key they already hold, which is stuffing rather than guessing.

---

## Level map

| Level | Rule | Behaviour |
|---|---|---|
| 13 | 100311 | SSH backdoor with immutable protection |
| 12 | 100309 | chattr |
| 12 | 100310 | authorized_keys |
| 12 | 100313 | rm -rf |
| 12 | 100314 | File upload |
| 11 | 100306 | System check |
| 11 | 100307 | Command obfuscation |
| 9 | 100312 | Obfuscation |
| 6 | 100315 | Proxy abuse attempt |
| 6 | 100316 | Credential stuffing |
| 5 | 100308 | System discovery |

---

## Files

| File | Contents |
|---|---|
| `local_rules.xml` | The Cowrie rule group as deployed on the Wazuh manager |
