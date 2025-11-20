# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T08:25:37Z
**Timeframe:** 2025-10-18T20:25:37Z to 2025-10-19T08:25:37Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-10-18T21:02:07Z.md
- Honeypot_Attack_Summary_Report_2025-10-18T22:02:02Z.md
- Honeypot_Attack_Summary_Report_2025-10-18T23:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T00:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T01:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T02:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T03:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T04:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T05:01:54Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T06:02:16Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T07:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-10-19T08:02:00Z.md

## Executive Summary

This report provides a comprehensive analysis of honeypot network activity over a 12-hour period, from October 18th to October 19th, 2025. During this time, a high volume of automated attacks were observed, primarily targeting SSH, SIP, SMB, and VNC services. The majority of these attacks appear to be opportunistic, leveraging common vulnerabilities and weak credentials to compromise devices and expand botnet networks.

A significant portion of the observed activity was attributed to a small number of hyper-aggressive IP addresses, most notably `185.243.96.105`, which was responsible for a high volume of VNC scans. Other prominent attackers, such as `72.146.232.13`, `198.23.190.58`, and `23.94.26.58`, were observed targeting a wide range of services. OSINT analysis of these IPs revealed their association with known malicious activities, including port scanning, brute-force attacks, and malware distribution.

The most frequently exploited vulnerability was CVE-2005-4050, a dated vulnerability in MultiTech VoIP gateways, indicating that many legacy systems remain unpatched and vulnerable to attack. Other notable CVEs included CVE-2024-4577, a critical PHP-CGI vulnerability, and CVE-2025-30208, a flaw in the Vite development tool. The appearance of a CVE with a future date (2025) is a significant anomaly that warrants further investigation.

Attackers were observed attempting to download and execute a variety of malware, including variants of the Mirai and Mozi botnets, such as "sora.sh," "yukari.sh," and "Mozi.m dlink.mips." These botnets are known to be used for launching large-scale DDoS attacks. A recurring tactic observed was the attempt to add an SSH key with the comment "mdrfckr" to the `authorized_keys` file, providing a clear signature of a specific attacker or botnet.

Overall, the data from the last 12 hours paints a picture of a relentless and automated threat landscape, where attackers are constantly scanning for vulnerable devices to expand their botnets and carry out further malicious activities.

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

| Honeypot | Total Attacks |
|---|---|
| Cowrie | 100087 |
| Suricata | 37415 |
| Honeytrap | 42522 |
| Sentrypeer | 21171 |
| Heralding | 14948 |
| Ciscoasa | 11653 |
| Dionaea | 2244 |
| Tanner | 741 |
| Mailoney | 404 |
| H0neytr4p | 382 |
| ConPot | 311 |
| Adbhoney | 137 |
| Redishoneypot | 138 |
| Miniprint | 86 |
| Honeyaml | 168 |
| Dicompot | 93 |
| ElasticPot | 54 |
| ssh-rsa | 36 |
| Ipphoney | 25 |
| Wordpot | 3 |

### Top Source Countries

*Data not available in the provided logs.*

### Top Attacking IPs

| IP Address | Total Attacks |
|---|---|
| 185.243.96.105 | 14408 |
| 72.146.232.13 | 11400 |
| 198.23.190.58 | 11394 |
| 23.94.26.58 | 10983 |
| 194.50.16.73 | 10565 |
| 38.242.213.182 | 6483 |
| 198.12.68.114 | 7421 |
| 134.199.195.80 | 1992 |
| 104.248.206.169 | 1469 |
| 88.210.63.16 | 1393 |

### Top Targeted Ports/Protocols

| Port/Protocol | Total Attacks |
|---|---|
| 22 | 16839 |
| 5060 | 21293 |
| vnc/5900 | 14408 |
| TCP/445 | 11319 |
| UDP/5060 | 12693 |
| 5903 | 2162 |
| 8333 | 1205 |
| 8000 | 2006 |
| 7070 | 1858 |
| 7000 | 1589 |

### Most Common CVEs

| CVE | Total Sightings |
|---|---|
| CVE-2005-4050 | 13788 |
| CVE-2002-0013, CVE-2002-0012 | 118 |
| CVE-2019-11500 | 45 |
| CVE-2021-3449 | 24 |
| CVE-2025-30208 | 14 |
| CVE-2001-0414 | 12 |
| CVE-2024-4577 | 8 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 24 |
| CVE-2021-35394 | 8 |
| CVE-2010-0569 | 4 |

### Commands Attempted by Attackers

| Command | Total Attempts |
|---|---|
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 473 |
| lockr -ia .ssh | 472 |
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" | 472 |
| free -m | grep Mem | awk ... | 449 |
| ls -lh $(which ls) | 448 |
| which ls | 448 |
| crontab -l | 447 |
| w | 445 |
| uname -m | 444 |
| cat /proc/cpuinfo | grep model | grep name | wc -l | 444 |
| top | 444 |
| uname | 444 |
| uname -a | 444 |
| whoami | 442 |
| lscpu | grep Model | 438 |
| df -h | head -n 2 | awk ... | 438 |
| Enter new UNIX password: | 241 |
| rm -rf /tmp/secure.sh; ... | 42 |
| uname -s -v -n -r -m | 8 |
| echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh | 3 |

### Signatures Triggered

| Signature | Total Triggers |
|---|---|
| ET VOIP MultiTech SIP UDP Overflow | 13788 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 9078 |
| ET DROP Dshield Block Listed Source group 1 | 4201 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 3229 |
| ET SCAN NMAP -sS window 1024 | 1629 |
| ET HUNTING RDP Authentication Bypass Attempt | 1530 |
| ET SCAN Potential SSH Scan | 631 |
| ET INFO Reserved Internal IP Traffic | 425 |
| GPL INFO SOCKS Proxy attempt | 592 |

### Users / Login Attempts

| Username/Password | Total Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 464 |
| root/3245gs5662d34 | 149 |
| root/123@Robert | 77 |
| ftpuser/ftppassword | 64 |
| /passw0rd | 57 |
| /Passw0rd | 56 |
| /1q2w3e4r | 55 |
| /qwertyui | 30 |
| user/7777777 | 6 |
| debian/2222222 | 6 |

### Files Uploaded/Downloaded

| Filename | Total |
|---|---|
| sh | 90 |
| wget.sh; | 42 |
| w.sh; | 18 |
| c.sh; | 18 |
| loader.sh | 5 |
| sora.sh; | 2 |
| rondo.rwx.sh|sh; | 2 |
| Mozi.m dlink.mips | 1 |
| yukari.sh; | 4 |
| gpon8080&ipv=0 | 4 |
| wlwps.htm | 1 |

### HTTP User-Agents

*No user agents were logged in this timeframe.*

### SSH Clients and Servers

*No specific SSH clients or servers were logged in this timeframe.*

### Top Attacker AS Organizations

*No attacker AS organizations were logged in this timeframe.*

## OSINT All Commands Captured

*The majority of commands are standard reconnaissance and persistence techniques. The command "curl2" is anomalous and its purpose is unknown.*

## OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Confidence of Malice | Summary |
|---|---|---|
| 185.243.96.105 | High | Associated with GTT Communications, managed by a Ukrainian organization. Flagged for network scanning, brute-force attacks (RDP and SSH), and phishing. Blocked by Malwarebytes. |
| 72.146.232.13 | Medium | Registered to Microsoft Corporation. Flagged for SSH attacks and forum spam. May be part of a dynamic cloud environment. |
| 198.23.190.58 | High | Managed by HostPapa. Flagged for port scanning and SIP-based attacks. Likely a compromised machine or a server deployed for malicious purposes. |
| 23.94.26.58 | High | Registered to HostPapa. Listed on multiple blacklists for brute-force attacks and port scanning. Observed targeting SIP services. |

## OSINT on CVE's

| CVE | Summary |
|---|---|
| CVE-2005-4050 | A critical buffer overflow vulnerability in Multi-Tech MultiVOIP devices, allowing remote code execution via a specially crafted SIP packet. This is an old vulnerability, but it is still being actively exploited, indicating that many legacy systems remain unpatched. |
| CVE-2025-30208 | An arbitrary file read flaw in the Vite development tool, allowing unauthenticated attackers to access any file on the server's filesystem. The "2025" year in the CVE identifier is highly unusual and may indicate a problem with CVE assignment or reporting. |
| CVE-2024-4577 | A critical remote code execution vulnerability in PHP-CGI on Windows systems, actively exploited in the wild to deploy ransomware, RATs, and botnets. |

## Key Observations and Anomalies

*   **Hyper-Aggressive VNC Scanner:** The IP address `185.243.96.105` was responsible for a massive number of VNC scans, suggesting a targeted campaign to find and compromise exposed VNC servers.
*   **Attacker Signature "mdrfckr":** A specific attacker or botnet was observed consistently attempting to add an SSH key with the comment "mdrfckr" to the `authorized_keys` file. This provides a unique signature that can be used to track this threat actor.
*   **Anomalous CVE Year:** The appearance of "CVE-2025-30208" is a significant anomaly. It is highly unusual for a CVE to be assigned a future year. This could be a data entry error, a reserved CVE ID, or an issue with the CVE numbering process itself.
*   **"curl2" Command:** The use of the "curl2" command is anomalous. It is not a standard Linux command and may be a custom tool or a modified version of `curl` used by the attacker.
*   **Targeting of Legacy Systems:** The widespread exploitation of CVE-2005-4050, a vulnerability from 2005, highlights the continued threat posed by unpatched legacy systems.
*   **Botnet Recruitment:** The presence of malware such as Mirai and Mozi variants ("sora.sh," "yukari.sh," "Mozi.m dlink.mips") indicates that a primary goal of these attacks is to recruit compromised devices into botnets for use in DDoS attacks and other malicious activities.
*   **Targeting of Routers:** The filenames "gpon8080&ipv=0" and "wlwps.htm" suggest that attackers are targeting specific vulnerabilities in routers, likely to gain control of these devices and use them as a foothold in a network.

This concludes the Honeypot Attack Summary Report.
