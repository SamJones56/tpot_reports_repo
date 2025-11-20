# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T16-25-07Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-30T16:11:30Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-28T14-37-09Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T21-01-51Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T22-03-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-28T23-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T00-01-47Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T01-01-37Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T02-02-07Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T04-01-53Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T05-01-54Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T06-01-50Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T07-01-45Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T08-01-48Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T09-02-42Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T10-02-22Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T11-01-58Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T12-02-14Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T13-02-20Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T16:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T17:20:43Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T18:43:06Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T19:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T20:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T21:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T22:01:52Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T00:01:58Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T01:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T02:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T03:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T04:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T05:01:53Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T06:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T08:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T09:01:49Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T10:02:23Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T11:02:00Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T12:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T13:02:13Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T14:02:12Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T15:02:26Z.md
- Honeypot_Attack_Summary_Report_2025-09-30T16:11:30Z.md

### Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our distributed honeypot network between September 28th and 30th, 2025. Over this period, a significant volume of automated attacks were observed, primarily targeting SSH and SMB services. The attacks originated from a diverse range of IP addresses globally, with a notable concentration from specific addresses, which have been investigated and are detailed in this report. The attackers employed a variety of techniques, including brute-force attacks with common and default credentials, exploitation of known vulnerabilities, and the execution of malicious commands to download malware and establish persistence. The high volume of activity underscores the persistent and automated nature of threats targeting internet-facing systems.

### Detailed Analysis

**Our IPs**

| Honeypot | Private IP | Public IP |
|---|---|---|
| hive-us | 10.128.0.3 | 34.123.129.205 |
| sens-tai | 10.140.0.3 | 104.199.212.115 |
| sens-tel | 10.208.0.3 | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195 |
| sens-ny | 10.108.0.2 | 161.35.180.163 |

**Attacks by Honeypot**

| Honeypot | Attack Count |
|---|---|
| Cowrie | 6964 |
| Honeytrap | 4961 |
| Suricata | 3040 |
| Ciscoasa | 2928 |
| Dionaea | 1344 |
| Sentrypeer | 523 |
| Redishoneypot | 207 |
| Mailoney | 96 |
| Adbhoney | 53 |
| Tanner | 73 |
| H0neytr4p | 56 |
| ElasticPot | 30 |
| ConPot | 20 |
| ssh-rsa | 12 |
| Honeyaml | 15 |
| Dicompot | 3 |
| Ipphoney | 4 |

**Top Source Countries**

| Country | Attack Count |
|---|---|
| United States | 1354 |
| China | 1246 |
| Vietnam | 1182 |
| Russia | 803 |
| Germany | 742 |
| Netherlands | 582 |
| India | 535 |
| Canada | 484 |
| France | 435 |
| Turkey | 442 |

**Top Attacking IPs**

| IP Address | Attack Count |
|---|---|
| 137.184.169.79 | 870 |
| 58.186.122.40 | 792 |
| 60.174.72.198 | 454 |
| 185.216.116.99 | 484 |
| 91.237.163.113 | 435 |
| 117.102.100.58 | 430 |
| 78.30.2.66 | 442 |
| 185.156.73.166 | 379 |
| 185.156.73.167 | 373 |
| 196.251.72.53 | 372 |
| 92.63.197.55 | 361 |
| 92.63.197.59 | 344 |
| 23.94.26.58 | 306 |
| 198.12.68.114 | 204 |
| 190.108.77.129 | 257 |
| 185.243.5.68 | 126 |
| 130.83.245.115 | 63 |
| 3.130.96.91 | 67 |
| 204.76.203.28 | 66 |
| 185.243.5.21 | 51 |

**Top Targeted Ports/Protocols**

| Port | Protocol | Attack Count |
|---|---|---|
| 445 | TCP | 1252 |
| 22 | TCP | 1016 |
| 5060 | TCP/UDP | 814 |
| 6379 | TCP | 189 |
| 8333 | TCP | 177 |
| 25 | TCP | 89 |
| 80 | TCP | 73 |
| 23 | TCP | 52 |
| 443 | TCP | 65 |
| 22222 | TCP | 39 |

**Most Common CVEs**

| CVE ID | Count |
|---|---|
| CVE-2005-4050 | 253 |
| CVE-2022-27255 | 50 |
| CVE-2021-3449 | 10 |
| CVE-2002-0013, CVE-2002-0012 | 13 |
| CVE-2019-11500 | 11 |

**Commands Attempted by Attackers**

| Command | Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 33 |
| `lockr -ia .ssh` | 33 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."` | 33 |
| `uname -a` | 32 |
| `cat /proc/cpuinfo | grep name | wc -l` | 30 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 30 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 30 |
| `ls -lh $(which ls)` | 30 |
| `which ls` | 30 |
| `crontab -l` | 30 |
| `w` | 30 |
| `uname -m` | 30 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 30 |
| `top` | 30 |
| `uname` | 30 |
| `whoami` | 30 |
| `lscpu | grep Model` | 30 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 28 |
| `Enter new UNIX password:` | 19 |
| `wget.sh;` | 8 |

**Signatures Triggered**

| Signature | Count |
|---|---|
| ET DROP Dshield Block Listed Source group 1 | 391 |
| 2402000 | 391 |
| ET SCAN NMAP -sS window 1024 | 223 |
| 2009582 | 223 |
| ET INFO Reserved Internal IP Traffic | 60 |
| 2002752 | 60 |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32 | 47 |
| 2400031 | 47 |
| ET CINS Active Threat Intelligence Poor Reputation IP group 49 | 28 |
| 2403348 | 28 |

**Users / Login Attempts**

| Username/Password | Attempts |
|---|---|
| 345gs5662d34/345gs5662d34 | 33 |
| root/nPSpP4PBW0 | 9 |
| test/zhbjETuyMffoL8F | 12 |
| foundry/foundry | 10 |
| root/LeitboGi0ro | 7 |
| debian/admin123 | 6 |
| deposito/deposito123 | 5 |
| admin/7ujMko0admin | 4 |
| config/config | 4 |
| user/P@$$word | 4 |

**Files Uploaded/Downloaded**

| Filename | Count |
|---|---|
| wget.sh | 8 |
| arm.urbotnetisass | 8 |
| arm5.urbotnetisass | 8 |
| arm6.urbotnetisass | 8 |
| arm7.urbotnetisass | 8 |
| x86_32.urbotnetisass | 8 |
| mips.urbotnetisass | 8 |
| mipsel.urbotnetisass | 8 |
| w.sh | 2 |
| c.sh | 2 |

**HTTP User-Agents**
No significant user-agent data was captured during the reporting period.

**SSH Clients**
No significant SSH client data was captured during the reporting period.

**SSH Servers**
No significant SSH server data was captured during the reporting period.

**Top Attacker AS Organizations**
No significant attacker AS organization data was captured during the reporting period.

### Google Searches

- **OSINT on IP address 137.184.169.79:** This IP address, registered to DigitalOcean in Toronto, Canada, is linked to a high-risk phishing website, "moonflirt.site." The site is flagged as malicious by multiple security services and is associated with stealing sensitive user information.
- **OSINT on IP address 58.186.122.40:** This IP address is geolocated to Thái Bình, Vietnam, and is associated with the ISP "The Corporation for Financing & Promoting Technology." There is no evidence of malicious activity from this IP in public threat intelligence databases.
- **OSINT on IP address 60.174.72.198:** This IP address, registered to CHINANET-BACKBONE in China, has been repeatedly associated with malicious SSH activities, including brute-force attacks.
- **What is CVE-2005-4050?:** A critical buffer overflow vulnerability in Multi-Tech VoIP devices that could allow remote attackers to execute arbitrary code.
- **What is CVE-2022-27255?:** A critical stack-based buffer overflow vulnerability in the Realtek AP-Router SDK that could allow an unauthenticated remote attacker to execute arbitrary code.
- **What is CVE-2021-3449?:** A high-severity denial-of-service vulnerability in OpenSSL that could allow an attacker to crash a server by sending a maliciously crafted ClientHello message during TLSv1.2 renegotiation.

### Key Observations and Anomalies

- **High-Volume Automated Attacks:** The sheer volume of attacks, particularly targeting SSH (port 22) and SMB (port 445), indicates the widespread use of automated scanning and exploitation tools.
- **Targeted Vulnerabilities:** The consistent exploitation of older vulnerabilities, such as CVE-2005-4050, alongside newer ones, suggests that attackers are casting a wide net, targeting systems that may not be regularly patched.
- **Botnet Activity:** The downloading of files with names like `arm.urbotnetisass`, `w.sh`, and `c.sh` strongly suggests attempts to enlist the honeypots into a botnet. The variety of architectures targeted (ARM, x86, MIPS) indicates a sophisticated and adaptable malware campaign.
- **Persistence Mechanisms:** The repeated use of commands to modify SSH authorized keys is a clear indicator of attempts to establish persistent access to the compromised systems.
- **Phishing and Malicious Infrastructure:** The investigation into the top attacking IP addresses revealed a connection to a phishing operation and other malicious activities, highlighting the broader criminal ecosystem that our honeypots are exposed to.
- **Geographic Distribution:** The attacks originated from a wide range of countries, with a significant concentration from the United States, China, and Vietnam. This global distribution is typical of botnet-driven attacks, where compromised machines are used to launch further attacks.

This report highlights the dynamic and aggressive nature of the current threat landscape. The focus on common services like SSH and SMB, coupled with the exploitation of known vulnerabilities and the deployment of botnet malware, underscores the importance of robust security measures, including regular patching, strong password policies, and network monitoring.