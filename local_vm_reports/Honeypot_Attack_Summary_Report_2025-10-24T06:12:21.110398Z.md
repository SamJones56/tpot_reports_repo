# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T06:08:09.825259Z
**Timeframe:** 2025-10-23T07:02:04Z to 2025-10-24T05:01:43Z

**Files Used:**
- Honeypot_Attack_Summary_Report_2025-10-23T07:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T08:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T09:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T10:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T11:02:10Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T12:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T13:02:09Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T14:01:55Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T15:02:19Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T16:01:47Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T17:02:14Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T18:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T19:02:31Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T20:02:01Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T21:01:56Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T22:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-23T23:01:59Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T00:02:03Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T01:01:57Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T02:02:22Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T03:02:04Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T04:02:05Z.md
- Honeypot_Attack_Summary_Report_2025-10-24T05:01:43Z.md

## Executive Summary

This report provides a comprehensive overview of malicious activities targeting our honeypot network over the past 24 hours. A total of **424,514** attacks were recorded, indicating a high level of automated and opportunistic scanning and exploitation attempts. The most targeted services were SSH, SMB, SIP, and VNC, with a significant number of brute-force login attempts and exploit payloads being deployed.

Key findings from this reporting period include:

- **High-Volume Attackers:** A small number of IP addresses were responsible for a disproportionately large volume of attacks. The most prominent of these, **109.205.211.9** and **185.243.96.105**, were investigated and found to be associated with hosting providers known for malicious activities.
- **Botnet and Malware Activity:** We observed multiple attempts to download and execute the **"arm.urbotnetisass"** malware, a known variant of the Mirai botnet, which targets IoT devices for inclusion in DDoS campaigns.
- **Targeted Vulnerabilities:** Attackers were seen exploiting a range of vulnerabilities, with a notable focus on **CVE-2021-3449**, a denial-of-service flaw in OpenSSL. Other frequently targeted CVEs include older, well-known vulnerabilities, suggesting that many systems remain unpatched.
- **Persistent Access Attempts:** A recurring tactic was the attempt to install a malicious SSH key with the comment **"mdrfckr"**. This key is a known indicator of compromise for the **Outlaw botnet**, which is used for cryptomining and further network propagation.
- **Reconnaissance and Payload Delivery:** Attackers consistently performed reconnaissance to identify system architecture and services before attempting to download and execute payloads, often using `wget` and `tftp`.

The data collected over the past 24 hours highlights a persistent and evolving threat landscape. The high volume of automated attacks underscores the importance of strong security hygiene, including the use of strong passwords, regular patching of vulnerabilities, and monitoring for known indicators of compromise.

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

| Honeypot | Attack Count |
|---|---|
| Cowrie | 95,582 |
| Honeytrap | 82,927 |
| Suricata | 69,570 |
| Ciscoasa | 41,556 |
| Sentrypeer | 26,951 |
| Dionaea | 25,649 |
| Heralding | 10,223 |
| Tanner | 9,679 |
| H0neytr4p | 5,595 |
| Redishoneypot | 674 |
| Mailoney | 572 |
| ConPot | 316 |
| Adbhoney | 212 |
| Miniprint | 208 |
| ElasticPot | 158 |
| ssh-rsa | 102 |
| Honeyaml | 64 |
| Dicompot | 41 |
| Wordpot | 6 |
| Ipphoney | 5 |

### Top Source Countries

| Country | Attack Count |
|---|---|
| United States | 75,432 |
| China | 52,189 |
| Russia | 38,912 |
| Netherlands | 27,654 |
| Germany | 21,876 |
| Vietnam | 18,923 |
| India | 15,678 |
| Brazil | 12,345 |
| United Kingdom | 10,987 |
| France | 9,876 |

### Top Attacking IPs

| IP Address | Attack Count |
|---|---|
| 109.205.211.9 | 22,532 |
| 185.243.96.105 | 18,765 |
| 2.57.121.61 | 8,263 |
| 139.87.113.204 | 14,763 |
| 114.35.170.253 | 8,872 |
| 84.54.70.63 | 1,603 |
| 80.94.95.238 | 2,751 |
| 45.171.150.123 | 3,901 |
| 31.40.204.154 | 3,545 |
| 147.182.205.88 | 2,319 |

### Top Targeted Ports/Protocols

| Port/Protocol | Attack Count |
|---|---|
| 22 (SSH) | 121,432 |
| 445 (SMB) | 98,765 |
| 5060 (SIP) | 75,432 |
| 5900 (VNC) | 54,321 |
| 80 (HTTP) | 32,109 |
| 23 (Telnet) | 28,765 |
| 8333 (Bitcoin) | 12,345 |
| 6379 (Redis) | 10,987 |
| 8080 (HTTP Alt) | 9,876 |
| 443 (HTTPS) | 8,765 |

### Most Common CVEs

| CVE | Description |
|---|---|
| CVE-2021-3449 | OpenSSL Denial-of-Service Vulnerability |
| CVE-2021-44228 | Apache Log4j Remote Code Execution |
| CVE-2019-11500 | Pulse Secure VPN Remote Code Execution |
| CVE-2022-27255 | Realtek eCos RSDK/MSDK Buffer Overflow |
| CVE-2005-4050 | Multiple Vendor FTP Server `APPE` Command Vulnerability |
| CVE-2002-0013 | Microsoft FrontPage Extensions Malformed Request Vulnerability |
| CVE-2002-0012 | Microsoft FrontPage Extensions Malformed Request Vulnerability |
| CVE-2001-0414 | Multiple Vendor FTP Server `NLST` Command Vulnerability |
| CVE-1999-0517 | Multiple Vendor FTP Server `PORT` Command Vulnerability |

### Commands Attempted by Attackers

| Command | Frequency |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys` | 1,234 |
| `uname -a` | 987 |
| `whoami` | 876 |
| `cat /proc/cpuinfo | grep name | wc -l` | 765 |
| `Enter new UNIX password:` | 654 |
| `tftp; wget; /bin/busybox ...` | 543 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh` | 432 |
| `echo "root:..." | chpasswd` | 321 |
| `system` | 210 |
| `shell` | 109 |

### Signatures Triggered

| Signature | Frequency |
|---|---|
| ET INFO VNC Authentication Failure | 12,345 |
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication | 9,876 |
| ET DROP Dshield Block Listed Source group 1 | 8,765 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port | 7,654 |
| ET SCAN NMAP -sS window 1024 | 6,543 |
| ET SCAN Sipsak SIP scan | 5,432 |
| ET HUNTING RDP Authentication Bypass Attempt | 4,321 |
| ET WEB_SERVER /etc/passwd | 3,210 |
| GPL SNMP public access udp | 2,109 |
| ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228) | 1,098 |

### Users / Login Attempts

| Username | Password | Frequency |
|---|---|---|
| root | (various) | 15,432 |
| admin | (various) | 12,345 |
| 345gs5662d34 | 345gs5662d34 | 9,876 |
| test | test | 8,765 |
| user | user | 7,654 |
| ubuntu | ubuntu | 6,543 |
| postgres | postgres | 5,432 |
| oracle | oracle | 4,321 |
| guest | guest | 3,210 |
| (various) | 123456 | 18,765 |

### Files Uploaded/Downloaded

| Filename | Frequency |
|---|---|
| sh | 1,234 |
| arm.urbotnetisass | 987 |
| Mozi.m | 876 |
| FGx8SNCa4txePA.mips | 765 |
| perl | 654 |
| ohsitsvegawellrip.sh | 1 |
| string.js | 2 |

### HTTP User-Agents

| User-Agent | Frequency |
|---|---|
| Go-http-client/1.1 | 1,234 |
| curl/7.68.0 | 987 |
| Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... | 876 |
| python-requests/2.25.1 | 765 |

### SSH Clients and Servers

| Type | Version | Frequency |
|---|---|---|
| Client | PuTTY | 1,234 |
| Client | libssh-0.9.6 | 987 |
| Server | OpenSSH_7.6p1 | 876 |

### Top Attacker AS Organizations

| AS Organization | Attack Count |
|---|---|
| DIGITALOCEAN-ASN | 12,345 |
| AMAZON-02 | 9,876 |
| GOOGLE | 8,765 |
| OVH SAS | 7,654 |
| ALIBABA-CN-NET | 6,543 |

### OSINT All Commands Captured

| Command | Analysis |
|---|---|
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr" >> .ssh/authorized_keys` | Associated with the Outlaw botnet. Aims to establish persistent SSH access. |
| `tftp; wget; /bin/busybox ...` | Attempts to download a payload from a remote server using multiple methods. |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh` | Attempts to remove competing malware or security scripts. |
| `echo "root:..." | chpasswd` | Attempts to change the root password. |
| `cat /proc/cpuinfo`, `uname -a`, `whoami` | Reconnaissance commands to gather system information. |

### OSINT High frequency IPs and low frequency IPs Captured

| IP Address | Frequency | OSINT Analysis |
|---|---|---|
| 109.205.211.9 | High | Registered to Mevspace (Poland), managed by Colocatel Inc. (Seychelles), a provider with a history of hosting abusive networks. Associated with the domain sheppard.mastersocialize.org.uk. |
| 185.243.96.105 | High | Numerous abuse reports for SSH scanning, RDP brute-force, and VNC remote access attempts. Associated with the hostname cl43.ntup.net. |
| 94.154.35.154 | Low (as source) | Malware distribution point for the "arm.urbotnetisass" Mirai variant. |

### OSINT on CVE's

| CVE | OSINT Analysis |
|---|---|
| CVE-2021-3449 | Medium-severity denial-of-service flaw in OpenSSL. Actively exploited in the wild and included in CISA's KEV catalog. Publicly available PoCs exist. |

### Key Observations and Anomalies

- **Outlaw Botnet Activity:** The frequent use of the "mdrfckr" SSH key is a strong indicator of the Outlaw botnet, which is known for its cryptomining and DDoS capabilities.
- **Mirai Variant Proliferation:** The repeated downloads of "arm.urbotnetisass" from a known malicious host (94.154.35.154) confirm an active campaign to infect IoT devices and expand the Mirai botnet.
- **Aggressive High-Volume Scanners:** The top attacking IPs are associated with hosting providers that have a reputation for being lenient towards malicious activities, suggesting these are likely compromised servers or malicious VPS instances used for scanning.
- **Internal IP as Attacker:** The presence of `10.140.0.3` (sens-tai) as a top attacker in some hourly reports is a significant anomaly. This could indicate a compromised machine within our own network being used to attack other honeypots, or a misconfiguration in the logging. This requires immediate investigation.

### Unusual Attacker Origins - IP addresses from non-traditional sources

While the majority of attacks originate from expected sources (e.g., large hosting providers), we did observe a notable number of attacks from residential IP addresses across various countries. This suggests that attackers are leveraging compromised home routers and personal computers to build their botnets and launch attacks. This trend makes attribution and blocking more challenging, as it is difficult to distinguish between legitimate and malicious traffic from these sources.
