# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T10:31:00.865610Z
**Timeframe:** Last 1 Hour (2025-10-21T09:31:00.865610Z to 2025-10-21T10:31:00.865610Z)
**Files Used:** Live Elastic Query Data

---

## Executive Summary

Over the past hour, our honeypot network observed a total of **18,131** attacks, indicating a high level of automated and targeted scanning activity across the internet. The primary sources of these attacks were IP addresses originating from **Canada, the United States, and Italy**. A single IP address, **142.4.197.12**, originating from OVH SAS in Canada, was responsible for an overwhelming majority of the traffic, launching **5,666** attacks alone. This suggests a highly aggressive, targeted scanning operation from a single source.

The attacks were distributed across various honeypot services, with **Honeytrap (10,059 events)** and **Cowrie (6,389 events)** logging the most interactions. This indicates a strong focus on SSH and a wide array of other TCP ports, which these honeypots are designed to emulate.

Key attack vectors included brute-force attempts against SSH (port 22) and scanning of service ports such as SIP (5060) and Windows SMB (445). A significant amount of VNC-related traffic was also detected through alert signatures. Attackers predominantly used common credential pairs like `root`/`123456`, typical of botnet-driven brute-force campaigns.

Multiple security alerts were triggered, with the most frequent being "GPL INFO VNC server response" and various `SURICATA STREAM` anomalies, which point towards network scanning, evasion techniques, or malformed packets from attacker tools. Several alerts for known vulnerabilities were also observed, including attempts to exploit flaws in Dovecot (CVE-2019-11500), Apache HTTP Server (CVE-2021-42013), and the infamous "Shellshock" bug (CVE-2014-6271).

Overall, the activity in the last hour reflects a dynamic threat landscape characterized by high-volume scanning from compromised servers or malicious hosting infrastructure, combined with opportunistic exploitation of known vulnerabilities and weak credentials.

---

## Detailed Analysis

### Our IPs

| Honeypot | Private IP    | Public IP      |
|----------|---------------|----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205 |
| sens-tai | 10.140.0.3    | 104.199.212.115|
| sens-tel | 10.208.0.3    | 34.165.197.224 |
| sens-dub | 172.31.36.128 | 3.253.97.195   |
| sens-ny  | 10.108.0.2    | 161.35.180.163 |

### Attacks by Honeypot

| Honeypot        | Attack Count |
|-----------------|--------------|
| Honeytrap       | 10059        |
| Cowrie          | 6389         |
| Dionaea         | 788          |
| Sentrypeer      | 664          |
| Mailoney        | 38           |
| Ciscoasa        | 34           |
| ConPot          | 32           |
| Tanner          | 31           |
| Redishoneypot   | 24           |
| H0neytr4p       | 22           |
| Adbhoney        | 16           |
| Dicompot        | 12           |
| Miniprint       | 12           |
| ElasticPot      | 7            |
| Ipphoney        | 2            |
| Honeyaml        | 1            |

### Top Source Countries

| Country       | Attack Count |
|---------------|--------------|
| Canada        | 5882         |
| United States | 4917         |
| Italy         | 1221         |
| India         | 856          |
| China         | 762          |
| Hong Kong     | 594          |
| France        | 424          |
| The Netherlands | 422        |
| Germany       | 396          |
| Brazil        | 346          |

### Top Attacking IPs

| Source IP         | Attack Count |
|-------------------|--------------|
| 142.4.197.12      | 5666         |
| 72.146.232.13     | 1221         |
| 165.227.98.222    | 1100         |
| 72.167.220.12     | 613          |
| 103.163.113.38    | 341          |
| 1.94.38.61        | 301          |
| 185.243.5.158     | 271          |
| 23.94.26.58       | 263          |
| 107.170.36.5      | 254          |
| 162.214.92.14     | 224          |
| 185.117.154.233   | 224          |

### Top Targeted Ports/Protocols

| Port | Protocol/Service | Attack Count |
|------|------------------|--------------|
| 22   | SSH              | 1461         |
| 5060 | SIP              | 711          |
| 445  | SMB              | 700          |
| 5903 | VNC              | 224          |
| 5904 | VNC              | 79           |
| 5901 | VNC              | 114          |
| 5905 | VNC              | 79           |
| 8333 | Bitcoin          | 111          |
| 25   | SMTP             | 59           |
| 23   | Telnet           | 55           |

*(Note: Port counts are aggregated from country-specific data and represent a minimum observed count.)*

### Most Common CVEs

| CVE ID(s)                                                                                                                                                                                                                                                | Count |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| CVE-2019-11500                                                                                                                                                                                                                                           | 8     |
| CVE-2002-0013, CVE-2002-0012                                                                                                                                                                                                                              | 6     |
| CVE-2021-3449                                                                                                                                                                                                                                            | 2     |
| CVE-2006-3602, CVE-2006-4458, CVE-2006-4542                                                                                                                                                                                                                | 1     |
| CVE-2009-2765                                                                                                                                                                                                                                            | 1     |
| CVE-2014-6271                                                                                                                                                                                                                                            | 1     |
| CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056                                                                                                                                                                               | 1     |
| CVE-2016-20017                                                                                                                                                                                                                                           | 1     |
| CVE-2019-16920                                                                                                                                                                                                                                           | 1     |
| CVE-2021-35395                                                                                                                                                                                                                                           | 1     |
| CVE-2021-42013                                                                                                                                                                                                                                           | 1     |
| CVE-2023-31983                                                                                                                                                                                                                                           | 1     |
| CVE-2023-47565                                                                                                                                                                                                                                           | 1     |
| CVE-2023-52163                                                                                                                                                                                                                                           | 1     |
| CVE-2024-10914                                                                                                                                                                                                                                           | 1     |
| CVE-2024-12856, CVE-2024-12885                                                                                                                                                                                                                            | 1     |
| CVE-2024-3721                                                                                                                                                                                                                                            | 1     |

### Signatures Triggered

| Signature                                     | Count |
|-----------------------------------------------|-------|
| GPL INFO VNC server response                  | 7524  |
| SURICATA STREAM Packet with broken ack        | 5752  |
| SURICATA STREAM ESTABLISHED packet out of window| 3355  |
| GPL ICMP PING                                 | 2806  |
| ET DROP Dshield Block Listed Source group 1   | 486   |
| SURICATA STREAM Packet with invalid ack       | 451   |
| ET INFO SSH session in progress on Expected Port| 230   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port| 230   |
| ET USER_AGENTS Go HTTP Client User-Agent      | 216   |
| ET INFO Go-http-client User-Agent Observed Outbound| 216   |

### User / Login Attempts

**Top Usernames**
| Username      | Attempts |
|---------------|----------|
| root          | 197      |
| user          | 24       |
| oracle        | 14       |
| 345gs5662d34  | 13       |
| user01        | 13       |
| ubuntu        | 12       |
| admin         | 11       |
| test          | 10       |
| deploy        | 9        |
| es            | 8        |

**Top Passwords**
| Password        | Attempts |
|-----------------|----------|
| 123456          | 127      |
| 123             | 55       |
| abc123          | 15       |
| 3245gs5662d34   | 14       |
| 345gs5662d34    | 13       |
| Password01      | 9        |
| 1               | 8        |
| 12345678        | 6        |
| password        | 6        |
| test            | 6        |

### Top Attacker AS Organizations

| ASN Organization              | Attack Count |
|-------------------------------|--------------|
| OVH SAS                       | 5757         |
| DIGITALOCEAN-ASN              | 1886         |
| MICROSOFT-CORP-MSN-AS-BLOCK   | 1689         |
| GOOGLE-CLOUD-PLATFORM         | 1047         |
| GO-DADDY-COM-LLC              | 613          |
| AS-COLOCROSSING               | 523          |
| KERALA FIBRE OPTIC NETWORK... | 341          |
| UNIFIEDLAYER-AS-1             | 334          |
| UCLOUD INFORMATION...         | 320          |
| Huawei Cloud Service...       | 301          |

---

## OSINT Investigations

### OSINT on High and Low Frequency IPs

| IP Address     | Frequency | ASN Organization | OSINT Findings                                                                                                                                                                                                   |
|----------------|-----------|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **142.4.197.12** | High      | OVH SAS          | Associated with OVH Hosting. The high volume of attacks suggests this is a compromised server or a dedicated machine being used for mass scanning. The lack of a specific AbuseIPDB report is not unusual for IPs from large hosting providers. |
| **72.146.232.13**| High      | (Not Queried)    | No specific AbuseIPDB report was found through the search, requiring a direct lookup. IPs in this range have been associated with various scanning activities in the past.                                     |
| **165.227.98.222**| High      | DIGITALOCEAN-ASN | Registered to DigitalOcean in the US. Third-party intelligence sites show a low but present threat level, with a history of a small number of attacks, indicating it may be a newly compromised host.             |
| **1.24.16.206**  | Low       | CHINA UNICOM     | Belongs to a major Chinese ISP. This IP has been found on other blocklists like Dataplane.org and ciarmy.com's "badguys" list, indicating a history of malicious activity.                                   |
| **60.188.249.64**  | Low       | CT-HangZhou-IDC  | Located in China. AbuseIPDB reports confirm malicious activity, specifically port scanning (port 22) and SSH brute-force attempts with "Invalid user" logs.                                                 |
| **8.211.43.53**  | Low       | Alibaba (US)     | Registered to Alibaba in Germany. The IP has been reported for abuse multiple times and appears on at least one blocklist, strongly suggesting it has been used for malicious purposes.                         |

### OSINT on CVEs

| CVE ID        | Summary                                                                                                                                                                                  |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CVE-2019-11500** | A critical remote code execution vulnerability in the Dovecot email server. It involves an out-of-bounds memory write, allowing an attacker to crash the server or execute arbitrary code. |
| **CVE-2002-0013** | A widespread, critical vulnerability in SNMPv1 implementations. Specially crafted SNMP requests could cause a denial of service or allow an attacker to gain unauthorized privileges.      |
| **CVE-2021-3449** | A critical denial-of-service vulnerability in OpenSSL. A maliciously crafted ClientHello message during TLSv1.2 renegotiation can cause a NULL pointer dereference, crashing the server.  |
| **CVE-2014-6271** | The "Shellshock" vulnerability. A critical flaw in GNU Bash that allows remote code execution by passing crafted strings in environment variables, often exploited via web servers (CGI). |
| **CVE-2019-16920** | A critical unauthenticated remote code execution vulnerability in numerous end-of-life D-Link routers, allowing attackers to take full control of the device.                            |
| **CVE-2021-35395** | A critical remote code execution vulnerability in the Realtek Jungle SDK, affecting a wide range of IoT devices. It has been actively exploited to spread Mirai malware.                |
| **CVE-2021-42013** | A critical path traversal and remote code execution vulnerability in Apache HTTP Server (versions 2.4.49 & 2.4.50), which was an incomplete fix for a prior CVE.                       |
| **CVE-2024-3721**  | A critical command injection vulnerability affecting TBK DVR models, allowing a remote attacker to execute arbitrary OS commands. This CVE is known to be actively exploited.            |

---

## Key Observations and Anomalies

1.  **Single-Source Dominance:** The most significant anomaly is the activity from **142.4.197.12 (OVH SAS)**, which single-handedly accounts for over 31% of all attacks in the last hour. This is not typical background noise but a concerted, high-volume scanning campaign from a single source, likely a compromised server within the OVH network.

2.  **High Volume of Stream Anomalies:** The top triggered signatures are dominated by `SURICATA STREAM` events ("Packet with broken ack," "ESTABLISHED packet out of window"). This indicates that a large portion of the traffic is malformed or non-standard. This can be a sign of custom scanning tools designed for speed and evasion, which may not adhere to standard TCP/IP session rules, or it could be a byproduct of IDS/IPS systems interfering with traffic.

3.  **VNC Scanning:** The top alert by a large margin is "GPL INFO VNC server response," with over 7,500 hits. This, combined with the targeting of VNC ports (5901-5905), points to a massive, ongoing scan for open VNC servers, which are a common target for attackers looking for remote access to systems.

4.  **Exploitation of Both Old and New CVEs:** The CVEs detected span over two decades, from a 2002 SNMP flaw (CVE-2002-0013) to recent 2024 DVR vulnerabilities (CVE-2024-3721). This demonstrates that attackers use a "shotgun" approach, scanning for a wide array of vulnerabilities, both old and new, in the hope of finding unpatched legacy systems or newly discovered flaws.

5.  **Brute-Force Credentials:** The prevalence of username/password combinations like `root`/`123456` and `user`/`123` is a clear indicator of automated, dictionary-based brute-force attacks. However, the presence of more specific credentials like `345gs5662d34` is unusual and may be default credentials for specific IoT devices or leftover artifacts from other malware.
