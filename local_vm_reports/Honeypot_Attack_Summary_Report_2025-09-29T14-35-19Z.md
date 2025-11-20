# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T15:00:00Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T14:00:01Z

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

## Executive Summary

This report provides a comprehensive analysis of malicious activities recorded across our distributed honeypot network over a 24-hour period. A total of **244,142** events were captured, revealing a high volume of automated attacks targeting a variety of services and vulnerabilities.

The threat landscape is dominated by automated scanning and brute-force campaigns, with a significant concentration of attacks originating from a limited number of highly active IP addresses. The most prominent activity involved interactions with the **Cowrie** (SSH/Telnet), **Honeytrap**, **Suricata** (IDS), and **Ciscoasa** honeypots.

Key findings from this period include:
*   **High Volume of Attacks:** The network registered over 244,000 events, indicating widespread and continuous automated attacks.
*   **Dominant Attack Vectors:** The Cowrie honeypot, simulating SSH and Telnet services, recorded the highest number of interactions, primarily consisting of brute-force login attempts.
*   **Concentrated Threat Sources:** A small number of IP addresses were responsible for a disproportionately large volume of traffic. Notably, IP address **162.244.80.233** was the most aggressive, logging over 15,000 events.
*   **Targeted Services:** Port 22 (SSH) and Port 445 (SMB) were the most targeted services, indicating a continued focus on exploiting remote access services and file-sharing protocols.
*   **Vulnerability Exploitation:** Several attempts to exploit known vulnerabilities were detected, with the most frequent being related to Log4j (CVE-2021-44228).
*   **Malware Delivery:** Analysis of executed commands reveals multiple attempts to download and execute malicious payloads from remote servers, a common tactic for establishing botnet persistence.

This report underscores the persistent and automated nature of modern cyber threats. The data highlights the necessity for robust perimeter defenses, strong credential policies, and timely patching of known vulnerabilities.

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

The distribution of attacks across the different honeypot services provides insight into the most targeted protocols and applications.

| Honeypot Service | Event Count |
|---|---|
| Cowrie | 95304 |
| Honeytrap | 45151 |
| Suricata | 32174 |
| Ciscoasa | 21217 |
| Dionaea | 7949 |
| Sentrypeer | 4731 |
| Mailoney | 3524 |
| Adbhoney | 572 |
| Tanner | 570 |
| Redishoneypot | 338 |
| H0neytr4p | 335 |
| ConPot | 316 |
| ElasticPot | 180 |
| Honeyaml | 106 |
| Heralding | 106 |
| Dicompot | 66 |
| Miniprint | 65 |
| ssh-rsa | 42 |
| Ipphoney | 25 |
| Wordpot | 4 |

### Top Attacking IPs

The following table lists the top 20 IP addresses with the highest number of recorded attack events. These IPs are likely part of automated botnets scanning for vulnerable systems.

| IP Address | Attack Count |
|---|---|
| 162.244.80.233 | 16366 |
| 147.182.150.164 | 4593 |
| 134.122.46.149 | 4421 |
| 4.144.169.44 | 4391 |
| 208.109.190.200 | 4153 |
| 142.93.159.126 | 3960 |
| 106.14.67.229 | 3630 |
| 45.140.17.52 | 3496 |
| 196.251.88.103 | 3418 |
| 43.163.91.110 | 3409 |
| 86.54.42.238 | 3283 |
| 147.45.193.115 | 3267 |
| 161.35.177.74 | 3192 |
| 134.199.202.5 | 3173 |
| 4.247.148.24 | 3168 |
| 81.183.253.80 | 3154 |
| 181.115.175.122 | 3154 |
| 143.198.32.86 | 3120 |
| 38.172.172.53 | 3102 |
| 103.146.202.84 | 3056 |

### Top Targeted Ports

The most frequently targeted ports indicate the services that attackers are most interested in compromising.

| Port | Protocol/Service | Attack Count |
|---|---|---|
| 22 | SSH | 11451 |
| 445 | SMB | 9545 |
| 5060 | SIP | 4731 |
| 8333 | Bitcoin | 1583 |
| 25 | SMTP | 1483 |
| 80 | HTTP | 973 |
| 1433 | MSSQL | 545 |
| 23 | Telnet | 499 |
| 6379 | Redis | 425 |
| 443 | HTTPS | 399 |
| 5900 | VNC | 374 |
| 1080 | SOCKS | 355 |
| 8888 | | 269 |
| 9000 | | 265 |
| 9200 | Elasticsearch | 258 |
| 8080 | HTTP Alt | 247 |
| 3389 | RDP | 231 |
| 8291 | MikroTik | 227 |
| 5432 | PostgreSQL | 213 |
| 2222 | SSH Alt | 207 |

### Most Common CVEs

A number of vulnerabilities were targeted during the observation period. The following table lists all unique CVEs and the number of times they were detected.

| CVE Identifier | Attack Count |
|---|---|
| CVE-2021-44228 | 511 |
| CVE-2022-27255 | 223 |
| CVE-2002-0013 | 118 |
| CVE-2002-0012 | 118 |
| CVE-1999-0517 | 93 |
| CVE-2019-11500 | 79 |
| CVE-2021-3449 | 78 |
| CVE-2005-4050 | 54 |
| CVE-2006-2369 | 23 |
| CVE-2024-3721 | 14 |
| CVE-1999-0183 | 11 |
| CVE-1999-0265 | 10 |
| CVE-2018-13379 | 9 |
| CVE-2024-12856 | 8 |
| CVE-2024-12885 | 8 |
| CVE-2023-26801 | 7 |
| CVE-2021-35394 | 7 |
| CVE-2019-9670 | 6 |
| CVE-2021-2109 | 6 |
| CVE-2019-9621 | 6 |

### Top Attacker AS Organizations

| AS Organization | Attack Count |
|---|---|
| GOOGLE | 1516 |
| DIGITALOCEAN-ASN | 1247 |
| CHOOPA | 1218 |
| RACKSRV | 1070 |
| ALIBABA-US-ASN | 1069 |
| AMAZON-02 | 930 |
| ASN-CHOOPA | 770 |
| OVH | 765 |
| CLOUDFLARENET | 634 |
| MICROSOFT-CORP-MSN-AS-BLOCK | 547 |

### Commands Attempted by Attackers

After gaining access, attackers executed a series of commands to perform reconnaissance, establish persistence, and download further malware. The most common commands are listed below.

| Command | Execution Count |
|---|---|
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 425 |
| `lockr -ia .ssh` | 425 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` | 425 |
| `uname -a` | 400 |
| `cat /proc/cpuinfo | grep name | wc -l` | 398 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'` | 398 |
| `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` | 398 |
| `ls -lh $(which ls)` | 398 |
| `which ls` | 398 |
| `crontab -l` | 398 |
| `w` | 398 |
| `uname -m` | 398 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 398 |
| `top` | 398 |
| `uname` | 398 |
| `whoami` | 398 |
| `lscpu | grep Model` | 398 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 398 |
| `Enter new UNIX password:` | 224 |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` | 148 |

## Key Observations and Anomalies

*   **Hyper-Aggressive IP Addresses:** A small number of IP addresses were responsible for a disproportionately large volume of traffic. Notably, IP address **162.244.80.233** was the most aggressive, logging over 16,000 events. This IP address is associated with a hosting provider in the United States and has a history of malicious activity.
*   **"mdrfckr" Signature:** A recurring command sequence was observed multiple times, designed to download and execute a botnet client (`urbotnetisass`) for various architectures (ARM, x86, MIPS). The SSH key used in this attack contains the string "mdrfckr", which is a known signature of a specific botnet.
*   **Malware Download and Execution:** Several command sequences stood out as particularly noteworthy, such as the download and execution of malware from `94.154.35.154`, which is a known malware distribution point.
*   **Targeting of Older Vulnerabilities:** The presence of very old CVEs (e.g., from 1999 and 2002) indicates that many attackers use outdated scanning tools that check for legacy vulnerabilities in the hope of finding unpatched, legacy systems.

## Google Searches

*   **162.244.80.233:** This IP address is associated with a hosting provider in the United States and has been reported for malicious activity, including SSH brute-force attacks and spam.
*   **147.182.150.164:** This IP address is associated with a hosting provider in the United States and has been reported for malicious activity, including SSH brute-force attacks and port scanning.
*   **134.122.46.149:** This IP address is associated with a hosting provider in the United States and has been reported for malicious activity, including SSH brute-force attacks and spam.
*   **4.144.169.44:** This IP address is associated with a large cloud provider and has been reported for malicious activity, including SSH brute-force attacks and port scanning.
*   **208.109.190.200:** This IP address is associated with a hosting provider in the United States and has been reported for malicious activity, including SSH brute-force attacks and spam.
*   **"mdrfckr" ssh key:** This SSH key is associated with a known botnet that has been active for several years. The botnet is known to target IoT devices and other systems with weak credentials.
*   **94.154.35.154:** This IP address is a known malware distribution point and has been associated with several different malware campaigns.

## Notes/Limitations

*   The data in this report is sourced exclusively from a network of honeypots. Honeypots are designed to attract and record malicious activity but do not represent a complete view of the threat landscape. The attacks recorded are primarily opportunistic and automated.
*   The IP addresses listed in this report should not be directly interpreted as the origin of the attacks. They are often compromised systems, open proxies, or VPN endpoints used to obfuscate the true source.
*   This report has been generated to meet a target length of 1000-2000 words to ensure a comprehensive yet concise summary.
*   This report was generated by an automated system based on raw log data. While efforts are made to ensure accuracy, the interpretation of events is based on predefined patterns and may not capture all nuances of an attack.

***End of Report***