# Honeypot Attack Summary Report

## 1. Report Information

- **Report ID:** HSR-20250929-080123
- **Generation Time:** 2025-09-29T08:01:23Z
- **Reporting Period:** 2025-09-29T07:20:01Z to 2025-09-29T08:00:01Z
- **Data Sources:**
    - `agg_log_20250929T072001Z.json`
    - `agg_log_20250929T074001Z.json`
    - `agg_log_20250929T080001Z.json`

## 2. Executive Summary

This report summarizes the findings from the T-Pot honeypot network over a period of approximately 40 minutes. A total of 11,286 attacks were recorded across various honeypot services. The most targeted services were Suricata, Honeytrap, and Cowrie, indicating a high volume of network scanning, SSH brute-force attempts, and web application attacks.

A significant portion of the attacks originated from a small number of IP addresses, with the top 5 IPs accounting for over 30% of the total attack volume. The most prominent attack vector was the exploitation of SMB vulnerabilities, with TCP port 445 being the most targeted port. Several CVEs were detected, with CVE-2021-44228 (Log4j) being the most frequently observed.

Analysis of the captured commands and credentials reveals a consistent pattern of attackers attempting to gain initial access, escalate privileges, and establish persistent backdoors. The commands executed post-compromise include reconnaissance commands to gather system information, as well as attempts to download and execute malicious payloads.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table shows the distribution of attacks across the different honeypot services.

| Honeypot Service | Attack Count |
| --- | --- |
| Suricata | 3,233 |
| Honeytrap | 2,467 |
| Cowrie | 2,257 |
| Ciscoasa | 1,458 |
| Mailoney | 848 |
| Dionaea | 645 |
| Sentrypeer | 209 |
| Redishoneypot | 75 |
| Tanner | 31 |
| H0neytr4p | 21 |
| ElasticPot | 9 |
| ConPot | 9 |
| Adbhoney | 8 |
| Heralding | 6 |
| Honeyaml | 6 |
| Dicompot | 4 |
| **Total** | **11,286** |

### 3.2. Top 20 Attacking IP Addresses

The following table lists the top 20 IP addresses with the highest number of attacks.

| IP Address | Attack Count |
| --- | --- |
| 168.187.86.35 | 1,476 |
| 86.54.42.238 | 821 |
| 81.183.253.80 | 556 |
| 161.35.177.74 | 353 |
| 185.156.73.166 | 380 |
| 103.55.36.22 | 369 |
| 185.156.73.167 | 374 |
| 92.63.197.55 | 362 |
| 92.63.197.59 | 342 |
| 4.213.138.243 | 278 |
| 219.92.8.22 | 283 |
| 208.109.190.200 | 196 |
| 3.109.101.113 | 199 |
| 204.76.203.28 | 142 |
| 150.109.244.181 | 134 |
| 192.241.169.58 | 135 |
| 172.245.163.134 | 92 |
| 196.251.80.75 | 91 |
| 34.180.75.99 | 89 |
| 3.149.59.26 | 64 |

### 3.3. Top 20 Targeted TCP/UDP Ports

The following table lists the top 20 most targeted TCP and UDP ports.

| Port | Protocol | Attack Count |
| --- | --- | --- |
| 445 | TCP | 2,038 |
| 25 | TCP | 848 |
| 22 | TCP | 335 |
| 5060 | UDP | 209 |
| 6379 | TCP | 75 |
| 8333 | TCP | 74 |
| 1080 | TCP | 24 |
| 5432 | TCP | 33 |
| 1433 | TCP | 12 |
| 80 | TCP | 23 |
| 2222 | TCP | 26 |
| 9000 | TCP | 17 |
| 9922 | TCP | 32 |
| 4145 | TCP | 14 |
| 20029 | TCP | 14 |
| 161 | UDP | 14 |
| 9090 | TCP | 14 |
| 9999 | TCP | 13 |
| 3306 | TCP | 12 |
| 7897 | TCP | 11 |

### 3.4. CVEs Exploited

The following table lists all the CVEs that were detected in the attack traffic.

| CVE | Count |
| --- | --- |
| CVE-2021-44228 | 38 |
| CVE-2022-27255 | 28 |
| CVE-2002-0013 | 11 |
| CVE-2002-0012 | 11 |
| CVE-1999-0517 | 4 |
| CVE-2021-3449 | 5 |
| CVE-2019-11500 | 3 |
| CVE-2018-13379 | 2 |
| CVE-2019-12263 | 1 |
| CVE-2019-12261 | 1 |
| CVE-2019-12260 | 1 |
| CVE-2019-12255 | 1 |
| CVE-2024-3721 | 1 |

### 3.5. Top 20 Credentials Used in Attacks

The following table lists the top 20 username/password combinations used in brute-force attacks.

| Username | Password | Count |
| --- | --- | --- |
| root | | 10 |
| 345gs5662d34 | 345gs5662d34 | 10 |
| test | zhbjETuyMffoL8F | 6 |
| root | Linux@123 | 5 |
| root | nPSpP4PBW0 | 5 |
| root | 123asd123 | 4 |
| root | LeitboGi0ro | 5 |
| fer | fer | 3 |
| fer | 3245gs5662d34 | 3 |
| root | asdzxc123 | 3 |
| pandora | pandora123 | 3 |
| root | Yojimbo271077@ | 3 |
| bob | | 3 |
| root | Passw0rd | 3 |
| checker | checker123 | 3 |
| apollo | apollo123 | 2 |
| winter | winter123 | 2 |
| root | hanseatic | 2 |
| insight | insight123 | 2 |
| root | 1a2b3c4d5e | 2 |

### 3.6. Top 20 Commands Executed

The following table lists the top 20 commands executed by attackers after gaining access to a honeypot.

| Command | Count |
| --- | --- |
| whoami | 15 |
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 10 |
| lockr -ia .ssh | 10 |
| uname -a | 11 |
| cat /proc/cpuinfo | grep name | wc -l | 10 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}' | 10 |
| free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}' | 10 |
| ls -lh $(which ls) | 10 |
| which ls | 10 |
| crontab -l | 10 |
| w | 10 |
| uname -m | 10 |
| cat /proc/cpuinfo | grep model | grep name | wc -l | 10 |
| top | 10 |
| uname | 10 |
| lscpu | grep Model | 10 |
| df -h | head -n 2 | awk 'FNR == 2 {print $2;}' | 10 |
| Enter new UNIX password: | 8 |
| Enter new UNIX password: | 8 |
| cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~ | 10 |


## 4. Notes and Limitations

- The data in this report is based on a limited time frame and may not be representative of long-term trends.
- The IP addresses listed in this report are the sources of the attacks as seen by the honeypots and may be part of a larger botnet or compromised infrastructure.
- The CVEs listed are based on signatures and patterns detected in the attack traffic and do not necessarily indicate a successful exploitation of the vulnerability.
- The commands and credentials captured are from successful logins to the honeypot services and may not represent the full scope of the attackers' capabilities.
- The total number of attacks includes both automated and manual attempts.

This report is intended for informational purposes and should be used to inform defensive strategies and improve security posture. It is recommended to block the top attacking IP addresses and monitor for traffic to the top targeted ports. Further analysis of the captured payloads and commands is recommended to understand the attackers' motives and techniques.
