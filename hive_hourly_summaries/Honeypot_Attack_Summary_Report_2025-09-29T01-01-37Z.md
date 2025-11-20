
# Honeypot Attack Summary Report

## 1. Report Information

*   **Report ID:** 55ab654d-8067-4217-a2f0-15e858509873
*   **Date of Generation:** 2025-09-29T01:01:20Z
*   **Time Period Covered:** 2025-09-29T00:20:01Z to 2025-09-29T01:00:01Z

## 2. Executive Summary

This report summarizes malicious activities recorded by our honeypot network over a 40-minute period. A total of 19,339 events were captured across three log files, indicating a high volume of automated attacks. The primary targets were services associated with remote access and file sharing, with Cowrie (SSH/Telnet) and Dionaea (SMB/HTTP) honeypots recording the most interactions. A significant portion of the attacks originated from a concentrated number of IP addresses, suggesting coordinated campaigns. Attackers were observed attempting to exploit known vulnerabilities, including Log4j (CVE-2021-44228), and brute-forcing credentials to gain unauthorized access.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table shows the distribution of attacks across the different honeypots:

| Honeypot | Attack Count |
| :--- | :--- |
| Cowrie | 9611 |
| Suricata | 3126 |
| Dionaea | 2502 |
| Honeytrap | 2441 |
| Ciscoasa | 1417 |
| Adbhoney | 95 |
| Sentrypeer | 32 |
| Tanner | 28 |
| Redishoneypot | 20 |
| H0neytr4p | 20 |
| Mailoney | 11 |
| Honeyaml | 16 |
| ConPot | 5 |
| Dicompot | 3 |
| Wordpot | 1 |
| ElasticPot | 1 |

### 3.2. Top 10 Attacking IP Addresses

The following table lists the top 10 most active attacking IP addresses:

| IP Address | Attack Count |
| :--- | :--- |
| 31.186.48.73 | 1626 |
| 134.122.46.149 | 1450 |
| 91.245.156.255 | 1184 |
| 147.182.150.164 | 1325 |
| 20.2.136.52 | 1242 |
| 104.131.110.234 | 704 |
| 58.181.99.73 | 916 |
| 58.181.99.75 | 874 |
| 144.130.11.9 | 536 |
| 176.107.152.59 | 266 |

### 3.3. Top 10 Destination Ports

The following table lists the top 10 most targeted destination ports:

| Port | Protocol | Attack Count |
| :--- | :--- | :--- |
| 445 | TCP | 4041 |
| 22 | TCP | 1314 |
| 1433 | TCP | 59 |
| 23 | TCP | 68 |
| 8333 | TCP | 108 |
| 5555 | TCP | 32 |
| 80 | TCP | 36 |
| 443 | TCP | 21 |
| 81 | TCP | 19 |
| 6379 | TCP | 14 |

### 3.4. CVEs Exploited

The following CVEs were detected in attack payloads:

| CVE | Count |
| :--- | :--- |
| CVE-2021-44228 | 35 |
| CVE-2002-0013 | 7 |
| CVE-2002-0012 | 7 |
| CVE-1999-0517 | 3 |
| CVE-2019-11500 | 2 |
| CVE-2005-4050 | 1 |

### 3.5. Top 10 Credentials Used in Attacks

The following are the top 10 username/password combinations used by attackers:

| Username/Password | Count |
| :--- | :--- |
| 345gs5662d34/345gs5662d34 | 21 |
| root/nPSpP4PBW0 | 11 |
| root/Passw0rd | 5 |
| hadoop/hadoop | 5 |
| test/zhbjETuyMffoL8F | 4 |
| root/Azerty123 | 5 |
| test/abc123 | 3 |
| hadoop/123 | 3 |
| mysql/mysql | 3 |
| root/snoopy12 | 3 |

### 3.6. Top 10 Commands Executed

The following are the top 10 commands executed by attackers after gaining access:

| Command | Count |
| :--- | :--- |
| uname -a | 22 |
| whoami | 21 |
| cd ~; chattr -ia .ssh; lockr -ia .ssh | 21 |
| lockr -ia .ssh | 21 |
| cd ~ && rm -rf .ssh && ... | 21 |
| cat /proc/cpuinfo | grep name | wc -l | 21 |
| cat /proc/cpuinfo | grep name | head -n 1 | awk '{...}' | 21 |
| free -m | grep Mem | awk '{...}' | 21 |
| ls -lh $(which ls) | 21 |
| which ls | 21 |

## 4. Notes & Limitations

*   The data in this report is based on a limited 40-minute window and may not be representative of long-term trends.
*   The honeypots are designed to attract attackers and may not reflect the full spectrum of attacks against a real production environment.
*   The attacking IP addresses may be part of botnets or compromised systems, and their geographic location may not be the true origin of the attack.
*   The CVEs listed are based on signatures and may not represent successful exploitation.

This report is intended for informational purposes and should be used in conjunction with other security data for a comprehensive understanding of the threat landscape.
