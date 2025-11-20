
# Honeypot Attack Summary Report

## 1. Report Information

*   **Report ID:** 471b4a3c-b258-406a-93f6-889816c14a93
*   **Generation Time:** 2025-09-29T13:01:44Z
*   **Time Range:** 2025-09-29T12:20:01Z to 2025-09-29T13:00:01Z
*   **Data Source:** T-Pot Honeypot Network
*   **Report Author:** Cybersecurity Data Analysis Agent

## 2. Executive Summary

This report provides a consolidated summary of malicious activities recorded by the T-Pot honeypot network over a period of approximately 40 minutes on September 29, 2025. A total of **11,972** attacks were detected across various honeypot services, indicating a significant and sustained level of automated scanning and exploitation attempts.

The **Cowrie** honeypot, emulating SSH and Telnet services, was the most targeted, accounting for **5,564** of the total interactions. This highlights the continued focus of attackers on compromising remote access services. Other significantly targeted services include **Honeytrap**, **Suricata**, and **Ciscoasa**.

The majority of attacks originated from a diverse set of IP addresses, with the top contributors being **8.218.160.83**, **208.109.190.200**, and **124.243.151.58**. These IPs were primarily involved in brute-force attacks and vulnerability scanning. The most frequently targeted ports were **22 (SSH)**, **5060 (SIP)**, and various web-related ports like **80** and **443**, as well as proxy ports like **1080**.

Attackers attempted to exploit several vulnerabilities, with a notable number of attempts targeting **CVE-2021-44228 (Log4Shell)**. A variety of other CVEs were also observed, indicating a broad-spectrum approach to finding vulnerable systems.

Analysis of captured commands and credentials reveals common attacker tactics, such as attempts to add SSH keys for persistent access, reconnaissance commands to identify system information (`uname`, `lscpu`), and the use of weak or default credentials like `root/Passw0rd`.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The distribution of attacks across the different honeypot services provides insight into the most targeted protocols and applications.

| Honeypot Service | Attack Count | Percentage of Total |
| :--- | :--- | :--- |
| Cowrie | 5,564 | 46.47% |
| Honeytrap | 2,125 | 17.75% |
| Suricata | 1,594 | 13.31% |
| Ciscoasa | 1,463 | 12.22% |
| Sentrypeer | 656 | 5.48% |
| Heralding | 225 | 1.88% |
| Dionaea | 98 | 0.82% |
| Tanner | 69 | 0.58% |
| Adbhoney | 40 | 0.33% |
| Mailoney | 36 | 0.30% |
| Redishoneypot | 39 | 0.33% |
| H0neytr4p | 22 | 0.18% |
| Ipphoney | 12 | 0.10% |
| Miniprint | 15 | 0.13% |
| Honeyaml | 9 | 0.08% |
| Dicompot | 3 | 0.03% |
| Wordpot | 1 | 0.01% |
| ElasticPot | 1 | 0.01% |
| **Total** | **11,972** | **100%** |

### 3.2. Top Attacker IP Addresses

The following table lists the top 20 IP addresses with the highest number of recorded attack events. These IPs are likely part of automated botnets scanning for vulnerable systems.

| IP Address | Attack Count |
| :--- | :--- |
| 8.218.160.83 | 1220 |
| 208.109.190.200 | 615 |
| 124.243.151.58 | 396 |
| 185.156.73.166 | 379 |
| 185.156.73.167 | 367 |
| 92.63.197.55 | 362 |
| 92.63.197.59 | 338 |
| 118.45.205.44 | 313 |
| 103.144.247.183 | 313 |
| 4.144.169.44 | 309 |
| 120.48.128.191 | 299 |
| 4.247.148.24 | 288 |
| 27.112.78.177 | 185 |
| 199.195.251.10 | 172 |
| 167.71.196.171 | 181 |
| 157.245.49.180 | 253 |
| 194.107.115.65 | 247 |
| 115.151.72.122 | 328 |
| 74.243.210.62 | 123 |
| 190.34.200.34 | 128 |


### 3.3. Top Target Ports

The most frequently targeted ports indicate the services that attackers are most interested in compromising.

| Port | Protocol/Service | Attack Count |
| :--- | :--- | :--- |
| 22 | SSH | 876 |
| 5060 | SIP | 656 |
| TCP/1080 | SOCKS Proxy | 199 |
| socks5/1080 | SOCKS5 Proxy | 193 |
| 8333 | Bitcoin | 101 |
| 80 | HTTP | 64 |
| TCP/80 | HTTP | 76 |
| 445 | SMB | 51 |
| 23 | Telnet | 60 |
| 8291 | MikroTik WinBox | 52 |
| 6379 | Redis | 39 |
| 25 | SMTP | 34 |
| postgresql/5432 | PostgreSQL | 32 |

### 3.4. CVEs Exploited

A number of vulnerabilities were targeted during the observation period. The following table lists all unique CVEs and the number of times they were detected.

| CVE Identifier | Attack Count |
| :--- | :--- |
| CVE-2021-44228 | 48 |
| CVE-2021-3449 | 4 |
| CVE-2002-0013, CVE-2002-0012 | 3 |
| CVE-2019-11500 | 3 |
| CVE-2005-4050 | 2 |
| CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255 | 2 |
| CVE-2024-4577 | 2 |
| CVE-2024-4577, CVE-2002-0953 | 2 |
| CVE-2018-2893 | 2 |
| CVE-2018-10562, CVE-2018-10561 | 1 |
| CVE-2013-7471 | 1 |
| CVE-2021-41773 | 1 |
| CVE-2021-42013 | 1 |
| CVE-2021-35394 | 1 |
| CVE-2016-20016 | 1 |


### 3.5. Top Credentials Used

The following credentials were most frequently used in brute-force attacks against SSH, Telnet, and other services. The list is dominated by default and weak username/password combinations.

| Username / Password | Attempt Count |
| :--- | :--- |
| 345gs5662d34 / 345gs5662d34 | 21 |
| root / Passw0rd | 12 |
| root / LeitboGi0ro | 11 |
| root / nPSpP4PBW0 | 7 |
| root / Linux@123 | 7 |
| root / 3245gs5662d34 | 6 |
| test1 / 3245gs5662d34 | 6 |
| test / zhbjETuyMffoL8F | 5 |
| test1 / Password! | 4 |
| root / ankit@123 | 3 |
| User-Agent: Mozilla/5.0... | 3 |
| demo / demo | 3 |
| amit / amit123 | 3 |
| freddy / freddy | 3 |
| antonio / 123 | 3 |
| root / 10293847 | 3 |


### 3.6. Top Commands Executed

After gaining access, attackers executed a series of commands to perform reconnaissance, establish persistence, and download further malware. The most common commands are listed below.

| Command | Execution Count |
| :--- | :--- |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh` | 25 |
| `lockr -ia .ssh` | 25 |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` | 25 |
| `uname -a` | 19 |
| `cat /proc/cpuinfo | grep name | wc -l` | 16 |
| `Enter new UNIX password:` | 12 |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{...}'` | 16 |
| `free -m | grep Mem | awk '{...}'` | 16 |
| `ls -lh $(which ls)` | 16 |
| `which ls` | 16 |
| `crontab -l` | 16 |
| `w` | 16 |
| `uname -m` | 16 |
| `cat /proc/cpuinfo | grep model | grep name | wc -l` | 16 |
| `top` | 16 |
| `uname` | 16 |
| `whoami` | 16 |
| `lscpu | grep Model` | 16 |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'` | 16 |

## 4. Notes and Limitations

*   This report is based on data collected from a network of honeypots. Honeypots are designed to attract and record malicious activity, but the data may not be representative of all attack traffic on the internet.
*   The IP addresses listed as attackers may be compromised systems or open proxies used by the actual attackers.
*   The commands and payloads are recorded as received by the honeypot and may not always represent successful execution.
*   The total number of "dropped" packets across the three log files was **210**, which could indicate network issues or malformed attack traffic.

---
**End of Report**
---
