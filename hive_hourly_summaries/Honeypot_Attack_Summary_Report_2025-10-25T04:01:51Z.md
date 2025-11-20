
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T04:01:19Z
**Timeframe:** 2025-10-25T03:20:02Z to 2025-10-25T04:00:02Z

**Files Used to Generate Report:**
- `agg_log_20251025T032002Z.json`
- `agg_log_20251025T034002Z.json`
- `agg_log_20251025T040002Z.json`

## Executive Summary

This report summarizes a total of 17,293 malicious events recorded over a 40-minute period across a distributed honeypot network. The primary attack vectors observed were SSH brute-force attempts and SMB scanning. A significant portion of the activity originated from the IP address `109.205.211.9`. The most frequently triggered honeypots were Suricata, Honeytrap, and Cowrie, indicating a high volume of network scans and SSH interaction attempts. Attackers were observed attempting to exploit several vulnerabilities, including older web server vulnerabilities, and attempting to install malware on compromised systems.

## Detailed Analysis

### Attacks by Honeypot

- **Suricata:** 4530
- **Honeytrap:** 4462
- **Cowrie:** 3858
- **Dionaea:** 2000
- **Ciscoasa:** 1842
- **Sentrypeer:** 240
- **Mailoney:** 112
- **Tanner:** 101
- **H0neytr4p:** 92
- **ConPot:** 18
- **Honeyaml:** 10
- **Adbhoney:** 8
- **Dicompot:** 7
- **Ipphoney:** 5
- **ElasticPot:** 4
- **Wordpot:** 2
- **ssh-rsa:** 2

### Top Attacking IPs

- **109.205.211.9:** 2759
- **80.94.95.238:** 1570
- **180.232.204.50:** 1128
- **114.37.149.144:** 620
- **152.42.216.249:** 340
- **45.119.84.54:** 338
- **23.180.120.244:** 337
- **156.246.91.141:** 306
- **103.217.144.113:** 295
- **107.170.36.5:** 243

### Top Targeted Ports/Protocols

- **445 (SMB):** 1804
- **22 (SSH):** 509
- **5060 (SIP):** 240
- **8333 (Bitcoin):** 165
- **3306 (MySQL):** 138
- **23 (Telnet):** 128
- **25 (SMTP):** 112
- **443 (HTTPS):** 102
- **80 (HTTP):** 92
- **TCP/80:** 81

### Most Common CVEs

- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2019-11500
- CVE-2016-20016

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem`
- `w`
- `uname -a`
- `whoami`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh`

### Signatures Triggered

- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 2101
- **ET HUNTING RDP Authentication Bypass Attempt:** 728
- **ET DROP Dshield Block Listed Source group 1:** 488
- **ET SCAN NMAP -sS window 1024:** 180
- **ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake:** 105
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 56

### Users / Login Attempts

- **345gs5662d34/345gs5662d34**
- **root/elastix_technet2015**
- **root/Elastix0808**
- **root/3245gs5662d34**
- **root/elastix2013**
- **root/Elastix2014**
- **root/Elastix2015**
- **user/candice**
- **user/booker**
- **user/beamer**

### Files Uploaded/Downloaded

- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `?format=json`

### HTTP User-Agents

- No user agents recorded in this period.

### SSH Clients and Servers

- No specific SSH clients or servers were identified in the logs.

### Top Attacker AS Organizations

- No AS organizations were recorded in this period.

## Key Observations and Anomalies

- **Persistent Attacker:** The IP address `109.205.211.9` was responsible for a significant portion of the attack traffic, indicating a targeted or automated campaign.
- **Post-Exploitation Activity:** The commands executed on the Cowrie honeypot show a clear pattern of post-exploitation behavior, including reconnaissance of the system and attempts to establish persistence by adding an SSH key.
- **Android Malware:** The `Adbhoney` honeypot captured attempts to download and execute files with names like `arm.urbotnetisass`, suggesting a campaign targeting Android devices.
- **SMB Exploitation:** The high volume of traffic on port 445, combined with the "DoublePulsar Backdoor" signature, strongly suggests continued scanning and exploitation attempts related to the EternalBlue vulnerability.
- **Lack of Sophistication:** The majority of the observed attacks appear to be automated and opportunistic, relying on common vulnerabilities and weak credentials.
