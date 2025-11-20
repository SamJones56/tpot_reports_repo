### **Honeypot Attack Summary Report**

**Report Generation Time:** 2025-09-30T12:01:28Z
**Timeframe of Report:** 2025-09-30T11:20:01Z to 2025-09-30T12:00:01Z
**Files Used to Generate Report:**
- agg_log_20250930T112001Z.json
- agg_log_20250930T114001Z.json
- agg_log_20250930T120001Z.json

---

### **Executive Summary**

This report summarizes 11,171 recorded attacks across various honeypots. The majority of these attacks were captured by the Cowrie honeypot. The most frequent attacks originated from IP addresses 209.38.21.236 and 147.182.204.39. A significant number of attacks targeted port 22 (SSH). Attackers attempted various commands, primarily focused on reconnaissance and establishing further access, such as manipulating SSH keys and downloading malicious files. Several CVEs were also detected, including CVE-2002-0013, CVE-2002-0012, CVE-1999-0517, CVE-2021-35394, CVE-2021-3449, and CVE-2019-11500.

---

### **Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 6177
- Honeytrap: 2252
- Ciscoasa: 1424
- Suricata: 1077
- Tanner: 53
- Sentrypeer: 51
- Redishoneypot: 27
- ConPot: 26
- H0neytr4p: 24
- Adbhoney: 12
- Dionaea: 10
- Mailoney: 10
- Miniprint: 10
- ElasticPot: 5
- Ipphoney: 4
- Heralding: 3
- Dicompot: 3
- Honeyaml: 3

**Top Attacking IPs:**
- 209.38.21.236
- 147.182.204.39
- 185.156.73.166
- 185.156.73.167
- 92.63.197.55
- 92.63.197.59
- 177.12.2.75
- 20.174.162.182
- 190.202.130.61
- 91.231.219.109
- 196.251.84.181
- 103.103.245.61
- 107.175.70.80
- 49.231.192.36

**Top Targeted Ports/Protocols:**
- 22
- 8333
- 6001
- 23
- 80
- 5060
- 5984
- 6379

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-35394
- CVE-2021-3449
- CVE-2019-11500

**Commands Attempted by Attackers:**
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `whoami`
- `lscpu | grep Model`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET SCAN Potential SSH Scan
- ET INFO CURL User Agent

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- superadmin/admin123
- root/2glehe5t24th1issZs
- test/zhbjETuyMffoL8F
- root/nPSpP4PBW0

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- boatnet.mpsl

**HTTP User-Agents:**
- (No data in logs)

**SSH Clients and Servers:**
- (No data in logs)

**Top Attacker AS Organizations:**
- (No data in logs)

---

### **Key Observations and Anomalies**

- A recurring attack pattern involves attempts to modify the `.ssh/authorized_keys` file to grant the attacker persistent access.
- Several commands indicate attempts to download and execute payloads from the IP `94.154.35.154`, suggesting a coordinated campaign to install malware (`urbotnetisass`).
- The attackers are using a variety of generic and default credentials in brute-force attempts.
- A long command was observed attempting to run an `sshd` executable with a large number of IP addresses as arguments, which could be an attempt to launch a DDoS attack or a scan from the compromised machine.
- The majority of attacks are automated, as evidenced by the repetitive nature of the commands and login attempts across different IPs.
