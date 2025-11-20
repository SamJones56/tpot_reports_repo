Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T20:01:38Z
**Timeframe Covered:** 2025-10-04T19:20:01Z to 2025-10-04T20:00:02Z
**Log Files Used:**
- agg_log_20251004T192001Z.json
- agg_log_20251004T194001Z.json
- agg_log_20251004T200002Z.json

### Executive Summary
This report summarizes 15,367 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH-based threats. Attackers primarily focused on brute-force login attempts and, upon successful compromise, executed a series of reconnaissance commands to identify system architecture. A significant number of attackers also attempted to add their SSH public keys to the `authorized_keys` file to establish persistence. Network traffic analysis revealed scanning for vulnerabilities related to SMB and mail services. Several CVEs, including older vulnerabilities, were targeted.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 9205
- **Dionaea:** 1618
- **Mailoney:** 1698
- **Ciscoasa:** 1486
- **Suricata:** 912
- **Honeytrap:** 180
- **Sentrypeer:** 80
- **H0neytr4p:** 65
- **Adbhoney:** 59
- **Tanner:** 28
- **Honeyaml:** 15
- **ConPot:** 11
- **Redishoneypot:** 6
- **ElasticPot:** 3
- **Ipphoney:** 1

**Top Attacking IPs:**
- 103.140.127.215: 1244
- 196.189.29.3: 1194
- 161.132.37.66: 1083
- 176.65.141.117: 820
- 86.54.42.238: 821
- 15.235.131.242: 355
- 91.228.186.78: 336
- 51.68.226.87: 334
- 154.91.170.39: 266
- 34.123.134.194: 268

**Top Targeted Ports/Protocols:**
- 445: 1599
- 25: 1698
- 22: 1297
- 5060: 80
- TCP/22: 47
- 443: 65
- 23: 54
- TCP/80: 36
- 80: 32

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2021-35394
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050
- CVE-1999-0517

**Commands Attempted by Attackers:**
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 45
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 45
- `ls -lh $(which ls)`: 45
- `which ls`: 45
- `crontab -l`: 45
- `uname -m`: 45
- `uname -a`: 45
- `whoami`: 45
- `lscpu | grep Model`: 45
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 45
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 45
- `lockr -ia .ssh`: 45
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys`: 45
- `Enter new UNIX password:`: 36

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 263
- 2402000: 263
- ET SCAN NMAP -sS window 1024: 109
- 2009582: 109
- ET INFO Reserved Internal IP Traffic: 47
- 2002752: 47
- ET SCAN Potential SSH Scan: 37
- 2001219: 37
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 16
- 2403344: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 18
- 2403348: 18
- ET INFO curl User-Agent Outbound: 12
- 2013028: 12
- ET HUNTING curl User-Agent to Dotted Quad: 12
- 2034567: 12

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 44
- novinhost/novinhost.org: 17
- root/nPSpP4PBW0: 18
- root/LeitboGi0ro: 18
- test/zhbjETuyMffoL8F: 18
- root/2glehe5t24th1issZs: 14
- test/3245gs5662d34: 10
- root/3245gs5662d34: 7

**Files Uploaded/Downloaded:**
- wget.sh;: 16
- w.sh;: 4
- c.sh;: 4
- boatnet.mpsl;: 1

**HTTP User-Agents:**
- No HTTP User-Agents were observed in the logs.

**SSH Clients and Servers:**
- No specific SSH client or server versions were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organization data was available in the logs.

### Key Observations and Anomalies
- **Automated Script Execution:** A recurring pattern involves attackers attempting to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from external servers. This indicates automated attacks aimed at deploying malware or adding the server to a botnet.
- **Persistence via SSH Keys:** The most common post-exploitation command involves removing the existing `.ssh` directory and adding a hardcoded RSA public key. This is a clear attempt to maintain persistent access to the compromised system.
- **System Reconnaissance:** Attackers consistently run a suite of commands (`uname`, `lscpu`, `free`, `df`) to gather information about the system's hardware and operating system. This information is likely used to tailor further attacks or payloads.
- **Credential Stuffing:** The variety of usernames and passwords suggests widespread credential stuffing campaigns, targeting common default credentials for services like SSH, databases, and IoT devices.
