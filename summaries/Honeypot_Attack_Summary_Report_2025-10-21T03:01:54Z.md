Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T03:01:16Z
**Timeframe:** 2025-10-21T02:20:01Z to 2025-10-21T03:00:02Z
**Log Files:**
- agg_log_20251021T022001Z.json
- agg_log_20251021T024001Z.json
- agg_log_20251021T030002Z.json

### Executive Summary
This report summarizes 7,778 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and command injections. The most targeted port was port 22 (SSH), and the most active attacking IP was 72.146.232.13. Several CVEs were triggered, and attackers attempted to download and execute malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 4405
- **Honeytrap:** 2164
- **Suricata:** 850
- **Sentrypeer:** 167
- **Mailoney:** 47
- **Adbhoney:** 30
- **Miniprint:** 21
- **Honeyaml:** 18
- **Redishoneypot:** 14
- **Ciscoasa:** 13
- **Tanner:** 13
- **H0neytr4p:** 13
- **Dionaea:** 12
- **ConPot:** 6
- **Dicompot:** 3
- **Ipphoney:** 1
- **ElasticPot:** 1

**Top Attacking IPs:**
- 72.146.232.13
- 188.37.131.134
- 103.134.154.55
- 85.208.253.184
- 120.48.39.73
- 162.240.156.34
- 95.237.254.79
- 83.97.24.41
- 102.88.137.145
- 87.106.35.227

**Top Targeted Ports/Protocols:**
- 22
- 5060
- TCP/1433
- 6001
- 8333
- 5905
- 5904
- 25
- TCP/80

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-1999-0183
- CVE-2024-3721

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO Reserved Internal IP Traffic
- 2002752

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- user01/Password01
- deploy/1234
- weblogic/weblogic
- weblogic/12345
- teamspeak/Password1
- user01/1234567890
- jahan/jahan
- jenkins/Jenkins
- weblogic/3245gs5662d34

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies
- A significant number of commands are related to reconnaissance and establishing persistence, such as gathering system information (`uname`, `lscpu`, `free`) and manipulating SSH keys.
- Attackers attempted to download and execute several shell scripts (`w.sh`, `c.sh`, `wget.sh`) and ELF binaries (`.urbotnetisass`), suggesting attempts to install malware or DDoS bots.
- The high number of login attempts with the username/password combination "345gs5662d34/345gs5662d34" across multiple log files indicates a coordinated brute-force attack.
- The Suricata signatures triggered are consistent with scanning activity (NMAP, MSSQL scans) and traffic from known malicious IP addresses (Dshield, CINS).
