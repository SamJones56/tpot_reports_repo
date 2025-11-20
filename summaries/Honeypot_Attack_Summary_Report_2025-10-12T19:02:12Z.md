Here is the Honeypot Attack Summary Report.

### **Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-12T19:01:38Z
**Timeframe of Report:** 2025-10-12T18:20:02Z to 2025-10-12T19:00:01Z
**Files Used to Generate Report:**
- agg_log_20251012T182002Z.json
- agg_log_20251012T184001Z.json
- agg_log_20251012T190001Z.json

### **Executive Summary**

During the monitored period, a total of 25,416 attacks were recorded across the honeypot network. The most targeted services were SMB (port 445) and SIP (port 5060). The majority of attacks originated from the IP address 202.88.244.34. A significant number of attacks involved attempts to gain SSH access and execute remote commands, including downloading and executing malicious binaries. Several CVEs were targeted, with a focus on older vulnerabilities.

### **Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 8081
- Dionaea: 8069
- Honeytrap: 3221
- Sentrypeer: 1908
- Ciscoasa: 1804
- Suricata: 1440
- Tanner: 620
- Mailoney: 114
- Redishoneypot: 44
- ElasticPot: 30
- ConPot: 22
- H0neytr4p: 18
- Adbhoney: 15
- Honeyaml: 8
- Heralding: 6
- Dicompot: 4
- Ipphoney: 2

**Top Attacking IPs:**
- 202.88.244.34: 7861
- 157.245.101.239: 1244
- 45.128.199.212: 1072
- 5.167.79.4: 1027
- 79.137.74.38: 391
- 193.32.235.22: 331
- 172.86.95.98: 340
- 62.141.43.183: 324
- 198.98.56.205: 222
- 111.238.174.6: 238
- 14.22.89.30: 139
- 103.189.234.9: 120
- 147.78.100.99: 145
- 192.227.128.4: 208
- 2.50.100.172: 173

**Top Targeted Ports/Protocols:**
- 445: 7927
- 5060: 1908
- 22: 1275
- 80: 622
- 5903: 191
- 1388: 117
- 25: 114
- 5908: 84
- 5901: 78
- 5909: 82
- 3306: 72
- 8333: 76
- 6379: 41
- 81: 36
- 23: 47

**Most Common CVEs:**
- CVE-2002-0013, CVE-2002-0012
- CVE-1999-0517
- CVE-2006-0189
- CVE-2022-27255
- CVE-2019-11500
- CVE-2021-3449
- CVE-2023-1389
- CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255
- CVE-2016-6563
- CVE-2023-26801
- CVE-2006-2369

**Commands Attempted by Attackers:**
- Basic reconnaissance commands (e.g., `uname -a`, `whoami`, `lscpu`, `w`).
- System information gathering (e.g., `cat /proc/cpuinfo`, `free -m`).
- Attempts to modify SSH authorized_keys to add a new key.
- Commands to download and execute malicious files (e.g., using `wget` and `curl`).
- File system manipulation (e.g., `rm -rf .ssh`, `mkdir .ssh`).
- Password change prompts (`Enter new UNIX password:`).

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET WEB_SERVER PHP tags in HTTP POST
- ET SCAN Potential SSH Scan
- GPL SNMP request udp

**Users / Login Attempts (user/password):**
- cron/
- 345gs5662d34/345gs5662d34
- holu/holu
- update/update
- admin/admin2001
- vpn/vpnpass
- deploy/123123
- ftpuser/ftppassword
- mega/123
- admin1234/admin1234
- root/ and various common passwords.

**Files Uploaded/Downloaded:**
- `bins.sh`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `Mozi.m`
- `welcome.jpg`, `writing.jpg`, `tags.jpg`

**HTTP User-Agents:**
- No significant user-agents were logged.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No AS organization data was available in the logs.

### **Key Observations and Anomalies**

- **High Volume of SMB Traffic:** The high number of probes on port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
- **Persistent SSH Attacks:** The `Cowrie` honeypot captured numerous brute-force attempts and subsequent command execution, indicating a focus on compromising systems via SSH.
- **Botnet Activity:** The downloaded filenames (e.g., `urbotnetisass`, `Mozi.m`) are associated with known botnets, suggesting attempts to recruit the honeypot into a larger network of compromised devices.
- **Reconnaissance Commands:** The frequent use of commands like `uname`, `lscpu`, and `cat /proc/cpuinfo` is a common tactic for attackers to profile a system before deploying a specific payload.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.
