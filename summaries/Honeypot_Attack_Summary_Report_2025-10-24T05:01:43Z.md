Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T05:01:23Z
**Timeframe of Analysis:** 2025-10-24T04:20:01Z to 2025-10-24T05:00:01Z
**Log Files Used:**
- agg_log_20251024T042001Z.json
- agg_log_20251024T044001Z.json
- agg_log_20251024T050001Z.json

---

### **Executive Summary**
This report summarizes 7,876 malicious events captured by the honeypot network over a 40-minute period. The majority of attacks were detected by the Suricata, Honeytrap, and Ciscoasa honeypots. A significant portion of the activity originated from the IP address `84.54.70.63`, primarily targeting TCP port 445 (SMB). Attackers were observed attempting system reconnaissance, password changes, and modification of SSH authorized keys. Several CVEs were targeted, including vulnerabilities in Log4j.

---

### **Detailed Analysis**

**Attacks by Honeypot:**
- Suricata: 2487
- Honeytrap: 2246
- Ciscoasa: 1803
- Cowrie: 936
- Sentrypeer: 117
- Dionaea: 92
- Tanner: 109
- Redishoneypot: 34
- Mailoney: 16
- Adbhoney: 9
- Honeyaml: 8
- ConPot: 7
- ElasticPot: 3
- H0neytr4p: 4
- Heralding: 3
- Dicompot: 2

**Top Attacking IPs:**
- 84.54.70.63: 1603
- 80.94.95.238: 539
- 93.123.109.182: 226
- 24.232.50.5: 278
- 209.15.115.240: 273
- 107.170.36.5: 156
- 168.227.224.196: 110
- 68.183.149.135: 112
- 138.197.138.95: 85
- 129.13.189.202: 62
- 185.243.5.144: 64
- 167.250.224.25: 70

**Top Targeted Ports/Protocols:**
- TCP/445: 1598
- 445: 62
- 2062: 156
- 22: 129
- 80: 105
- 8333: 127
- 5060: 117
- 9093: 57
- 5905: 82
- 5904: 79
- 6379: 34
- 5901: 54

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2021-3449
- CVE-2019-11500
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2001-0414

**Commands Attempted by Attackers:**
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem ...`
- `crontab -l`
- `whoami`
- `lscpu | grep Model`
- `echo -e "123456\\nIBJrsxOjZb9R\\nIBJrsxOjZb9R"|passwd|bash`
- `system`
- `shell`
- `cat /proc/mounts; /bin/busybox BDDTY`
- `tftp; wget; /bin/busybox BDDTY`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET CINS Active Threat Intelligence Poor Reputation IP (various groups)
- ET DROP Spamhaus DROP Listed Traffic Inbound (various groups)
- ET INFO CURL User Agent (2002824)
- ET SCAN Suspicious inbound to PostgreSQL port 5432 (2010939)

**Users / Login Attempts (user/pass):**
- 345gs5662d34/345gs5662d34
- liran/3245gs5662d34
- augusto/augusto123
- root/datatot
- root/dBaL81ug23
- root/Dbhecyzr1
- rocket/rocket123
- mother/fucker
- various other combinations with users `root`, `admin`, `test`, and `user`.

**Files Uploaded/Downloaded:**
- sh: 6 instances

**HTTP User-Agents:**
- None recorded in this period.

**SSH Clients and Servers:**
- SSH Clients: None recorded in this period.
- SSH Servers: None recorded in this period.

**Top Attacker AS Organizations:**
- None recorded in this period.

---

### **Key Observations and Anomalies**
- **High Volume SMB Scans:** The IP address `84.54.70.63` was responsible for over 1,600 events, almost exclusively targeting TCP port 445 and triggering the "DoublePulsar Backdoor" Suricata signature. This indicates a likely automated worm or exploit scanner searching for vulnerable SMB services.
- **Credential Stuffing:** A wide variety of username and password combinations were attempted, suggesting broad, automated credential stuffing attacks against SSH services.
- **SSH Key Manipulation:** Multiple commands focused on deleting the existing `.ssh` directory and adding a new `authorized_keys` file. This is a common technique for attackers to gain persistent access to a compromised machine.
- **System Reconnaissance:** Attackers frequently used commands like `uname`, `whoami`, `lscpu`, and `cat /proc/cpuinfo` to gather information about the system architecture, likely to tailor further attacks or payloads.
- **Payload Download Attempts:** The command sequence `tftp; wget; /bin/busybox BDDTY` indicates an attempt to download a payload from a remote server using multiple common utilities.

This report highlights ongoing automated attacks targeting common vulnerabilities and weak credentials. Continuous monitoring of these indicators is recommended.