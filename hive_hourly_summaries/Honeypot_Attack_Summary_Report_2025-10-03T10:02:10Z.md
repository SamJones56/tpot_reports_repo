Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T10:01:48Z
**Timeframe of Analysis:** 2025-10-03T09:20:01Z to 2025-10-03T10:00:02Z
**Log Files Used:**
- agg_log_20251003T092001Z.json
- agg_log_20251003T094001Z.json
- agg_log_20251003T100002Z.json

---

### Executive Summary

This report summarizes 16,597 events recorded across the honeypot network. The majority of malicious activities were captured by the Cowrie (SSH/Telnet), Suricata (IDS/IPS), and Ciscoasa honeypots. A significant portion of the attacks originated from IP address 176.65.141.117. The most targeted services were SMTP (Port 25), SIP (Port 5060), and SSH (Port 22). Analysis of IDS signatures revealed a high number of scans and exploit attempts, particularly related to the DoublePulsar backdoor over SMB. Attackers commonly attempted to download and execute shell scripts and ELF binaries after gaining access.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6,403
- **Suricata:** 3,218
- **Ciscoasa:** 2,603
- **Mailoney:** 1,616
- **Sentrypeer:** 1,261
- **Dionaea:** 936
- **Honeytrap:** 229
- **Adbhoney:** 115
- **H0neytr4p:** 65
- **Redishoneypot:** 60
- **ConPot:** 48
- **Tanner:** 27
- **Others (Dicompot, Honeyaml, Miniprint, ElasticPot, Ipphoney, Wordpot):** 16

**Top Attacking IPs:**
- 176.65.141.117
- 49.48.129.187
- 196.251.88.103
- 23.94.26.58
- 78.30.0.26
- 2.59.62.188
- 23.175.48.211
- 185.156.73.166
- 185.245.83.140
- 92.63.197.55
- 120.48.25.89
- 92.63.197.59
- 103.59.95.42
- 80.119.245.162

**Top Targeted Ports/Protocols:**
- 25 (SMTP)
- 5060 (SIP)
- TCP/445 (SMB)
- 22 (SSH)
- 445 (SMB)
- 3306 (MySQL)
- 6379 (Redis)
- 443 (HTTPS)
- 80 (HTTP)

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `wget http://...`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN Sipsak SIP scan
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET INFO curl User-Agent Outbound

**Users / Login Attempts (Username/Password):**
- john/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- root/LeitboGi0ro
- foundry/foundry
- superadmin/admin123

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- nwfaiehg4ewijfgriehgirehaughrarg.mips
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- None observed in the provided logs.

**SSH Clients and Servers:**
- **Clients:** None observed in the provided logs.
- **Servers:** None observed in the provided logs.

**Top Attacker AS Organizations:**
- None observed in the provided logs.

---

### Key Observations and Anomalies

1.  **High-Volume SMB Exploitation:** A significant number of alerts were triggered by the `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` signature, indicating widespread, automated attempts to exploit the vulnerability addressed by MS17-010.
2.  **Credential Stuffing and Brute-Forcing:** The Cowrie honeypot logged numerous login attempts with common and default credentials (e.g., `john`, `root`, `superadmin`), highlighting continued brute-force tactics against SSH and Telnet.
3.  **Post-Exploitation Script Execution:** Attackers frequently attempted to download and execute shell scripts (`wget.sh`, `w.sh`) and various ELF binaries for different architectures (`arm`, `mips`, `x86`), demonstrating intent to establish persistence and control.
4.  **System Reconnaissance:** Upon gaining shell access, attackers consistently ran commands (`uname -a`, `cat /proc/cpuinfo`, `free -m`) to identify the system's architecture and resources, likely to deploy the appropriate malware payload.
5.  **SIP Scanning:** The Sentrypeer honeypot and Suricata signatures both indicate a high volume of scanning activity on port 5060, targeting SIP services for potential exploitation or abuse.

This concludes the Honeypot Attack Summary Report.
