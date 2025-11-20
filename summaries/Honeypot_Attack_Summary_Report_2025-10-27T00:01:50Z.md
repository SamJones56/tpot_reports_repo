Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T00:01:30Z
**Timeframe:** 2025-10-26T23:20:01Z to 2025-10-27T00:00:01Z
**Files Used:**
- agg_log_20251026T232001Z.json
- agg_log_20251026T234001Z.json
- agg_log_20251027T000001Z.json

**Executive Summary**

This report summarizes 10,700 attacks recorded across the honeypot infrastructure. The most targeted services were SIP (Sentrypeer) and SSH (Cowrie). A significant portion of the attacks originated from a small number of IP addresses, with 198.23.190.58 being the most persistent attacker. The majority of attacks were automated scans and brute-force attempts. Several CVEs were targeted, with CVE-2005-4050 being the most frequent. Attackers attempted to gain persistent access by adding their SSH keys to the authorized_keys file.

**Detailed Analysis**

**Attacks by Honeypot**
- Sentrypeer: 2826
- Cowrie: 2654
- Ciscoasa: 1847
- Honeytrap: 1614
- Suricata: 1550
- Mailoney: 83
- Dionaea: 33
- ssh-rsa: 30
- Tanner: 20
- H0neytr4p: 13
- Adbhoney: 13
- ConPot: 6
- Ipphoney: 4
- Dicompot: 3
- ElasticPot: 2
- Honeyaml: 2

**Top Attacking IPs**
- 198.23.190.58: 1586
- 144.172.108.231: 823
- 167.172.36.39: 708
- 185.243.5.148: 445
- 121.142.87.218: 311
- 185.243.5.158: 305
- 193.24.211.28: 128
- 200.6.48.51: 187
- 220.205.122.62: 118
- 115.190.11.142: 105
- 197.5.145.73: 169
- 107.170.36.5: 156
- 68.183.149.135: 114
- 167.250.224.25: 100

**Top Targeted Ports/Protocols**
- 5060: 2826
- UDP/5060: 410
- 22: 432
- TCP/22: 75
- 5905: 78
- 5904: 78
- 25: 83
- 8000: 62

**Most Common CVEs**
- CVE-2005-4050: 401
- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2013-2135: 5
- CVE-2018-11776: 5
- CVE-2023-22527 CVE-2023-22527: 3
- CVE-2021-35394 CVE-2021-35394: 1

**Commands Attempted by Attackers**
- Commands to add SSH key to authorized_keys: 9
- System information gathering (uname, lscpu, etc.): 9 each
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 9
- `lockr -ia .ssh`: 9
- `crontab -l`: 9
- `w`: 9
- `top`: 9
- `Enter new UNIX password: `: 6

**Signatures Triggered**
- ET VOIP MultiTech SIP UDP Overflow: 401
- ET DROP Dshield Block Listed Source group 1: 242
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 170
- ET SCAN NMAP -sS window 1024: 135
- ET HUNTING RDP Authentication Bypass Attempt: 58
- ET INFO Reserved Internal IP Traffic: 48
- ET SCAN Potential SSH Scan: 31

**Users / Login Attempts**
- root/: 33
- 345gs5662d34/345gs5662d34: 8
- root/HMnyjH22: 3
- root/hohuxi55: 3
- root/hojalateria10: 3
- root/hmon8t5q: 3
- root/Hitit1: 3
- root/tamere: 2
- admin/08041977: 2
- admin/08031984: 2
- admin/08031973: 2

**Files Uploaded/Downloaded**
- rondo.whm.sh|sh: 9
- wget.sh;: 4
- loader.sh|sh;#: 1
- w.sh;: 1
- c.sh;: 1

**HTTP User-Agents**
- No HTTP user-agents were recorded in this period.

**SSH Clients**
- No SSH clients were recorded in this period.

**SSH Servers**
- No SSH servers were recorded in this period.

**Top Attacker AS Organizations**
- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- The most notable activity is the repeated attempt by attackers to add their SSH public key to the `authorized_keys` file. This indicates a clear intent to establish persistent access to the compromised machine.
- The high number of SIP-related attacks (targeting port 5060) suggests widespread scanning for vulnerabilities in VoIP systems.
- The commands executed after successful logins are primarily for reconnaissance, gathering information about the system's hardware and configuration.
- There is a significant amount of scanning for RDP and MSSQL services on non-standard ports.
- The attackers are using a variety of generic and default credentials, indicating automated brute-force attacks.
- Some attackers attempted to download and execute shell scripts, likely to install malware or set up a backdoor.
- The presence of `ssh-rsa` as a honeypot type is anomalous and likely a parsing error in the logging pipeline.
