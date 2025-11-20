Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T10:01:51Z
**Timeframe:** 2025-10-23T09:20:01Z to 2025-10-23T10:00:01Z
**Files Used:**
- agg_log_20251023T092001Z.json
- agg_log_20251023T094001Z.json
- agg_log_20251023T100001Z.json

---

### Executive Summary

This report summarizes 24,483 events recorded across multiple honeypots. The most targeted services were SSH (Cowrie) and various TCP ports (Honeytrap). A significant portion of the attacks originated from the IP address 109.205.211.9. The most frequently targeted port was 445 (SMB), indicating widespread scanning for Microsoft Windows vulnerabilities. Attackers primarily focused on brute-force login attempts and executing shell commands to establish persistent access by modifying SSH keys. Multiple network signatures were triggered, with scans for MS Terminal Server being the most common.

---

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7,372
- Honeytrap: 7,314
- Suricata: 3,841
- Dionaea: 3,189
- Ciscoasa: 1,748
- Sentrypeer: 936
- Mailoney: 21
- H0neytr4p: 13
- Redishoneypot: 10
- Tanner: 15
- ConPot: 6
- Heralding: 6
- Adbhoney: 4
- Honeyaml: 3
- ssh-rsa: 2
- ElasticPot: 1
- Wordpot: 1
- Ipphoney: 1

**Top Attacking IPs:**
- 109.205.211.9: 2,256
- 180.246.121.46: 1,435
- 202.58.206.36: 1,252
- 196.251.88.103: 1,008
- 196.188.120.232: 319
- 107.170.36.5: 250
- 178.128.245.118: 390
- 40.115.18.231: 168
- 103.145.145.80: 222
- 156.229.21.151: 159
- 107.155.50.50: 158
- 185.243.5.146: 158

**Top Targeted Ports/Protocols:**
- 445: 3,129
- 22: 1,268
- 5060: 936
- 1203: 91
- 1208: 90
- 1213: 90
- 1155: 90
- 1091: 90
- 1217: 90
- 1183: 90
- 1206: 90
- 1220: 89
- 1188: 88
- 1193: 88
- 1211: 88
- 1205: 88

**Most Common CVEs:**
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-1999-0183: 2
- CVE-2001-0414: 2
- CVE-2006-2369: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2025-34036 CVE-2025-34036: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 34
- `lockr -ia .ssh`: 34
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 33
- `uname -a`: 19
- `Enter new UNIX password: `: 14
- `Enter new UNIX password:`: 14
- `cat /proc/cpuinfo | grep name | wc -l`: 17
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 16
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 15
- `ls -lh $(which ls)`: 17
- `which ls`: 17
- `crontab -l`: 17
- `w`: 17
- `uname -m`: 17
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 17
- `top`: 17
- `whoami`: 17
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 17

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 1,648
- ET HUNTING RDP Authentication Bypass Attempt / 2034857: 797
- ET DROP Dshield Block Listed Source group 1 / 2402000: 450
- ET SCAN NMAP -sS window 1024 / 2009582: 172
- ET INFO Reserved Internal IP Traffic / 2002752: 58
- ET SCAN Potential SSH Scan / 2001219: 52
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake / 2010908: 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 12

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 29
- root/Chang3M3Pl3as3: 4
- root/changemepassword123: 4
- root/Chapel5647: 4
- root/123asdASD: 4
- root/CheriyaSukham1: 4
- root/chinagrandauto: 4
- root/Chava7574: 4
- root/Q1W2E3R4: 3
- bots/bots123: 3
- root/1qw2!QW@: 3
- burnie/burnie: 3
- user/Qq123456: 3
- root/sa@123456: 3
- root/Admin_2025: 3
- ubuntu1/ubuntu1: 3
- root/chc67freepw!: 3

**Files Uploaded/Downloaded:**
- SOAP-ENV:Envelope>: 3
- ?format=json: 2
- ohsitsvegawellrip.sh: 1
- string.js: 1

**HTTP User-Agents:**
- No user-agent data was observed in this period.

**SSH Clients and Servers:**
- No specific SSH client or server version data was observed in this period.

**Top Attacker AS Organizations:**
- No attacker AS organization data was observed in this period.

---

### Key Observations and Anomalies

1.  **High-Volume Automated Attacks:** The volume of traffic, particularly towards SSH (Cowrie) and SMB (Dionaea), suggests widespread, automated scanning and brute-force campaigns.
2.  **SSH Key Manipulation:** A common tactic observed was the attempt to remove existing SSH configurations and install a new public key (`authorized_keys`). This indicates a clear objective to gain persistent, passwordless access to compromised systems.
3.  **Targeted Scans:** A significant number of security signatures were triggered for scans related to Microsoft Remote Desktop Protocol (RDP) and MS Terminal Services, even on non-standard ports. This highlights a continued focus by attackers on exploiting remote access services.
4.  **Credential Stuffing:** The variety of usernames and passwords reflects a credential stuffing strategy, using common or previously breached credentials to gain access. The user 'root' and password '345gs5662d34' were the most frequently attempted.
5.  **Uncommon CVE:** The log for `20251023T100001Z.json` included a reference to `CVE-2025-34036`. This is an unusual finding, as the CVE is for a future year and likely indicates a test, a misconfiguration in a scanner, or a researcher probing for specific responses.
