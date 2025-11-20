**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-13T01:01:41Z
**Timeframe:** 2025-10-13T00:20:01Z to 2025-10-13T01:00:01Z

**Files Used to Generate Report:**
- agg_log_20251013T002001Z.json
- agg_log_20251013T004001Z.json
- agg_log_20251013T010001Z.json

**Executive Summary**

This report summarizes 18,052 events captured by the honeypot network over a 40-minute period. The most engaged honeypot was Cowrie, accounting for over 33% of the total traffic. A significant volume of attacks originated from IP address 31.40.204.154. The primary attack vectors observed were scanning and brute-force attempts against SIP (5060) and SSH (22) services. Attackers were also observed attempting to add their SSH keys to compromised machines for persistent access and downloading malicious ELF binaries.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 6052
- Honeytrap: 3424
- Sentrypeer: 2346
- Suricata: 2191
- Ciscoasa: 1995
- Mailoney: 1003
- Dionaea: 852
- H0neytr4p: 76
- Tanner: 50
- Redishoneypot: 34
- Honeyaml: 12
- ConPot: 8
- Adbhoney: 5
- ElasticPot: 3
- Wordpot: 1

**Top Attacking IPs:**
- 31.40.204.154: 1258
- 223.123.65.4: 1227
- 86.54.42.238: 821
- 45.128.199.212: 895
- 218.31.7.24: 510
- 196.251.88.103: 418
- 172.86.95.98: 369
- 27.254.152.90: 311
- 103.97.177.230: 324
- 62.141.43.183: 282

**Top Targeted Ports/Protocols:**
- 5060: 2346
- 25: 1005
- 22: 917
- UDP/5060: 635
- TCP/21: 222
- 5903: 168
- 21: 112
- 80: 44
- 3306: 46
- 443: 69

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2006-2369
- CVE-2002-0013 CVE-2002-0012
- CVE-1999-0183
- CVE-2001-0414
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- lockr -ia .ssh
- Basic system enumeration commands (uname, whoami, w, top, lscpu, crontab -l)
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh
- echo -ne '\\x7F\\x45\\x4C\\x46...' >> ./catvycao (Attempt to write an ELF file)
- echo "root:KZ0ABZxoFIgO"|chpasswd|bash

**Signatures Triggered:**
- ET SCAN Sipsak SIP scan
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port

**Users / Login Attempts (user/pass):**
- cron/
- 345gs5662d34/345gs5662d34
- admin/admin11
- nobody/000000
- support/nimda
- 000000/000000
- root/superadmin
- admin/user
- root/3245gs5662d34

**Files Uploaded/Downloaded:**
- ?format=json
- json
- soap-envelope
- wsmanidentity.xsd

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

**Key Observations and Anomalies**

1.  **Persistent Access Attempts:** A recurring command involves deleting the .ssh directory and adding a specific SSH public key to `authorized_keys`. This indicates a clear objective to maintain persistent access to compromised systems.
2.  **SIP Scanning:** A high volume of traffic targeted SIP port 5060, with the "ET SCAN Sipsak SIP scan" signature being the most triggered event. This points to widespread scanning for vulnerable VoIP systems.
3.  **Malware Delivery:** The use of `echo -ne` commands to write a binary file (`catvycao`) piece by piece is a common technique to deliver malware without using tools like `wget` or `curl`, which may be monitored more closely. The file header `\\x7F\\x45\\x4C\\x46` confirms it is an ELF binary.
4.  **Credential Stuffing:** The variety of login attempts suggests widespread credential stuffing campaigns against SSH and other services.
