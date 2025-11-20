Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T10:01:37Z
**Timeframe:** Approximately 2025-10-22T09:20:01Z to 2025-10-22T10:00:01Z
**Log Files:**
- agg_log_20251022T092001Z.json
- agg_log_20251022T094001Z.json
- agg_log_20251022T100001Z.json

### Executive Summary
This report summarizes 22,110 events captured by the honeypot network over the last hour. The majority of attacks were registered on the Cowrie honeypot. The most prominent attacking IP address was 111.175.37.46. The most targeted port was 445/TCP, primarily associated with SMB services, with a significant number of attacks also targeting port 22 (SSH). A variety of CVEs were detected, indicating attempts to exploit known vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8213
- Honeytrap: 4251
- Suricata: 3897
- Dionaea: 3201
- Ciscoasa: 1767
- Sentrypeer: 351
- Tanner: 162
- Heralding: 54
- Mailoney: 93
- H0neytr4p: 52
- Redishoneypot: 37
- Adbhoney: 17
- ConPot: 10
- ElasticPot: 3
- Wordpot: 1
- Honeyaml: 1

**Top 10 Attacking IPs:**
- 111.175.37.46: 5535
- 102.41.209.27: 2273
- 77.73.90.195: 1353
- 8.219.210.54: 1244
- 88.214.50.58: 381
- 124.226.219.166: 342
- 88.210.63.16: 301
- 165.22.196.164: 235
- 107.170.36.5: 252
- 196.251.72.53: 123

**Top 10 Targeted Ports/Protocols:**
- 445: 2295
- 22: 1577
- TCP/445: 1349
- 5060: 351
- 5903: 229
- TCP/21: 232
- 80: 150
- 5901: 118
- 8333: 104
- 21: 114

**Most Common CVEs:**
- CVE-1999-0517
- CVE-2002-0012
- CVE-2002-0013
- CVE-2002-0953
- CVE-2002-1149
- CVE-2005-4050
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-41773
- CVE-2021-42013
- CVE-2024-4577

**Top 10 Commands Attempted by Attackers:**
- `uname -a`: 4
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 3
- `lockr -ia .ssh`: 3
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo ...`: 3
- `cat /proc/cpuinfo | grep name | wc -l`: 3
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 3
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 3
- `ls -lh $(which ls)`: 3
- `which ls`: 3
- `crontab -l`: 3

**Top 5 Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1347
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 572
- ET DROP Dshield Block Listed Source group 1: 436
- ET HUNTING RDP Authentication Bypass Attempt: 262
- ET SCAN NMAP -sS window 1024: 180

**Top 10 Users / Login Attempts:**
- root/bistro1724: 4
- root/bkletmein321: 4
- root/bkt2004: 4
- root/BitByteIQQI12: 4
- root/adminHW: 3
- admin/admin123: 3
- root/Bitvki-2008long.admin: 3
- jenkins/112233: 2
- root/john: 2
- server/aa123456: 2

**Files Uploaded/Downloaded:**
- sh: 98
- 11: 32
- fonts.gstatic.com: 32
- css?family=Libre+Franklin...: 32
- ie8.css?ver=1.0: 32
- html5.js?ver=3.7.3: 32
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- ?format=json: 2

**HTTP User-Agents:**
- No user agents were logged during this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged during this period.

**Top Attacker AS Organizations:**
- No AS organizations were logged during this period.

### Key Observations and Anomalies
- A high volume of attacks on port 445 (SMB) were associated with the DoublePulsar backdoor signature, indicating attempts to exploit vulnerabilities related to the EternalBlue family of exploits.
- The IP address 111.175.37.46 was consistently the most active attacker across all three time periods, suggesting a persistent threat source.
- Attackers frequently attempted to modify SSH authorized_keys files to gain persistent access. The repeated use of the same SSH key by different attackers is noteworthy.
- A wide range of generic usernames and passwords were used in brute-force attempts, with a focus on 'root' and 'admin' accounts.
- Several commands were executed to gather system information, such as `uname`, `lscpu`, and `free`, which are typical reconnaissance techniques.
