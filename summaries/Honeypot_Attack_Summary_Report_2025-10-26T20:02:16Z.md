Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T20:01:30Z
**Timeframe:** 2025-10-26T19:20:01Z to 2025-10-26T20:00:01Z
**Files Used:**
- agg_log_20251026T192001Z.json
- agg_log_20251026T194001Z.json
- agg_log_20251026T200001Z.json

### Executive Summary
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 29,904 attacks were recorded. The most targeted honeypot was Cowrie, a medium interaction SSH and Telnet honeypot. The top attacking IP address was 172.188.91.73, responsible for a significant portion of the attacks. The most targeted port was 22 (SSH), followed by 445 (SMB) and 5060 (SIP). Several CVEs were observed, with the most frequent being related to older vulnerabilities. A variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing control.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 19341
- Dionaea: 2308
- Honeytrap: 2980
- Sentrypeer: 1664
- Ciscoasa: 1717
- Suricata: 1563
- Mailoney: 123
- H0neytr4p: 67
- Adbhoney: 35
- Tanner: 52
- Redishoneypot: 34
- ElasticPot: 7
- Honeyaml: 7
- ConPot: 3
- Dicompot: 3

**Top Attacking IPs:**
- 172.188.91.73: 12815
- 103.245.18.122: 2203
- 144.172.108.231: 1066
- 34.47.232.78: 590
- 95.24.31.174: 318
- 165.232.91.82: 440
- 185.243.5.158: 367
- 78.187.21.105: 263
- 185.213.165.135: 258
- 14.225.253.26: 331
- 203.150.162.250: 405
- 119.28.113.215: 280
- 107.170.36.5: 246
- 138.124.158.147: 169
- 61.228.79.221: 232
- 118.193.38.97: 225
- 104.223.122.114: 207
- 172.173.103.90: 184
- 61.12.84.15: 207
- 103.187.165.26: 229

**Top Targeted Ports/Protocols:**
- 22: 3510
- 445: 2259
- 5060: 1664
- 8333: 147
- 5903: 129
- 5901: 118
- 25: 123
- TCP/445: 47
- TCP/22: 77
- TCP/80: 34
- 443: 78
- 80: 53
- 23: 187
- 5904: 76
- 5905: 77
- 6379: 22
- 5907: 51
- 5908: 48
- 5909: 47
- 27017: 27
- 27019: 34

**Most Common CVEs:**
- CVE-2019-11500
- CVE-1999-0183
- CVE-2001-0414
- CVE-2021-35394
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 51
- lockr -ia .ssh: 51
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 51
- cat /proc/cpuinfo | grep name | wc -l: 21
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 21
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 21
- ls -lh $(which ls): 21
- which ls: 21
- crontab -l: 21
- w: 21
- uname -m: 21
- cat /proc/cpuinfo | grep model | grep name | wc -l: 21
- top: 21
- uname: 21
- uname -a: 21
- whoami: 21
- lscpu | grep Model: 21
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 21
- Enter new UNIX password: : 17
- Enter new UNIX password: 17

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 357
- ET SCAN NMAP -sS window 1024: 164
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 142
- ET INFO Reserved Internal IP Traffic: 57
- ET HUNTING RDP Authentication Bypass Attempt: 49
- ET SCAN Potential SSH Scan: 37
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 52: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 10
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 12
- GPL INFO SOCKS Proxy attempt: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 9
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 13
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 12

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 51
- root/3245gs5662d34: 13
- jla/xurros22$: 13
- ubuntu/tizi@123: 15
- serafin/3245gs5662d34: 5
- bash/Drag1823hcacatcuciocolataABC111: 13
- root/asdf1234!: 5
- root/H1v3r2015: 4
- root/A12345!: 4
- root/02041992Ionela%^&: 10
- root/lin123: 4
- serafin/serafin: 4
- root/H3lls1ng2013: 4
- oracle/123.com: 5
- albert/albert123: 5
- hardy/Thiendaovocuc496: 4
- staging/staging: 4
- staging/3245gs5662d34: 4
- root/H4K1N6: 4
- root/H905065009: 4
- systemd/Voidsetdownload.so: 3
- root/Bscs@2024: 3

**Files Uploaded/Downloaded:**
- lol.sh;: 2
- wget.sh;: 12
- arm.uhavenobotsxd;: 2
- arm.uhavenobotsxd: 2
- arm5.uhavenobotsxd;: 2
- arm5.uhavenobotsxd: 2
- arm6.uhavenobotsxd;: 2
- arm6.uhavenobotsxd: 2
- arm7.uhavenobotsxd;: 2
- arm7.uhavenobotsxd: 2
- x86_32.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd: 2
- mips.uhavenobotsxd;: 2
- mips.uhavenobotsxd: 2
- mipsel.uhavenobotsxd;: 2
- mipsel.uhavenobotsxd: 2
- Mozi.a+varcron: 2
- w.sh;: 3
- c.sh;: 3

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- The overwhelming majority of attacks were directed at the Cowrie honeypot, indicating a strong focus on SSH and Telnet services.
- The IP address 172.188.91.73 was responsible for a disproportionately large number of attacks, suggesting a targeted or automated campaign from this source.
- The most common commands attempted by attackers are related to reconnaissance and establishing a foothold on the system, including manipulating SSH authorized keys.
- A number of files were downloaded, many with names suggesting they are malicious payloads for different architectures (e.g., ARM, x86).
- The "ET DROP Dshield Block Listed Source group 1" signature was triggered most frequently, indicating that many of the attacking IPs are on known blocklists.
- The CVEs detected are generally older, suggesting that attackers are scanning for unpatched systems with well-known vulnerabilities.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.
