Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T14:01:43Z
**Timeframe:** 2025-10-08T13:20:01Z to 2025-10-08T14:00:02Z
**Files Used:**
- agg_log_20251008T132001Z.json
- agg_log_20251008T134001Z.json
- agg_log_20251008T140002Z.json

### Executive Summary

This report summarizes 14,260 events captured by the honeypot network. The majority of attacks were detected by the Cowrie and Suricata honeypots. The most prominent attack vector was targeting TCP/445, likely related to SMB exploits, with a significant number of events associated with the DoublePulsar backdoor. A large number of SSH login attempts were also observed.

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 5098
- Suricata: 3327
- Honeytrap: 2186
- Ciscoasa: 1568
- Mailoney: 886
- Dionaea: 729
- Sentrypeer: 205
- H0neytr4p: 98
- Miniprint: 44
- ssh-rsa: 30
- Honeyaml: 20
- ElasticPot: 16
- ConPot: 15
- Dicompot: 12
- Tanner: 12
- Redishoneypot: 9
- Adbhoney: 2
- Heralding: 3

**Top Attacking IPs**
- 201.190.168.218: 1771
- 161.35.44.220: 1343
- 176.65.141.117: 820
- 182.176.149.227: 687
- 139.167.46.226: 664
- 170.64.142.60: 342
- 88.214.50.58: 333
- 52.224.240.74: 187
- 178.27.90.142: 157
- 103.59.200.5: 157
- 41.128.181.199: 184
- 222.108.0.231: 124
- 45.7.119.49: 119
- 177.126.132.91: 119
- 43.134.176.129: 119

**Top Targeted Ports/Protocols**
- TCP/445: 1771
- 25: 888
- 22: 871
- 445: 690
- TCP/5900: 295
- 5060: 205
- 443: 93
- 8333: 121
- 5903: 95
- 5901: 77
- TCP/22: 51
- 5909: 50
- 5908: 49
- 5907: 49
- 9100: 44

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2006-2369: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 15
- lockr -ia .ssh: 15
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 15
- cat /proc/cpuinfo | grep name | wc -l: 11
- Enter new UNIX password: : 11
- Enter new UNIX password::: 11
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 11
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 11
- ls -lh $(which ls): 11
- which ls: 11
- crontab -l: 11
- w: 11
- uname -m: 11
- cat /proc/cpuinfo | grep model | grep name | wc -l: 11
- top: 11
- uname: 11
- uname -a: 11
- whoami: 11
- lscpu | grep Model: 9
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 9
- system: 4
- shell: 4

**Signatures Triggered**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1765
- 2024766: 1765
- ET DROP Dshield Block Listed Source group 1: 364
- 2402000: 364
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 305
- 2400040: 305
- ET SCAN NMAP -sS window 1024: 139
- 2009582: 139
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 166
- 2023753: 166
- ET HUNTING RDP Authentication Bypass Attempt: 83
- 2034857: 83
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN Potential SSH Scan: 43
- 2001219: 43

**Users / Login Attempts**
- root/: 33
- 345gs5662d34/345gs5662d34: 14
- admin/Password@123: 6
- ubuntu/3245gs5662d34: 6
- guest/uploader: 6
- unknown/pass: 6
- root/root666: 6
- ubuntu/asdasd: 4
- user/user!: 4
- support/4444: 4
- centos/centos5: 4
- ubuntu/P@ssw0rd2026: 4
- user/user123456: 4
- vpn/vpnvpn: 6
- test/123: 4
- ubnt/ubnt13: 4
- root/66666666: 4

**Files Uploaded/Downloaded**
- .i;: 4

**HTTP User-Agents**
- N/A

**SSH Clients and Servers**
- N/A

**Top Attacker AS Organizations**
- N/A

### Key Observations and Anomalies
- A significant number of commands are related to reconnaissance and establishing persistence, such as manipulating SSH authorized_keys and gathering system information.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...` was executed multiple times, indicating a clear attempt to maintain access.
- The file `.i;` was downloaded four times, suggesting a potential second-stage payload.
- The high number of events targeting TCP/445 and the associated DoublePulsar signature indicate a likely automated worm or exploit campaign.
