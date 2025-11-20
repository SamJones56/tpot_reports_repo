Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T09:01:32Z
**Timeframe:** 2025-10-06T08:20:01Z - 2025-10-06T09:00:01Z
**Files Used:**
- agg_log_20251006T082001Z.json
- agg_log_20251006T084002Z.json
- agg_log_20251006T090001Z.json

### Executive Summary
This report summarizes honeypot activity over the past hour, based on data from three log files. A total of 23,344 attacks were recorded. The most targeted honeypot was Cowrie, with 7,639 events. The most active attacking IP was 196.25.125.58 with 3,093 events. A variety of CVEs were targeted, with CVE-2021-44228 being the most frequent. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 7639
- Suricata: 3506
- Dionaea: 3201
- Sentrypeer: 2824
- Honeytrap: 2703
- Ciscoasa: 1297
- Mailoney: 852
- Redishoneypot: 141
- Heralding: 127
- ConPot: 67
- Adbhoney: 52
- H0neytr4p: 45
- Tanner: 34
- Honeyaml: 17
- Dicompot: 7
- ssh-rsa: 2
- ElasticPot: 1

**Top Attacking IPs**
- 196.25.125.58: 3093
- 5.39.12.192: 2438
- 182.10.161.232: 1402
- 170.64.232.235: 1461
- 86.54.42.238: 821
- 176.65.141.117: 820
- 196.251.88.103: 800
- 5.167.79.4: 706
- 20.2.136.52: 518
- 45.140.17.52: 323
- 88.210.63.16: 465
- 172.86.95.98: 371
- 99.92.204.98: 357
- 182.18.139.237: 357
- 103.210.21.178: 352
- 40.82.137.99: 262
- 14.103.50.32: 273
- 115.190.12.52: 278
- 14.103.118.190: 169
- 117.247.111.70: 170

**Top Targeted Ports/Protocols**
- 445: 3141
- 5060: 2824
- 22: 1298
- 25: 1665
- TCP/445: 1400
- 6379: 141
- 5902: 97
- 5903: 94
- 8333: 82
- 5038: 114
- vnc/5900: 127
- 443: 58
- 10001: 39
- TCP/22: 32
- 80: 35
- 1025: 23
- TCP/5432: 34
- 8008: 21
- 4145: 22
- 22225: 14

**Most Common CVEs**
- CVE-2021-44228 CVE-2021-44228: 18
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-1999-0517: 3
- CVE-2005-4050: 2
- CVE-2001-0414: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 19
- lockr -ia .ssh: 19
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 19
- cat /proc/cpuinfo | grep name | wc -l: 19
- Enter new UNIX password: : 19
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- ls -lh $(which ls): 19
- which ls: 19
- crontab -l: 19
- w: 19
- uname -m: 19
- cat /proc/cpuinfo | grep model | grep name | wc -l: 19
- top: 19
- uname: 19
- uname -a: 20
- whoami: 19
- lscpu | grep Model: 19
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 19
- uname -s -v -n -r -m: 5

**Signatures Triggered**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1395
- 2024766: 1395
- ET DROP Dshield Block Listed Source group 1: 509
- 2402000: 509
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 411
- 2023753: 411
- ET HUNTING RDP Authentication Bypass Attempt: 198
- 2034857: 198
- ET SCAN NMAP -sS window 1024: 143
- 2009582: 143
- ET INFO VNC Authentication Failure: 124
- 2002920: 124
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 34
- 2010939: 34
- ET SCAN Potential SSH Scan: 22
- 2001219: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 11
- 2403347: 11
- ET INFO CURL User Agent: 10
- 2002824: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 9
- 2403343: 9
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 14
- 2400027: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 68: 9
- 2403367: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 9
- 2403349: 9
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 9
- 2400031: 9

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 18
- guest/guest: 5
- bridget/bridget123: 3
- include/include@123: 3
- tty/tty123: 3
- anne/anne123: 3
- ruben/ruben123: 3
- ruben/3245gs5662d34: 3
- cad/cad@123: 3
- imbroglio/imbroglio123: 3
- rosemary/rosemary@123: 3
- nginx/nginx123: 4
- user/111111: 3
- oracle/oracle: 3
- app/app123: 3
- root/P@ssw0rd: 3
- fourier/fourier123: 3
- tom/tom: 3
- user1/user1: 3
- elastic/elastic: 3

**Files Uploaded/Downloaded**
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- 11: 1
- fonts.gstatic.com: 1
- css?family=Libre+Franklin...: 1
- ie8.css?ver=1.0: 1
- html5.js?ver=3.7.3: 1
- ?format=json: 2

**HTTP User-Agents**
- No data recorded.

**SSH Clients**
- No data recorded.

**SSH Servers**
- No data recorded.

**Top Attacker AS Organizations**
- No data recorded.

### Key Observations and Anomalies
- A significant number of commands are related to establishing an SSH backdoor, indicating a targeted effort to gain persistent access.
- The high number of "DoublePulsar Backdoor" signatures suggests that many attacking IPs are likely compromised systems from previous campaigns.
- The presence of commands to download and execute shell scripts (e.g., w.sh, c.sh, wget.sh) from specific IPs (89.144.20.51, 180.93.42.18) indicates active malware campaigns.
- There is a noticeable lack of data for HTTP User-Agents, SSH clients/servers, and AS organizations, which might be a limitation of the current honeypot configuration or logging level.
