Honeypot Attack Summary Report

Report generated at: 2025-10-13T11:01:30Z
Timeframe: 2025-10-13T10:20:01Z to 2025-10-13T11:00:01Z
Files used to generate this report:
- agg_log_20251013T102001Z.json
- agg_log_20251013T104001Z.json
- agg_log_20251013T110001Z.json

## Executive Summary
This report summarizes honeypot activity over the last hour, based on data from three log files. A total of 29,985 attacks were recorded. The most targeted honeypot was Cowrie, a medium interaction SSH and Telnet honeypot. The most active attacking IP address was 45.234.176.18, which was observed launching a significant number of attacks. The most common attack vector was over port 22 (SSH). Several CVEs were detected, with CVE-2006-0189 being the most frequent. A large number of commands were attempted by attackers, many of which were aimed at reconnaissance and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 13764
- Honeytrap: 8812
- Suricata: 3883
- Ciscoasa: 1555
- Dionaea: 850
- Sentrypeer: 906
- Tanner: 62
- H0neytr4p: 46
- Mailoney: 35
- ElasticPot: 22
- Redishoneypot: 15
- Honeyaml: 8
- ConPot: 8
- Miniprint: 9
- Dicompot: 5
- Adbhoney: 5

### Top Attacking IPs
- 45.234.176.18: 8546
- 175.184.252.178: 1498
- 138.197.43.50: 1195
- 182.183.34.173: 776
- 134.199.202.8: 753
- 79.133.188.66: 1326
- 103.100.211.174: 332
- 51.178.137.178: 529
- 190.128.241.2: 392
- 165.154.244.165: 293
- 156.238.229.20: 333
- 129.226.95.35: 365
- 179.63.5.23: 197
- 154.205.129.28: 306
- 93.93.118.37: 180
- 206.189.131.118: 288
- 172.86.95.115: 298
- 103.193.178.68: 253
- 62.141.43.183: 180
- 103.157.25.60: 173

### Top Targeted Ports/Protocols
- TCP/445: 2815
- 22: 1844
- 5060: 906
- 445: 791
- 80: 64
- TCP/22: 54
- 443: 46
- TCP/443: 48
- 25: 36
- UDP/5060: 43
- 9200: 21
- 6379: 14
- 23: 13
- 3306: 11
- 5986: 11
- TCP/80: 17
- 6666: 8
- 8093: 8
- 9100: 8

### Most Common CVEs
- CVE-2006-0189: 16
- CVE-2022-27255 CVE-2022-27255: 16
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2005-4050: 1
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2013-7471 CVE-2013-7471: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 106
- lockr -ia .ssh: 106
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 105
- cat /proc/cpuinfo | grep name | wc -l: 76
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 76
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 76
- ls -lh $(which ls): 74
- which ls: 74
- crontab -l: 73
- uname -m: 73
- w: 72
- whoami: 73
- top: 73
- uname: 73
- uname -a: 74
- lscpu | grep Model: 73
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 73
- Enter new UNIX password: : 67
- Enter new UNIX password:: 67

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2811
- 2024766: 2811
- ET DROP Dshield Block Listed Source group 1: 285
- 2402000: 285
- ET SCAN NMAP -sS window 1024: 180
- 2009582: 180
- ET SCAN Potential SSH Scan: 39
- 2001219: 39
- ET INFO Reserved Internal IP Traffic: 53
- 2002752: 53
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 37
- 2023753: 37
- GPL MISC source port 53 to <1024: 46
- 2100504: 46
- ET INFO CURL User Agent: 12
- 2002824: 12
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 14
- 2038669: 14
- ET VOIP SIP UDP Softphone INVITE overflow: 14
- 2002848: 14
- ET DROP Spamhaus DROP Listed Traffic Inbound group 50: 12
- 2400049: 12

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 102
- deploy/123123: 29
- vpn/vpnpass: 26
- mega/123: 29
- ftpuser/ftppassword: 24
- admin1234/admin1234: 25
- holu/holu: 23
- hadi/3245gs5662d34: 18
- root/3245gs5662d34: 12
- deploy/3245gs5662d34: 18
- default/default2014: 6
- root/Ss123456: 6
- ubuntu/Password@123: 5
- ubuntu/admin1234: 5
- centos/centos000: 6
- ubnt/1111111: 6

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- soap-envelope
- addressing
- discovery
- env:Envelope>
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
- )

### HTTP User-Agents
- No user agents were recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were recorded in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this timeframe.

## Key Observations and Anomalies
- The high number of attacks from the IP address 45.234.176.18 suggests a targeted or automated attack campaign.
- The prevalence of commands related to SSH key manipulation indicates that attackers are attempting to establish persistent access to the honeypots.
- The `urbotnetisass` file downloads are indicative of a botnet campaign.
- The high number of DoublePulsar backdoor installation attempts is a significant finding and should be monitored closely.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data may be due to the nature of the attacks or a gap in logging.
