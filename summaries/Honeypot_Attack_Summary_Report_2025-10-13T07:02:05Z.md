Honeypot Attack Summary Report

Report Generation Time: 2025-10-13T07:01:35Z
Timeframe of logs: 2025-10-13T06:20:01Z to 2025-10-13T07:00:01Z
Files used to generate this report:
- agg_log_20251013T062001Z.json
- agg_log_20251013T064001Z.json
- agg_log_20251013T070001Z.json

Executive Summary
This report summarizes 14,085 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Suricata, Ciscoasa, and Dionaea. The most frequent attacks originated from IP address 203.78.147.68. The most targeted port was 445/TCP, a common target for SMB exploits. Several CVEs were detected, including CVE-2002-0013 and CVE-2024-4577. A variety of commands were attempted by attackers, many of which were aimed at reconnaissance and establishing persistence.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 5931
- Suricata: 2361
- Ciscoasa: 1834
- Dionaea: 1832
- Sentrypeer: 892
- Mailoney: 849
- Honeytrap: 153
- Tanner: 114
- Miniprint: 44
- Redishoneypot: 16
- H0neytr4p: 17
- Adbhoney: 14
- ConPot: 11
- ElasticPot: 3
- Honeyaml: 5
- Wordpot: 2
- Heralding: 3
- Dicompot: 3
- Ipphoney: 1

Top attacking IPs:
- 203.78.147.68: 1558
- 182.10.161.21: 1331
- 138.124.30.225: 975
- 86.54.42.238: 820
- 223.100.22.69: 801
- 36.229.206.51: 778
- 116.50.179.74: 312
- 62.141.43.183: 324
- 197.44.15.210: 282
- 64.227.133.234: 282
- 172.86.95.98: 247
- 172.86.95.115: 241
- 157.10.252.119: 226
- 138.99.80.102: 258
- 221.121.100.32: 198
- 166.140.30.14: 273
- 200.196.50.91: 168
- 1.221.66.66: 164
- 52.172.177.191: 164

Top targeted ports/protocols:
- 445: 1787
- TCP/445: 1331
- 5060: 892
- 22: 970
- 25: 846
- 80: 116
- TCP/80: 64
- TCP/22: 63
- 9100: 44
- TCP/1080: 27
- 443: 17
- 1337: 20
- 23: 17
- 6379: 11
- 81: 17
- TCP/1433: 11
- TCP/8080: 11
- 1723: 6
- 6664: 5
- TCP/3306: 6

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 20
- cat /proc/cpuinfo | grep name | wc -l: 18
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- crontab -l: 18
- w: 18
- uname -m: 18
- uname -a: 18
- whoami: 18
- lscpu | grep Model: 18
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 18
- ls -lh $(which ls): 17
- which ls: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17
- Enter new UNIX password: : 12
- Enter new UNIX password:": 5
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 2

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1325
- 2024766: 1325
- ET DROP Dshield Block Listed Source group 1: 274
- 2402000: 274
- ET SCAN NMAP -sS window 1024: 158
- 2009582: 158
- ET SCAN Potential SSH Scan: 57
- 2001219: 57
- ET INFO Reserved Internal IP Traffic: 52
- 2002752: 52
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 20
- 2010517: 20
- GPL INFO SOCKS Proxy attempt: 18
- 2100615: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 6
- 2403343: 6
- ET CINS Active Threat Intelligence Poor Reputation IP group 12: 6
- 2403311: 6
- ET DROP Spamhaus DROP Listed Traffic Inbound group 9: 6
- 2400008: 6

Users / login attempts:
- 345gs5662d34/345gs5662d34: 19
- ubnt/3333333: 4
- blank/55555: 4
- blank/55: 4
- centos/centos2004: 4
- support/support33: 4
- test/test2024: 4
- vpn/vpnpass: 6
- sa/: 4
- ftpuser/ftppassword: 6
- root/CowS: 3
- root/ntrevick: 3
- root/3245gs5662d34: 3
- root/netforces: 3
- holu/holu: 3
- root/EricJ: 3
- test/qwerty12345: 3
- root/Arie: 3
- root/Paul: 3
- root/espc: 3

Files uploaded/downloaded:
- sh: 98
- wget.sh;: 4
- 11: 12
- fonts.gstatic.com: 12
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 12
- ie8.css?ver=1.0: 12
- html5.js?ver=3.7.3: 12
- w.sh;: 1
- c.sh;: 1
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1

HTTP User-Agents:
- N/A

SSH clients and servers:
- N/A

Top attacker AS organizations:
- N/A

Key Observations and Anomalies
- The high number of attacks on port 445 (SMB) suggests a continued focus on exploiting this service. The triggered signature for the DoublePulsar backdoor corresponds with this activity.
- A significant number of commands are related to reconnaissance and disabling security measures (e.g., `chattr -ia .ssh`), followed by attempts to install SSH keys for persistence.
- Several attackers attempted to download and execute malicious shell scripts and ELF binaries (e.g., `arm.urbotnetisass`, `w.sh`), indicating attempts to install malware or botnet clients.
- The variety of credentials used in brute-force attempts indicates that attackers are using common and default credential lists.
- There is a notable amount of scanning activity, particularly from Nmap, and traffic from IP addresses on Dshield and Spamhaus blocklists.
