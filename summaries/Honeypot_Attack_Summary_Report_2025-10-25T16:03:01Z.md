Honeypot Attack Summary Report
Report generated on: 2025-10-25T16:01:34Z
Timeframe: 2025-10-25 15:20:01 - 2025-10-25 16:00:01
Files used to generate this report:
- agg_log_20251025T152001Z.json
- agg_log_20251025T154001Z.json
- agg_log_20251025T160001Z.json

Executive Summary:
This report summarizes 18,477 events collected from the honeypot network. The majority of attacks were reconnaissance and brute-force attempts. A significant number of attacks were observed against VNC and SSH services. The top attacking IP address is 185.243.96.105 with 4084 events.

Detailed Analysis:
Attacks by honeypot:
- Cowrie: 5235
- Heralding: 4183
- Honeytrap: 3423
- Suricata: 3159
- Ciscoasa: 1783
- Sentrypeer: 192
- Tanner: 121
- Dionaea: 96
- Redishoneypot: 100
- Mailoney: 104
- Adbhoney: 25
- H0neytr4p: 20
- ConPot: 28
- ElasticPot: 6
- Medpot: 1
- Honeyaml: 1

Top attacking IPs:
- 185.243.96.105: 4084
- 153.142.31.8: 1431
- 80.94.95.238: 1001
- 64.226.124.227: 1077
- 220.80.223.144: 354
- 125.25.172.245: 350
- 94.254.0.234: 284
- 103.206.72.2: 266
- 107.170.36.5: 250
- 103.250.10.21: 189
- 163.53.168.23: 197
- 158.174.211.17: 190
- 101.89.133.243: 140
- 3.137.73.221: 87
- 101.36.231.233: 153
- 204.76.203.28: 185
- 38.137.11.10: 160
- 31.193.137.190: 188
- 185.50.38.231: 109
- 135.235.138.43: 108
- 14.225.167.148: 88
- 196.251.85.178: 63
- 167.71.65.227: 50
- 45.136.68.49: 49
- 109.123.239.165: 46

Top targeted ports/protocols:
- vnc/5900: 4183
- TCP/445: 1426
- 22: 802
- 8333: 213
- 5060: 192
- 80: 121
- 6379: 100
- 5903: 133
- 5901: 110
- 25: 104
- 5904: 76
- 5905: 78
- 443: 26
- 1025: 23
- 3129: 19
- 81: 33
- 5907: 49
- TCP/22: 36
- 5909: 49
- 23: 30

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2023-20887 CVE-2023-20889 CVE-2023-20888 CVE-2023-20887: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 25
- lockr -ia .ssh: 25
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 24
- cat /proc/cpuinfo | grep name | wc -l: 24
- rm -rf /tmp/secure.sh; ...: 17
- cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 24
- free -m | grep Mem | awk ...: 24
- which ls: 24
- ls -lh $(which ls): 24
- crontab -l: 24
- w: 24
- uname -m: 24
- cat /proc/cpuinfo | grep model | grep name | wc -l: 24
- top: 24
- uname: 24
- uname -a: 24
- whoami: 24
- lscpu | grep Model: 24
- df -h | head -n 2 | awk ...: 24
- Enter new UNIX password: : 7
- cd /data/local/tmp/; rm *; busybox wget ...: 4

Users / login attempts:
- 345gs5662d34/345gs5662d34: 20
- /Passw0rd: 24
- root/3245gs5662d34: 14
- /passw0rd: 15
- /qwertyui: 13
- /1q2w3e4r: 13
- /1qaz2wsx: 13
- root/EZvhENPH25: 4
- root/F0gL1gh7: 3
- /visual: 3
- /z1x2c3v4: 2
- gitlab/gitlab: 2
- system/1qaz2wsx: 2
- user/user: 2
- user1/user1: 2
- root/Aa123456: 2
- root/P@ssword: 2
- /123456qw: 2
- root/www.my-idc.com: 2
- chiara/chiara: 3
- root/adminHW: 3
- root/f0n31p: 3
- /123qweasd: 2
- devuser/devuser: 2
- root/changeit: 2
- root/secreto: 2
- neo4j/neo4j: 2
- telecomadmin/admintelecom: 2
- root/technical: 2
- /1234qwer: 5
- john/1q2w3e4r: 2
- root/qwe!@#123: 2
- root/F1x1c5fort: 4
- /support: 3
- /user: 3
- /manager: 3
- devendra/devendra: 3
- root/change: 3
- root/F1x1c5traversit: 3
- /1a2s3d4f: 2
- rohan/rohan123: 2
- root/sb123: 2
- faxuser/faxuser: 2
- /01234567: 2
- /testpass: 2

Files uploaded/downloaded:
- rondo.dtm.sh||curl: 12
- rondo.dtm.sh)|sh`: 12
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
- mips: 2
- sh: 6

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1424
- 2024766: 1424
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 461
- 2023753: 461
- ET DROP Dshield Block Listed Source group 1: 319
- 2402000: 319
- ET SCAN NMAP -sS window 1024: 191
- 2009582: 191
- ET INFO VNC Authentication Failure: 89
- 2002920: 89
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET HUNTING RDP Authentication Bypass Attempt: 58
- 2034857: 58
- ET SCAN Potential SSH Scan: 20
- 2001219: 20
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14: 16
- 2400013: 16
- GPL MISC source port 53 to <1024: 12
- 2100504: 12
- ET INFO CURL User Agent: 9
- 2002824: 9
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 7
- 2400040: 7
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 7
- 2400031: 7
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 7
- 2400027: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 14: 6
- 2403313: 6
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 6
- 2403302: 6

Key Observations and Anomalies:
- A large number of events are associated with the IP address 185.243.96.105, indicating a targeted attack or a botnet.
- The high number of VNC and SSH related events suggests that attackers are actively trying to gain remote access to the systems.
- The presence of the DoublePulsar backdoor signature indicates that some of the attacks are using sophisticated malware.
- The commands attempted by attackers suggest that they are trying to gather information about the system, disable security measures, and install malware.
- The file `arm.urbotnetisass` was downloaded multiple times, which could be a payload for ARM-based devices.
- A number of reconnaissance commands like `whoami`, `uname -a`, `lscpu` were frequently observed.
