Honeypot Attack Summary Report

Report Generation Time: 2025-10-16T01:01:36Z
Timeframe: 2025-10-16T00:20:01Z to 2025-10-16T01:00:01Z

Files used to generate this report:
- agg_log_20251016T002001Z.json
- agg_log_20251016T004001Z.json
- agg_log_20251016T010001Z.json

Executive Summary:
This report summarizes 18,693 attacks recorded by the honeypot network. The majority of attacks were detected by the Suricata, Honeytrap, Cowrie, and Sentrypeer honeypots. A significant portion of the attacks were directed at port 445 (TCP), indicating a high level of interest in the SMB protocol. Attackers were observed attempting to install the DoublePulsar backdoor. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common.

Detailed Analysis:

Attacks by honeypot:
- Suricata: 4507
- Cowrie: 4291
- Honeytrap: 4418
- Sentrypeer: 3327
- Ciscoasa: 1684
- Dionaea: 247
- Tanner: 89
- Dicompot: 25
- H0neytr4p: 28
- ConPot: 23
- Mailoney: 35
- Honeyaml: 7
- ElasticPot: 3
- Adbhoney: 2
- Wordpot: 1
- Heralding: 3
- Redishoneypot: 3

Top attacking IPs:
- 117.233.92.45: 1328
- 182.184.30.36: 1321
- 206.191.154.180: 1379
- 159.89.166.213: 1260
- 185.243.5.121: 1098
- 23.94.26.58: 834
- 172.86.95.98: 474
- 172.86.95.115: 469
- 156.229.21.151: 342
- 197.243.14.52: 241
- 182.151.8.21: 204
- 62.141.43.183: 265
- 107.170.36.5: 232
- 198.12.68.114: 179
- 64.188.30.192: 193
- 200.39.46.41: 143
- 118.193.43.167: 171
- 193.32.162.157: 216
- 192.227.213.240: 133
- 152.32.145.25: 99

Top targeted ports/protocols:
- TCP/445: 2644
- 5060: 3327
- 22: 685
- TCP/5900: 365
- 8333: 187
- 5903: 191
- 80: 87
- 3306: 85
- UDP/5060: 92
- 5901: 108
- 1813: 156
- TCP/22: 63
- 23: 37
- 445: 105
- 5905: 78
- 5904: 76
- 443: 31
- 5907: 34
- 27017: 17
- 9092: 57

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0517

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 18
- cat /proc/cpuinfo | grep name | wc -l: 12
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
- ls -lh $(which ls): 12
- which ls: 12
- crontab -l: 12
- w: 12
- uname -m: 12
- cat /proc/cpuinfo | grep model | grep name | wc -l: 12
- top: 12
- uname: 12
- uname -a: 12
- whoami: 12
- lscpu | grep Model: 12
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 12
- Enter new UNIX password: : 8
- Enter new UNIX password:": 8
- uname -s -v -n -r -m: 2
- echo -e \"123qwe!@#\\ndINZhVrJ5mT6\\ndINZhVrJ5mT6\"|passwd|bash: 1

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2641
- 2024766: 2641
- ET DROP Dshield Block Listed Source group 1: 403
- 2402000: 403
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 197
- 2400041: 197
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 165
- 2400040: 165
- ET SCAN NMAP -sS window 1024: 153
- 2009582: 153
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 69
- 2023753: 69
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 45
- 2010517: 45
- ET SCAN Potential SSH Scan: 36
- 2001219: 36
- ET SCAN Sipsak SIP scan: 25
- 2008598: 25
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system: 14
- 2008953: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 13
- 2403345: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 22
- 2403348: 22

Users / login attempts:
- root/: 73
- 345gs5662d34/345gs5662d34: 18
- centos/dietpi: 6
- guest/11111: 5
- root/!QAZ2wsx#EDC: 3
- user/live: 3
- user1/user1: 3
- admin/130985: 2
- admin/13091992: 2
- admin/130891: 2
- admin/130781: 2
- lab/lab123: 2
- root/Qaz123qaz: 7
- Admin/1234: 2
- sa/: 2
- debian/password123: 6
- nobody/nobody2010: 6
- centos/0000000: 4
- root/PBX2015: 4
- zgr/123: 3

Files uploaded/downloaded:
- 11: 1
- fonts.gstatic.com: 1
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 1
- ie8.css?ver=1.0: 1
- html5.js?ver=3.7.3: 1

HTTP User-Agents:
- No HTTP User-Agents were logged in this timeframe.

SSH clients and servers:
- No SSH clients or servers were logged in this timeframe.

Top attacker AS organizations:
- No attacker AS organizations were logged in this timeframe.

Key Observations and Anomalies:
- A large number of attacks are targeting port 445, which is used for SMB. The signature for the DoublePulsar backdoor was triggered a significant number of times, suggesting that attackers are attempting to exploit this vulnerability.
- Attackers are using a variety of generic and default credentials to attempt to gain access to the honeypots. The most common username is "root".
- A number of commands were executed by attackers, including reconnaissance commands to gather system information, and commands to modify SSH authorized_keys to maintain persistence.
- A small number of files were downloaded, all of which appear to be related to web assets (CSS, Javascript).
- The CVEs detected are quite old, suggesting that some attackers are still using old exploits.
