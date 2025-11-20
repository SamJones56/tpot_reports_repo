Honeypot Attack Summary Report

Report generated at: 2025-10-16T00:01:35Z
Timeframe: 2025-10-15T23:20:02Z to 2025-10-16T00:00:01Z
Files used: agg_log_20251015T232002Z.json, agg_log_20251015T234001Z.json, agg_log_20251016T000001Z.json

Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 22,119 attacks were recorded. The most targeted honeypot was Honeytrap. The top attacking IP address was 188.246.224.87, and the most targeted port was 5060. Numerous CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, primarily related to establishing SSH access and reconnaissance. A significant number of security signatures were triggered, with "ET SCAN MS Terminal Server Traffic on Non-standard Port" being the most frequent.

Detailed Analysis

Attacks by honeypot:
- Honeytrap: 5194
- Cowrie: 4945
- Suricata: 4056
- Sentrypeer: 3704
- Mailoney: 1708
- Ciscoasa: 1735
- Dionaea: 506
- Tanner: 144
- H0neytr4p: 64
- ElasticPot: 21
- ConPot: 12
- Honeyaml: 9
- Dicompot: 6
- Adbhoney: 7
- Redishoneypot: 3
- Heralding: 3
- Ipphoney: 2

Top attacking IPs:
- 188.246.224.87: 2692
- 206.191.154.180: 1363
- 86.54.42.238: 1631
- 185.243.5.121: 1263
- 23.94.26.58: 859
- 171.231.183.204: 370
- 171.243.151.249: 426
- 172.86.95.98: 475
- 172.86.95.115: 454
- 168.167.140.62: 408
- 62.141.43.183: 321
- 143.244.134.97: 187
- 64.227.133.234: 179
- 43.153.100.224: 224
- 107.170.36.5: 253
- 36.134.203.156: 212
- 185.213.164.85: 224
- 14.116.156.100: 133
- 34.123.134.194: 143
- 51.89.150.103: 135

Top targeted ports/protocols:
- 5060: 3704
- 22: 864
- 25: 1708
- 445: 370
- TCP/5900: 350
- 5903: 225
- 8333: 194
- 80: 152
- UDP/5060: 184
- 5901: 113
- 3306: 80
- 5905: 77
- 5904: 80
- 23: 55
- 8000: 78
- TCP/1433: 53
- 443: 54
- 9200: 21
- 2323: 28
- 1434: 34

Most common CVEs:
- CVE-2005-4050: 88
- CVE-2002-0013 CVE-2002-0012: 17
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 25
- lockr -ia .ssh: 25
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 25
- cat /proc/cpuinfo | grep name | wc -l: 7
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 7
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 7
- ls -lh $(which ls): 7
- which ls: 7
- crontab -l: 7
- w: 7
- uname -m: 7
- cat /proc/cpuinfo | grep model | grep name | wc -l: 7
- top: 7
- uname: 7
- uname -a: 8
- whoami: 7
- lscpu | grep Model: 7
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 7
- Enter new UNIX password: : 4

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1431
- ET HUNTING RDP Authentication Bypass Attempt: 678
- ET DROP Dshield Block Listed Source group 1: 410
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 226
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 159
- ET SCAN NMAP -sS window 1024: 162
- ET VOIP MultiTech SIP UDP Overflow: 88
- ET INFO Reserved Internal IP Traffic: 58
- ET SCAN Suspicious inbound to MSSQL port 1433: 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 29

Users / login attempts:
- root/: 77
- 345gs5662d34/345gs5662d34: 24
- root/Qaz123qaz: 15
- root/123@@@: 13
- ftpuser/ftppassword: 10
- centos/centos2005: 6
- debian/4: 6
- user/qwerty1: 6
- centos/centos2007: 6
- supervisor/supervisor2011: 6
- blank/999999: 6
- root/QWE123!@#qwe: 8
- user/user2024: 6

Files uploaded/downloaded:
- sh: 98
- bot.html): 2
- get?src=cl1ckh0use: 2
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
- ns#: 2
- rdf-schema#: 1
- types#: 1

HTTP User-Agents:
- N/A

SSH clients:
- N/A

SSH servers:
- N/A

Top attacker AS organizations:
- N/A

Key Observations and Anomalies

- A high volume of attacks originated from the IP address 188.246.224.87, primarily triggering the "ET SCAN MS Terminal Server Traffic on Non-standard Port" signature. This suggests a targeted campaign to find and exploit vulnerable RDP services.
- The most common commands executed by attackers are focused on reconnaissance (e.g., `uname -a`, `cat /proc/cpuinfo`) and establishing persistent SSH access by adding their public key to `authorized_keys`. The use of "mdrfckr" in the key is a notable identifier.
- The `urbotnetisass` malware was downloaded in various architectures (arm, x86, mips), indicating a multi-platform attack campaign.
- The top targeted ports are a mix of common services like SSH (22), SMTP (25), and SIP (5060), as well as less common ports that are often associated with specific malware or trojans.
- The presence of CVEs from as early as 1999 suggests that attackers are still attempting to exploit old, well-known vulnerabilities.

This concludes the Honeypot Attack Summary Report.
