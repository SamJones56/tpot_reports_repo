Honeypot Attack Summary Report

Report generated on 2025-10-20T19:01:37Z for the timeframe from 2025-10-20T18:20:01Z to 2025-10-20T19:01:37Z.

Files used for this report:
- agg_log_20251020T182001Z.json
- agg_log_20251020T184001Z.json
- agg_log_20251020T190001Z.json

Executive Summary:
This report summarizes 21,591 events collected from the honeypot network. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequent attacks originated from IP address 77.83.240.70. The most targeted port was port 22 (SSH). A number of CVEs were detected, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis:

Attacks by honeypot:
- Honeytrap: 10,047
- Cowrie: 7,841
- Suricata: 1,552
- Mailoney: 901
- Dionaea: 694
- Sentrypeer: 297
- Adbhoney: 52
- Tanner: 68
- H0neytr4p: 49
- Ciscoasa: 43
- Redishoneypot: 32
- ElasticPot: 31
- Miniprint: 28
- Dicompot: 28
- ConPot: 11
- Honeyaml: 10
- Ipphoney: 3

Top attacking IPs:
- 77.83.240.70: 5356
- 45.78.193.116: 1135
- 72.146.232.13: 1068
- 176.65.141.119: 821
- 43.229.78.35: 642
- 103.143.238.207: 302
- 85.234.140.36: 288
- 186.118.142.216: 228
- 103.146.23.183: 220
- 154.221.28.214: 229
- 101.36.98.7: 150
- 62.218.113.26: 233
- 49.247.36.49: 217
- 4.213.138.243: 207
- 103.49.238.251: 203
- 144.48.8.10: 139
- 107.170.36.5: 127
- 203.25.214.255: 187
- 36.50.54.8: 129
- 125.88.169.233: 109
- 185.243.5.158: 111

Top targeted ports/protocols:
- 22: 1276
- 25: 901
- 5060: 297
- 5903: 180
- TCP/21: 177
- 21: 94
- 8333: 117
- 2121: 385
- 31337: 156
- 23: 80
- 5901: 101
- 80: 66
- 5905: 67
- 5904: 52
- 443: 36
- TCP/80: 45
- 1433: 22
- 6379: 23
- 9200: 23

Most common CVEs:
- CVE-2005-4050
- CVE-2019-11500
- CVE-2018-10562
- CVE-2018-10561
- CVE-2021-3449
- CVE-2020-2551
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-35394

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 38
- lockr -ia .ssh: 38
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 37
- cat /proc/cpuinfo | grep name | wc -l: 36
- cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 36
- free -m | grep Mem | awk ...: 36
- ls -lh $(which ls): 36
- which ls: 36
- crontab -l: 36
- w: 36
- uname -m: 36
- cat /proc/cpuinfo | grep model | grep name | wc -l: 36
- top: 36
- uname: 36
- uname -a: 35
- whoami: 34
- lscpu | grep Model: 34
- df -h | head -n 2 | awk ...: 35
- Enter new UNIX password: : 31
- Enter new UNIX password:: 31

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1: 316
- 2402000: 316
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 225
- 2023753: 225
- ET SCAN NMAP -sS window 1024: 156
- 2009582: 156
- ET FTP FTP PWD command attempt without login: 87
- 2010735: 87
- ET FTP FTP CWD command attempt without login: 86
- 2010731: 86
- ET HUNTING RDP Authentication Bypass Attempt: 43
- 2034857: 43
- ET INFO Reserved Internal IP Traffic: 50
- 2002752: 50

Users / login attempts:
- 345gs5662d34/345gs5662d34: 36
- user01/Password01: 14
- deploy/123123: 12
- gcs_client/SysGal.5560: 6
- sa/GCSsa5560: 6
- gcs_web_client/SysGal.5560: 6
- root/AdminGIS2015: 4
- user01/3245gs5662d34: 4
- root/adminp4d1JKT1111: 4
- deploy/3245gs5662d34: 5

Files uploaded/downloaded:
- wget.sh;: 16
- w.sh;: 4
- c.sh;: 4
- gpon80&ipv=0: 4
- arm.urbotnetisass;: 1
- arm5.urbotnetisass;: 1
- arm6.urbotnetisass;: 1
- arm7.urbotnetisass;: 1
- x86_32.urbotnetisass;: 1
- mips.urbotnetisass;: 1
- mipsel.urbotnetisass;: 1
- bot;: 1

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH clients and servers:
- No specific SSH clients or servers were logged in this timeframe.

Top attacker AS organizations:
- No AS organization data was available in the logs.

Key Observations and Anomalies:
- A large number of commands executed by attackers are related to establishing a persistent SSH connection by adding a public key to the `authorized_keys` file.
- There is a significant amount of scanning activity for MS Terminal Server and FTP services on non-standard ports.
- The Dshield blocklist is effective in dropping a large number of connections from known malicious IPs.
- Several download attempts of files with `.urbotnetisass` extension were observed, which is likely related to a botnet.
- The CVEs detected are relatively old, suggesting that attackers are targeting unpatched systems.
