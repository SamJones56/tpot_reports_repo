Honeypot Attack Summary Report

Report Generation Time: 2025-10-11T08:01:31Z
Timeframe: 2025-10-11T07:20:01Z to 2025-10-11T08:00:01Z
Files Used:
- agg_log_20251011T072001Z.json
- agg_log_20251011T074001Z.json
- agg_log_20251011T080001Z.json

Executive Summary

This report summarizes 12,254 attacks recorded by the honeypot network. The primary attack vectors observed were reconnaissance and brute-force attempts targeting a variety of services, most notably SSH (port 22), SMB (port 445), and SIP (port 5060). A significant portion of the attacks originated from a small number of IP addresses, with a wide geographic distribution. Several vulnerabilities were targeted, with CVE-2022-27255 being the most frequent. Attackers attempted a range of commands, primarily focused on establishing control and gathering system information.

Detailed Analysis

Attacks by Honeypot:
- Honeytrap: 3262
- Cowrie: 2720
- Suricata: 2235
- Ciscoasa: 1773
- Dionaea: 824
- Mailoney: 854
- Sentrypeer: 372
- Tanner: 75
- Redishoneypot: 39
- ConPot: 22
- H0neytr4p: 21
- Honeyaml: 8
- Adbhoney: 6
- Heralding: 6
- ElasticPot: 4
- Dicompot: 3
- Miniprint: 29
- Ipphoney: 1

Top Attacking IPs:
- 176.65.141.117: 820
- 223.100.22.69: 744
- 216.9.225.39: 477
- 88.214.50.58: 206
- 5.250.184.177: 219
- 150.95.157.171: 236
- 88.210.63.16: 224
- 152.32.172.117: 219
- 203.57.39.187: 169
- 167.250.224.25: 165
- 4.213.160.153: 162
- 51.75.194.10: 144
- 222.107.251.147: 100
- 103.171.84.217: 144
- 68.183.193.0: 102
- 107.170.36.5: 97
- 159.89.121.144: 95
- 188.246.224.87: 88
- 14.103.127.80: 86
- 185.39.19.40: 83

Top Targeted Ports/Protocols:
- 25: 844
- 445: 753
- 5060: 380
- 22: 409
- UDP/5060: 215
- 5903: 195
- 80: 66
- TCP/80: 51
- TCP/22: 84
- 23: 47
- 5908: 83
- 5909: 82
- 5901: 79
- 5907: 49
- 9000: 14
- 6379: 28
- 9100: 29
- 1723: 14
- 8880: 12
- 8099: 27

Most Common CVEs:
- CVE-2022-27255 CVE-2022-27255: 23
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-1999-0183: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 19
- lockr -ia .ssh: 19
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 19
- cat /proc/cpuinfo | grep name | wc -l: 10
- cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 10
- free -m | grep Mem | awk ...: 10
- ls -lh $(which ls): 10
- which ls: 10
- crontab -l: 10
- w: 10
- uname -m: 10
- cat /proc/cpuinfo | grep model | grep name | wc -l: 10
- top: 10
- uname: 10
- uname -a: 10
- whoami: 10
- lscpu | grep Model: 9
- df -h | head -n 2 | awk ...: 9
- Enter new UNIX password: : 7
- Enter new UNIX password:": 7

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1: 504
- 2402000: 504
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 350
- 2023753: 350
- ET SCAN Sipsak SIP scan: 187
- 2008598: 187
- ET HUNTING RDP Authentication Bypass Attempt: 159
- 2034857: 159
- ET SCAN NMAP -sS window 1024: 144
- 2009582: 144
- ET SCAN Potential SSH Scan: 68
- 2001219: 68
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 29
- 2400031: 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 11
- 2403343: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 9
- 2403346: 9
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 8
- 2038669: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 15
- 2403342: 15

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 17
- root/3245gs5662d34: 7
- support/support44: 6
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 5
- root/nPSpP4PBW0: 5
- test/qwe123: 6
- root/marketing: 4
- root/ElastixAdmin1234: 4
- root/dialbpo2020: 4
- root/1q2w3e4r5t6y: 4
- root/samsung: 6
- root/password123: 6

Files Uploaded/Downloaded:
- sh: 98
- 11: 5
- fonts.gstatic.com: 5
- css?family=Libre+Franklin...: 4
- ie8.css?ver=1.0: 4
- html5.js?ver=3.7.3: 4
- welcome.jpg): 1
- writing.jpg): 1
- tags.jpg): 1
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2

HTTP User-Agents:
- No user agents were recorded in this timeframe.

SSH Clients:
- No SSH clients were recorded in this timeframe.

SSH Servers:
- No SSH servers were recorded in this timeframe.

Top Attacker AS Organizations:
- No AS organizations were recorded in this timeframe.

Key Observations and Anomalies

- A significant number of commands are associated with reconnaissance and establishing a foothold on the compromised machine, such as manipulating SSH keys and gathering system information.
- The command `cd /data/local/tmp/; rm *; busybox wget ...` indicates an attempt to download and execute a malicious payload, specifically targeting Android devices.
- The repeated targeting of CVE-2022-27255, a vulnerability in Realtek eCos SDK, suggests a widespread campaign against IoT devices.
- The high volume of attacks from a limited number of IPs suggests either a targeted campaign from these sources or a small number of highly active infected machines.
- The presence of Mailoney as a top honeypot indicates a significant amount of SMTP-based attacks, likely related to spam or phishing campaigns.
