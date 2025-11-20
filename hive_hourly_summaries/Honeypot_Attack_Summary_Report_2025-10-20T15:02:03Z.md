Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T15:01:37Z
**Timeframe:** 2025-10-20T14:20:01Z to 2025-10-20T15:00:01Z
**Files Used to Generate Report:**
- agg_log_20251020T142001Z.json
- agg_log_20251020T144001Z.json
- agg_log_20251020T150001Z.json

**Executive Summary**
This report summarizes 18,670 total attacks recorded across three honeypot log files. The most frequently attacked honeypots were Honeytrap (8,406 attacks) and Cowrie (8,081 attacks). The top attacking IP address was 193.22.146.182 with 4,480 recorded attacks. Port 22 (SSH) was the most targeted port. Several CVEs were observed, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on system enumeration and establishing persistence.

**Detailed Analysis**

**Attacks by honeypot:**
- Honeytrap: 8,406
- Cowrie: 8,081
- Suricata: 1,376
- Sentrypeer: 362
- Dionaea: 137
- Redishoneypot: 70
- Mailoney: 82
- Tanner: 34
- Dicompot: 29
- Ciscoasa: 25
- H0neytr4p: 25
- ConPot: 21
- Miniprint: 10
- Adbhoney: 5
- Honeyaml: 6
- Ipphoney: 1

**Top attacking IPs:**
- 193.22.146.182: 4,480
- 8.208.83.0: 1,253
- 72.146.232.13: 1,221
- 157.230.169.149: 428
- 196.251.88.103: 347
- 194.190.153.226: 273
- 118.193.46.102: 396
- 154.70.102.114: 327
- 190.129.122.12: 311
- 23.91.96.123: 298
- 185.243.5.158: 258
- 103.139.192.221: 218
- 107.170.36.5: 247
- 202.65.129.171: 198
- 103.88.76.27: 253
- 213.109.67.90: 180
- 14.103.242.177: 105
- 152.32.252.65: 209
- 211.20.14.156: 145
- 14.103.121.146: 120

**Top targeted ports/protocols:**
- 22: 1,530
- 5060: 362
- 5903: 227
- 4444: 82
- 5901: 115
- 6379: 70
- 25: 82
- 8333: 79
- 5905: 75
- 5904: 75
- 3306: 45
- TCP/22: 46
- 5908: 49
- 5907: 48
- 5909: 49
- 5902: 40
- 8800: 34
- 80: 16
- 445: 44
- 9080: 15

**Most common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 3

**Commands attempted by attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
- lockr -ia .ssh: 27
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 27
- cat /proc/cpuinfo | grep name | wc -l: 27
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 27
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 27
- ls -lh $(which ls): 27
- which ls: 27
- crontab -l: 27
- w: 27
- uname -m: 27
- cat /proc/cpuinfo | grep model | grep name | wc -l: 27
- top: 27
- Enter new UNIX password: : 25
- Enter new UNIX password:": 25
- uname: 26
- uname -a: 26
- whoami: 26
- lscpu | grep Model: 26
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 26

**Signatures triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 275
- ET DROP Dshield Block Listed Source group 1: 258
- ET SCAN NMAP -sS window 1024: 186
- ET HUNTING RDP Authentication Bypass Attempt: 89
- ET INFO Reserved Internal IP Traffic: 60
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system: 39
- ET SCAN Potential SSH Scan: 33
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 17
- ET DROP Spamhaus DROP Listed Traffic Inbound group 6: 16
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 16

**Users / login attempts:**
- 345gs5662d34/345gs5662d34: 25
- user01/Password01: 15
- deploy/123123: 7
- root/adm1n010010: 4
- root/Adm1n123: 4
- root/ADM11corp: 4
- root/adm}n: 3
- root/Adm1n.123: 3
- root/mar: 3
- user01/3245gs5662d34: 3
- patrick/3245gs5662d34: 3
- root/ASDFG123: 2
- maks/maks123: 2
- vtatis/123: 2
- root/ortho: 2
- root/Root123..: 2
- root/qaz.123456: 2
- root/server1: 2
- public/0000: 2
- root/123: 4

**Files uploaded/downloaded:**
- rondo.naz.sh|sh&...: 1
- mips: 2

**HTTP User-Agents:**
- No HTTP User-Agents were recorded in this timeframe.

**SSH clients and servers:**
- No specific SSH clients or servers were recorded in this timeframe.

**Top attacker AS organizations:**
- No attacker AS organizations were recorded in this timeframe.

**Key Observations and Anomalies**
- The high volume of attacks from 193.22.146.182 suggests a targeted attack or a botnet with a significant number of nodes.
- The most common commands attempted by attackers are focused on reconnaissance and establishing persistence on the compromised machine.
- The triggered signatures indicate a high volume of scanning activity for MS Terminal Server and RDP services.
- The variety of credentials used in login attempts suggests that attackers are using common and default credential lists.
- The file `rondo.naz.sh` was downloaded, which is likely a malicious script to be executed on the target machine.
- The `mips` file downloaded suggests that attackers are targeting IoT devices or other MIPS-based architectures.
- The lack of HTTP User-Agents, SSH clients, and AS organizations suggests that the attacks are likely automated and not initiated from a browser or a specific SSH client.
