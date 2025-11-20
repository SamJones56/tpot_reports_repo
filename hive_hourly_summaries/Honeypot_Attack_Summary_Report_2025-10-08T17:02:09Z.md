Honeypot Attack Summary Report

**Report Generated:** 2025-10-08T17:01:37Z
**Timeframe:** 2025-10-08T16:20:01Z to 2025-10-08T17:00:01Z
**Files Used:**
- agg_log_20251008T162001Z.json
- agg_log_20251008T164001Z.json
- agg_log_20251008T170001Z.json

**Executive Summary**
This report summarizes 14,179 malicious events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. Attackers were observed attempting to exploit several vulnerabilities, including CVE-2022-27255, CVE-2021-3449, and CVE-2019-11500. A significant number of brute-force login attempts were detected, alongside various post-login commands aimed at reconnaissance and establishing persistence. Network traffic analysis revealed multiple scanning activities and triggers for security signatures related to known malicious IPs and attack patterns.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 7053
- Honeytrap: 2046
- Suricata: 1772
- Ciscoasa: 1642
- Mailoney: 855
- Sentrypeer: 470
- H0neytr4p: 65
- Dionaea: 56
- ConPot: 45
- Tanner: 51
- Redishoneypot: 31
- ElasticPot: 26
- ssh-rsa: 30
- Adbhoney: 7
- Ipphoney: 11
- Honeyaml: 10
- Dicompot: 3
- Heralding: 6

**Top Attacking IPs:**
- 176.65.141.117: 779
- 23.94.26.58: 494
- 212.87.220.20: 608
- 116.205.121.146: 338
- 104.168.35.231: 282
- 173.212.228.191: 277
- 172.245.135.97: 351
- 118.219.239.122: 312
- 189.217.130.86: 203
- 103.146.52.252: 198
- 117.216.143.31: 247
- 176.65.151.22: 248
- 45.140.17.52: 127
- 145.239.89.124: 119
- 23.95.37.90: 119
- 118.45.205.44: 114
- 146.190.93.207: 109
- 45.94.4.184: 109
- 103.176.78.28: 104
- 154.203.166.161: 104

**Top Targeted Ports/Protocols:**
- 22: 906
- 25: 859
- 5060: 470
- TCP/1080: 338
- 8333: 137
- TCP/5900: 166
- UDP/5060: 192
- 443: 57
- 5903: 96
- 5901: 73
- 23: 46
- 9200: 24
- TCP/5432: 33
- 5908: 49
- 5907: 48
- 5909: 48
- 12125: 33
- 80: 38
- 6379: 14

**Most Common CVEs:**
- CVE-2022-27255: 9
- CVE-2021-3449: 7
- CVE-2019-11500: 5
- CVE-2006-2369: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 44
- lockr -ia .ssh: 44
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 44
- cat /proc/cpuinfo | grep name | wc -l: 43
- Enter new UNIX password: : 43
- Enter new UNIX password:: 43
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 43
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 43
- ls -lh $(which ls): 43
- which ls: 43
- crontab -l: 43
- w: 43
- uname -m: 43
- cat /proc/cpuinfo | grep model | grep name | wc -l: 43
- top: 43
- uname: 43
- uname -a: 44
- whoami: 43
- lscpu | grep Model: 43
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 43

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 295
- 2402000: 295
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 191
- 2400040: 191
- ET SCAN NMAP -sS window 1024: 142
- 2009582: 142
- ET SCAN Sipsak SIP scan: 180
- 2008598: 180
- GPL INFO SOCKS Proxy attempt: 171
- 2100615: 171
- ET INFO Python aiohttp User-Agent Observed Inbound: 168
- 2064326: 168
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 76
- 2023753: 76
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET HUNTING RDP Authentication Bypass Attempt: 34
- 2034857: 34
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 31
- 2010939: 31

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 39
- root/: 30
- supervisor/ubuntu: 6
- supervisor/supervisor66: 6
- unknown/3333: 6
- unknown/222: 6
- blank/blank33: 6
- root/Admin123: 6
- test/1234: 6
- felix/3245gs5662d34: 5
- support/1123456: 4
- root/dottie: 4
- deployer/deployer!: 7
- operator/qwerty1234: 6
- support/1z2x3c4v: 4
- nobody/nobody55: 4
- root/qwertyui: 4
- debian/debian12345: 4
- felix/felix1234: 4
- bitwarden/bitwarden!: 4

**Files Uploaded/Downloaded:**
- parm;: 3
- parm5;: 3
- parm6;: 3
- parm7;: 3
- psh4;: 3
- parc;: 3
- pmips;: 3
- pmipsel;: 3
- psparc;: 3
- px86_64;: 3
- pi686;: 3
- pi586;: 3
- discovery: 2
- mips: 2
- rondo.naz.sh|sh&...: 1
- w.sh;: 1
- c.sh;: 1
- soap-envelope: 1
- soap-encoding: 1
- addressing: 1

**HTTP User-Agents:**
- No user agents recorded in this timeframe.

**SSH Clients:**
- No specific SSH clients recorded in this timeframe.

**SSH Servers:**
- No specific SSH servers recorded in this timeframe.

**Top Attacker AS Organizations:**
- No AS organization data recorded in this timeframe.

**Key Observations and Anomalies**
- A high concentration of SSH-based attacks, primarily targeting user 'root' and using common credential stuffing lists.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` was executed repeatedly, indicating a coordinated campaign to inject a malicious SSH key for persistence.
- The presence of CVE-2022-27255 exploitation attempts (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow) is a notable trend.
- A significant amount of scanning activity was detected by Suricata, particularly NMAP scans and probes for SIP and RDP services.
- The lack of HTTP user agents, SSH client/server strings, and ASN organization data might suggest either a limitation in the current honeypot configuration or that attackers are using non-standard tools that do not advertise this information.
