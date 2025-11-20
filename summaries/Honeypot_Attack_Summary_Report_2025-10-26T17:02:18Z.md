Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T17:01:27Z
**Timeframe:** 2025-10-26T16:20:02Z to 2025-10-26T17:00:01Z
**Files Used:**
- agg_log_20251026T162002Z.json
- agg_log_20251026T164002Z.json
- agg_log_20251026T170001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 23,820 events were recorded. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and telnet-based brute force and command injection attempts. The most prolific attacking IP address was 172.188.91.73. A variety of CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted numerous commands, primarily aimed at reconnaissance and installing malware.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 14511
- Honeytrap: 2880
- Sentrypeer: 1895
- Ciscoasa: 1799
- Suricata: 1454
- Dionaea: 728
- Redishoneypot: 152
- Tanner: 146
- Adbhoney: 98
- Mailoney: 127
- H0neytr4p: 22
- Honeyaml: 6
- Ipphoney: 2

**Top Attacking IPs:**
- 172.188.91.73: 12843
- 41.139.164.134: 610
- 144.172.108.231: 994
- 45.154.138.19: 667
- 185.243.5.158: 362
- 185.243.5.121: 402
- 199.68.196.115: 184
- 107.170.36.5: 250
- 192.40.58.3: 193
- 162.240.39.179: 208
- 35.128.43.14: 144
- 149.104.94.10: 235
- 125.124.42.183: 183
- 77.83.207.203: 113
- 167.250.224.25: 125
- 68.183.149.135: 111
- 3.137.73.221: 84
- 130.83.245.115: 66
- 68.183.207.213: 63
- 198.23.238.154: 60

**Top Targeted Ports/Protocols:**
- 22: 2850
- 5060: 1895
- 5038: 667
- 445: 699
- 80: 146
- 6379: 152
- 8333: 156
- 5903: 134
- 5901: 124
- 25: 127
- TCP/22: 100
- 5904: 77
- 5905: 76
- TCP/80: 84
- 25565: 38
- 5909: 50
- 5908: 49
- 5907: 48

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2014-6271: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 5
- `lockr -ia .ssh`: 5
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 5
- `cat /proc/cpuinfo | grep name | wc -l`: 5
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 5
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 5
- `ls -lh $(which ls)`: 5
- `which ls`: 5
- `crontab -l`: 5
- `w`: 3
- `uname -m`: 3
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 3
- `top`: 3
- `uname`: 3
- `uname -a`: 3
- `whoami`: 3
- `lscpu | grep Model`: 3
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 3
- `pm path com.ufo.miner`: 2
- `pm install /data/local/tmp/ufo.apk`: 2
- `rm -f /data/local/tmp/ufo.apk`: 2
- `am start -n com.ufo.miner/com.example.test.MainActivity`: 2
- `ps | grep trinity`: 2
- `rm -rf /data/local/tmp/*`: 2
- `chmod 0755 /data/local/tmp/nohup`: 2
- `chmod 0755 /data/local/tmp/trinity`: 2
- `/data/local/tmp/nohup su -c /data/local/tmp/trinity`: 2
- `/data/local/tmp/nohup /data/local/tmp/trinity`: 2
- `cat /proc/uptime 2 > /dev/null | cut -d. -f1`: 2

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 296
- 2402000: 296
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 192
- 2023753: 192
- ET SCAN NMAP -sS window 1024: 168
- 2009582: 168
- ET HUNTING RDP Authentication Bypass Attempt: 77
- 2034857: 77
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 48
- 2001219: 48
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 53
- 2010517: 53
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 18
- 2400027: 18
- ET INFO CURL User Agent: 13
- 2002824: 13
- GPL SNMP request udp: 8
- 2101417: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 39: 7
- 2400038: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 7
- 2403302: 7
- ET DROP Spamhaus DROP Listed Traffic Inbound group 34: 7
- 2400033: 7
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 26
- 2010939: 26
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 14
- 2400031: 14

**Users / Login Attempts:**
- root/granith: 4
- root/Gremlin688: 4
- root/griffin12: 4
- root/grup0f4v4: 4
- root/GslStf010501A: 4
- root/grc007xp: 3
- root/02041992Ionela%^&: 3
- 345gs5662d34/345gs5662d34: 4
- admin/100790: 2
- admin/10071978: 2
- admin/100683: 2
- admin/100586: 2
- admin/10051982: 2
- ubuntu/pass: 2
- root/3245gs5662d34: 2
- bash/Drag1823hcacatcuciocolataABC111: 2
- jla/xurros22$: 2
- user/Edong^$!!: 2
- user/EEBP@assw0rd!: 2
- user/Cxf26/2=13: 2
- user/Cup@1234: 2
- user/Cmiotcswxhn&bhn@20240828: 2

**Files Uploaded/Downloaded:**
- sh: 98
- Help:Contents: 34
- wget.sh;: 24
- a>: 4
- w.sh;: 6
- c.sh;: 6
- arm.uhavenobotsxd;: 2
- arm.uhavenobotsxd: 2
- arm5.uhavenobotsxd;: 2
- arm5.uhavenobotsxd: 2
- arm6.uhavenobotsxd;: 2
- arm6.uhavenobotsxd: 2
- arm7.uhavenobotsxd;: 2
- arm7.uhavenobotsxd: 2
- x86_32.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd: 2
- mips.uhavenobotsxd;: 2
- mips.uhavenobotsxd: 2
- mipsel.uhavenobotsxd;: 1
- mipsel.uhavenobotsxd: 1
- lol.sh;: 2
- mediawiki-announce: 1
- Localisation#Translation_resources: 1
- Manual:Combating_spam: 1
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies
- The overwhelming majority of attacks originate from the IP address 172.188.91.73, suggesting a single, highly active threat actor or a large botnet.
- A significant number of commands are related to downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`), indicating attempts to install malware or establish persistence.
- Several commands target Android devices (e.g., `pm path com.ufo.miner`, `pm install /data/local/tmp/ufo.apk`), which is a notable trend.
- Attackers are attempting to modify SSH authorized_keys to gain persistent access.
- There is a mix of broad, untargeted scanning activity and more specific, targeted attacks against SSH and other services.

This concludes the Honeypot Attack Summary Report.
