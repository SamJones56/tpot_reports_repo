Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T09:01:35Z
**Timeframe:** 2025-10-19T08:20:01Z to 2025-10-19T09:00:01Z
**Files Used:**
- agg_log_20251019T082001Z.json
- agg_log_20251019T084001Z.json
- agg_log_20251019T090001Z.json

**Executive Summary**

This report summarizes 27,576 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was 185.243.96.105, predominantly targeting VNC on port 5900. A significant number of attacks also targeted SIP and SSH services. The most frequently observed CVE was CVE-2005-4050. Attackers attempted various commands, including efforts to add SSH keys for persistence.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 10844
- Heralding: 4877
- Suricata: 4333
- Honeytrap: 3252
- Sentrypeer: 2212
- Ciscoasa: 926
- Dionaea: 875
- Adbhoney: 61
- ConPot: 56
- Mailoney: 51
- Tanner: 23
- ElasticPot: 23
- H0neytr4p: 17
- Redishoneypot: 10
- Honeyaml: 8
- Dicompot: 4
- Miniprint: 2
- Ipphoney: 2

***Top Attacking IPs***

- 185.243.96.105: 4871
- 194.50.16.73: 1977
- 72.146.232.13: 1164
- 198.23.190.58: 1146
- 23.94.26.58: 1115
- 50.6.225.98: 1130
- 213.6.65.122: 1077
- 198.12.68.114: 847
- 186.10.24.214: 682
- 152.42.130.45: 613
- 178.62.252.242: 520
- 159.223.6.241: 496
- 129.212.187.135: 492
- 45.128.199.34: 402
- 118.193.46.102: 263
- 45.140.17.52: 247
- 190.85.41.170: 233
- 23.95.128.167: 124
- 64.225.55.168: 144
- 116.196.106.74: 145

***Top Targeted Ports/Protocols***

- vnc/5900: 4871
- 22: 2381
- 5060: 2212
- UDP/5060: 1339
- TCP/445: 1074
- 445: 689
- 5903: 218
- 8333: 187
- 5901: 111
- TCP/22: 142
- 1433: 88
- 5905: 75
- 5904: 73
- 27017: 57
- 25: 51
- TCP/1433: 45
- 5909: 49
- 5908: 47
- 2053: 36
- 9200: 20

***Most Common CVEs***

- CVE-2005-4050: 1331
- CVE-2002-0013 CVE-2002-0012: 15
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2013-7471 CVE-2013-7471: 1

***Commands Attempted by Attackers***

- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 31
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 30
- `lockr -ia .ssh`: 30
- `cat /proc/cpuinfo | grep name | wc -l`: 15
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 15
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 15
- `ls -lh $(which ls)`: 15
- `which ls`: 15
- `crontab -l`: 15
- `w`: 15
- `uname -m`: 15
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 15
- `top`: 15
- `uname`: 15
- `uname -a`: 15
- `whoami`: 15
- `lscpu | grep Model`: 15
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 15
- `Enter new UNIX password: `: 11
- `Enter new UNIX password:`: 11
- `rm -rf /data/local/tmp/*`: 4
- `pm path com.ufo.miner`: 2
- `pm install /data/local/tmp/ufo.apk`: 2
- `rm -f /data/local/tmp/ufo.apk`: 2
- `am start -n com.ufo.miner/com.example.test.MainActivity`: 2

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1070
- 2024766: 1070
- ET VOIP MultiTech SIP UDP Overflow: 1331
- 2003237: 1331
- ET DROP Dshield Block Listed Source group 1: 474
- 2402000: 474
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 287
- 2023753: 287
- ET SCAN NMAP -sS window 1024: 167
- 2009582: 167
- ET SCAN Potential SSH Scan: 130
- 2001219: 130
- ET HUNTING RDP Authentication Bypass Attempt: 112
- 2034857: 112
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN Suspicious inbound to MSSQL port 1433: 42
- 2010935: 42

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 31
- /Passw0rd: 26
- /passw0rd: 17
- default/default2018: 8
- blank/4444: 6
- /1q2w3e4r: 14
- root/Admin123*: 5
- root/qweqwe@123: 5
- root1/3245gs5662d34: 4
- root/ABCabc123.: 4
- /qwertyui: 7
- www/www: 4
- angie/123: 4
- seven/seven: 3
- root/4siwip: 3
- git/123456789: 3
- git/git: 3
- guest/guest: 3
- kdm/kdm: 3
- ociisstd/ociisstd: 3

***Files Uploaded/Downloaded***

- Mozi.m: 5
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- ): 1

***HTTP User-Agents***

- No HTTP user-agents were recorded in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- The attacker with IP `185.243.96.105` was consistently the most active across all three logging periods, indicating a persistent and possibly automated attack campaign against VNC services.
- A common command executed by attackers involves adding a specific SSH public key to the `authorized_keys` file. This is a clear attempt to establish persistent access to the compromised system.
- The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signatures suggests that many of the attacks targeting SMB services are related to the EternalBlue/DoublePulsar exploit, which remains a prevalent threat.
- There is a noticeable amount of scanning and attack activity targeting VoIP (SIP) and MSSQL services, in addition to the more common SSH and VNC targets.
- Several commands related to Android (e.g., `pm install /data/local/tmp/ufo.apk`) were observed, suggesting that the Adbhoney honeypot is attracting targeted attacks.