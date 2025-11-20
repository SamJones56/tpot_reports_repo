Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T16:01:38Z
**Timeframe:** 2025-10-10T15:20:01Z to 2025-10-10T16:00:01Z
**Files Used:**
- agg_log_20251010T152001Z.json
- agg_log_20251010T154001Z.json
- agg_log_20251010T160001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 13,279 attacks were recorded, with a significant focus on SSH and other remote access protocols. The Cowrie honeypot was the most frequently targeted. A wide range of attack vectors were observed, including brute-force login attempts, execution of reconnaissance commands, and attempts to exploit known vulnerabilities.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 7012
- Honeytrap: 2403
- Suricata: 1866
- Ciscoasa: 1755
- Redishoneypot: 34
- Dionaea: 38
- Sentrypeer: 39
- Mailoney: 38
- Tanner: 32
- H0neytr4p: 24
- ElasticPot: 7
- Adbhoney: 17
- Honeyaml: 5
- ConPot: 4
- Dicompot: 4
- Ipphoney: 1

***Top Attacking IPs***

- 51.89.1.87: 1250
- 103.122.61.254: 945
- 167.250.224.25: 716
- 103.165.218.190: 257
- 103.55.36.22: 252
- 88.210.63.16: 243
- 172.174.72.225: 233
- 125.31.2.160: 274
- 185.39.19.40: 265
- 156.227.235.133: 203

***Top Targeted Ports/Protocols***

- 22: 970
- TCP/1080: 354
- 5903: 187
- 8333: 97
- 5909: 83
- 5908: 81
- 5901: 72
- 23: 53
- 6379: 34
- 25: 38

***Most Common CVEs***

- CVE-2005-4050
- CVE-2022-27255
- CVE-2021-35394
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

***Commands Attempted by Attackers***

- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- tftp; wget; /bin/busybox KBIUO
- chmod
- echo -ne ... >>./categumh

***Signatures Triggered***

- GPL INFO SOCKS Proxy attempt
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 67
- ET SCAN Potential SSH Scan
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 68

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- root/!ZXC1234
- root/.ZXC1234
- support/test12345
- root/ZXC12345
- ubnt/8888
- root/avonline
- admin/Admin123!
- operator/66666
- daniel/daniel!

***Files Uploaded/Downloaded***

- wget.sh;
- w.sh;
- c.sh;
- mips.nn;

***HTTP User-Agents***

- No HTTP user agents were recorded in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were recorded in this period.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- A high volume of attacks originated from a small number of IP addresses, suggesting targeted campaigns or botnet activity.
- The most common commands executed by attackers are typical reconnaissance commands used to gather system information.
- The presence of commands attempting to modify SSH authorized_keys files indicates attempts to establish persistent access.
- The `echo -ne` commands suggest attempts to write binary payloads to the system.
- The variety of honeypots triggered indicates a broad spectrum of scanning and exploitation attempts against different services.
