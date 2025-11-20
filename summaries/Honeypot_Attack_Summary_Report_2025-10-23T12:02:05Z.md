Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T12:01:46Z
**Timeframe:** 2025-10-23T11:20:01Z to 2025-10-23T12:00:02Z

**Files Used:**
- agg_log_20251023T112001Z.json
- agg_log_20251023T114002Z.json
- agg_log_20251023T120002Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three separate log files. A total of 16,858 events were recorded across various honeypots. The most targeted services were SSH (port 22) and services on port 5060. The IP address 109.205.211.9 was the most active attacker. A number of CVEs were targeted, with CVE-2021-3449 and CVE-2002-0012/13 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Honeytrap: 6393
- Cowrie: 4420
- Suricata: 3324
- Ciscoasa: 1694
- Sentrypeer: 697
- Dionaea: 110
- H0neytr4p: 58
- Redishoneypot: 40
- Tanner: 30
- Mailoney: 24
- ConPot: 20
- Miniprint: 12
- Honeyaml: 12
- Ipphoney: 11
- ElasticPot: 6
- Dicompot: 4
- Heralding: 3

***Top Attacking IPs***

- 109.205.211.9: 2202
- 157.245.67.217: 528
- 103.195.100.131: 258
- 107.170.36.5: 250
- 193.24.211.28: 212
- 185.243.5.146: 204
- 85.208.84.222: 181
- 46.191.141.152: 146
- 13.212.79.99: 134
- 202.51.214.98: 164
- 45.227.254.6: 108

***Top Targeted Ports/Protocols***

- 5060: 697
- 22: 640
- 1275: 90
- 1273: 90
- 1236: 88
- 1270: 91
- 1279: 90
- 1263: 90
- 1238: 90
- 1248: 90
- 1291: 90
- 1287: 90
- 1277: 88
- 1210: 82

***Most Common CVEs***

- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2010-0738
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- Enter new UNIX password:
- tftp; wget; /bin/busybox GKMFS

***Signatures Triggered***

- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 84
- ET CINS Active Threat Intelligence Poor Reputation IP group 3
- GPL INFO SOCKS Proxy attempt
- ET SCAN Potential SSH Scan

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- root/cirtsite
- root/cisadmin
- root/Cinta32121
- root/Cipi310709
- root/CircE.2013
- test/test123test
- cloudadmin/cloudadmin
- manager/qwe123
- proxy/123

***Files Uploaded/Downloaded***

- nse.html)

***HTTP User-Agents***

- No user agents recorded in this timeframe.

***SSH Clients and Servers***

- No specific SSH clients or servers recorded in this timeframe.

***Top Attacker AS Organizations***

- No AS organization data recorded in this timeframe.

**Key Observations and Anomalies**

- A significant amount of reconnaissance and automated attacks were observed, particularly targeting SSH and RDP services.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install persistent backdoors via SSH authorized keys.
- The presence of the command `tftp; wget; /bin/busybox GKMFS` suggests attempts to download and execute malicious payloads.
- The CVEs targeted are a mix of older and more recent vulnerabilities, indicating a broad-spectrum scanning approach by attackers.
- The high number of events from the IP address 109.205.211.9 suggests a targeted or persistent attacker.
