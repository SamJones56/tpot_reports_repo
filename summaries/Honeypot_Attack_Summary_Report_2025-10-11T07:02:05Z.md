Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T07:01:37Z
**Timeframe:** 2025-10-11T06:20:01Z to 2025-10-11T07:00:01Z
**Files Used:**
- agg_log_20251011T062001Z.json
- agg_log_20251011T064001Z.json
- agg_log_20251011T070001Z.json

**Executive Summary**

This report summarizes 15,960 attacks recorded by the honeypot network over a period of approximately 40 minutes. The majority of attacks were SSH brute-force attempts, with a significant number of scans for open ports and known vulnerabilities. The most active honeypots were Cowrie, Honeytrap, and Suricata. A notable increase in activity targeting port 25 (SMTP) was observed in the last 20 minutes of this reporting period.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 6041
- Honeytrap: 3898
- Suricata: 2543
- Ciscoasa: 1870
- Mailoney: 859
- Sentrypeer: 429
- Tanner: 163
- Dionaea: 58
- H0neytr4p: 32
- ElasticPot: 25
- Adbhoney: 16
- ConPot: 11
- Redishoneypot: 9
- Medpot: 3
- Wordpot: 2
- Honeyaml: 1

***Top Attacking IPs:***
- 176.65.141.117
- 216.9.225.39
- 88.214.50.58
- 171.80.10.125
- 161.132.68.222
- 4.213.160.153
- 205.185.127.60
- 88.210.63.16
- 159.223.16.184
- 103.210.22.17

***Top Targeted Ports/Protocols:***
- 25
- 22
- 5060
- UDP/5060
- 1181
- 5903
- 80
- 8333
- 5901

***Most Common CVEs:***
- CVE-2022-27255
- CVE-2019-11500
- CVE-2021-3449
- CVE-2024-40891

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

***Signatures Triggered:***
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Sipsak SIP scan
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 48

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/nPSpP4PBW0
- root/LeitboGi0ro
- root/3245gs5662d34
- blank/1q2w3e4r
- default/Default2014
- admin/administrator
- Pa$$w0rd
- me/1234

***Files Uploaded/Downloaded:***
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

***HTTP User-Agents:***
- No HTTP user agents were logged in this period.

***SSH Clients:***
- No specific SSH clients were logged in this period.

***SSH Servers:***
- No specific SSH servers were logged in this period.

***Top Attacker AS Organizations:***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A significant number of commands executed by attackers are related to reconnaissance and establishing persistence, such as enumerating system information and modifying SSH authorized_keys.
- The presence of `urbotnetisass` malware downloads indicates a campaign targeting IoT devices.
- The high number of login attempts with the username/password `345gs5662d34/345gs5662d34` suggests a targeted brute-force campaign.
- The spike in SMTP traffic on port 25, primarily from the IP `176.65.141.117`, is a notable anomaly in this reporting period, suggesting a potential spam or mail-based attack campaign.
