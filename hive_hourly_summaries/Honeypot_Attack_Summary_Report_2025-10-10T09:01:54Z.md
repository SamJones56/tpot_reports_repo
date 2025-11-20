
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T09:01:26Z
**Timeframe:** 2025-10-10T08:20:01Z to 2025-10-10T09:00:01Z
**Files Used:**
- agg_log_20251010T082001Z.json
- agg_log_20251010T084001Z.json
- agg_log_20251010T090001Z.json

## Executive Summary

This report summarizes 19,253 events collected from the honeypot network. The majority of attacks were detected by Suricata, Cowrie, and Honeytrap. The most frequent attacks targeted TCP/445, likely related to SMB exploits. A significant number of SSH login attempts and command executions were observed. The most notable CVEs are related to DoublePulsar and RDP vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot

- Suricata: 7675
- Cowrie: 5214
- Honeytrap: 3557
- Ciscoasa: 1710
- Dionaea: 535
- Sentrypeer: 346
- H0neytr4p: 58
- Redishoneypot: 43
- Tanner: 27
- Mailoney: 26
- ConPot: 13
- ElasticPot: 14
- Honeyaml: 12
- Miniprint: 10
- Dicompot: 6
- Heralding: 6
- Ipphoney: 1

### Top Attacking IPs

- 196.188.109.42: 1497
- 49.145.98.224: 1400
- 113.182.51.157: 1362
- 85.208.84.144: 1010
- 85.208.84.142: 1010
- 167.250.224.25: 961
- 103.163.113.150: 342
- 45.134.26.3: 321
- 138.124.182.117: 273
- 92.222.23.164: 270
- 154.201.70.16: 283
- 103.59.95.187: 263
- 103.31.38.141: 201
- 212.25.35.70: 172
- 88.210.63.16: 241
- 170.239.86.101: 209
- 147.50.231.135: 214
- 154.221.19.162: 152
- 193.24.123.88: 124
- 91.92.199.36: 105

### Top Targeted Ports/Protocols

- TCP/445: 4245
- 445: 374
- 22: 832
- 5060: 346
- 5903: 201
- TCP/1433: 122
- 1433: 115
- 5909: 80
- 5908: 71
- 5901: 73
- 443: 58
- 6379: 37
- 2181: 37
- 5907: 48
- 15672: 34
- 8333: 38
- 25: 17
- 23: 16
- 9090: 18
- 80: 22

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2022-27255 CVE-2022-27255
- CVE-2024-3721 CVE-2024-3721
- CVE-2016-20016 CVE-2016-20016

### Commands Attempted by Attackers

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- 2403342
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- 2403345
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- ubuntu/3245gs5662d34
- dixell/dixell
- Support/Support2016
- root/ZAQ1234@
- root/ZAQ1234!
- vpn/P@ssw0rd
- root/ZAQ1234.
- default/uploader
- root/ZAQ@1234
- root/ZAQ!1234
- root/ZAQ.1234
- root/@ZAQ1234
- root/!ZAQ1234
- root/.ZAQ1234
- root/ZAQ12345
- default/administrator
- supervisor/logon
- root/ZAQ12345@
- root/ZAQ12345!
- supervisor/supervisor0
- default/default123456
- admin/admin@123
- root/@ZAQ12345
- root/!ZAQ12345
- root/1a2s3d
- root/.ZAQ12345
- root/ZAQ123456
- root/ZAQ123456@
- default/qwerty12345
- root/ZAQ123456!
- root/ZAQ123456.
- root/ZAQ@123456
- root/ZAQ!123456
- root/ZAQ.123456
- root/@ZAQ123456
- root/!ZAQ123456
- root/.ZAQ123456
- root/ZAQ@2025
- root/ZAQ!2025
- unknown/77777
- root/ZAQ.2025
- root/@ZAQ2025
- root/!ZAQ2025
- operator/operator8
- root/.ZAQ2025
- root/ZAQ2024
- root/ZAQ2024@
- root/ZAQ2024!
- root/ZAQ2024.
- root/ZAQ@2024
- root/ZAQ!2024
- root/ZAQ.2024
- root/@ZAQ2024
- samurai/samurai
- default/default0
- root/!ZAQ2024
- root/.ZAQ2024

### Files Uploaded/Downloaded

- Mozi.a+varcron

### HTTP User-Agents

- None Observed

### SSH Clients

- None Observed

### SSH Servers

- None Observed

### Top Attacker AS Organizations

- None Observed

## Key Observations and Anomalies

- A large number of attacks are related to the DoublePulsar backdoor, indicating that attackers are still attempting to exploit this vulnerability.
- The high volume of traffic on TCP/445 suggests that SMB vulnerabilities are a primary target.
- The variety of usernames and passwords attempted, especially for the 'root' user, indicates widespread brute-force attacks.
- The commands executed by attackers are typical of initial reconnaissance and attempts to establish persistence, such as modifying SSH authorized_keys and checking system information.
- The `Mozi.a+varcron` file download is indicative of botnet activity.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organizations suggests that the attacks are primarily automated and may not be from sophisticated actors.
