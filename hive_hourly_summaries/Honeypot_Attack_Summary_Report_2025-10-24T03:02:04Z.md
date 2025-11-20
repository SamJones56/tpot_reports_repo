Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T03:01:39Z
**Timeframe:** 2025-10-24T02:20:01Z to 2025-10-24T03:00:01Z
**Log Files:**
- agg_log_20251024T022001Z.json
- agg_log_20251024T024001Z.json
- agg_log_20251024T030001Z.json

**Executive Summary**

This report summarizes 16,888 events collected from the honeypot network. The majority of attacks were captured by the Sentrypeer honeypot, indicating a high volume of SIP/VoIP-related scanning. A significant number of SSH brute-force attempts and SMB exploit attempts were also observed. The most prominent attacking IP was 2.57.121.61, which was responsible for over 8,000 events.

**Detailed Analysis**

***Attacks by Honeypot***
- Sentrypeer: 8,363
- Cowrie: 3,305
- Suricata: 2,109
- Ciscoasa: 1,498
- Honeytrap: 1,482
- Dionaea: 45
- Mailoney: 17
- Redishoneypot: 14
- Honeyaml: 13
- Tanner: 11
- H0neytr4p: 10
- ConPot: 8
- Miniprint: 8
- Heralding: 3
- ElasticPot: 2

***Top Attacking IPs***
- 2.57.121.61: 8,263
- 113.190.197.158: 1,448
- 61.219.181.31: 399
- 103.186.1.197: 394
- 80.94.95.238: 373
- 103.183.75.228: 346
- 45.64.112.160: 283
- 77.82.84.12: 258
- 152.32.218.149: 163
- 180.138.194.82: 145

***Top Targeted Ports/Protocols***
- 5060: 8,363
- TCP/445: 1,456
- 22: 391
- 8333: 126
- 2056: 78
- 5904: 66
- 5905: 65
- TCP/22: 12

***Most Common CVEs***
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

***Commands Attempted by Attackers***
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 50

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- b/1
- colin/colin
- root/Kg123456
- hiroshi/hiroshi
- root/test123321
- firefart/firefart

***Files Uploaded/Downloaded***
- login.aspx
- 129.212.146.61:8081
- default.aspx
- k.php?a=x86_64,EYF500S1J5ZK9H8AH

***HTTP User-Agents***
- None observed

***SSH Clients and Servers***
- None observed

***Top Attacker AS Organizations***
- None observed

**Key Observations and Anomalies**

- The overwhelming number of events from the Sentrypeer honeypot, specifically from the IP 2.57.121.61, suggests a large-scale, automated scanning operation targeting SIP services.
- A significant number of commands are related to establishing persistent SSH access by adding a public key to `authorized_keys`.
- The Suricata signature for the DoublePulsar backdoor was triggered numerous times, indicating attempts to exploit the EternalBlue vulnerability.
- An attempt to download a malicious payload (`k.php`) was observed, which is likely a script for further exploitation.
- The variety of credentials used in brute-force attacks indicates that attackers are using common and default password lists.
- The commands for gathering system information (`uname`, `lscpu`, `free`, etc.) are typical post-exploitation commands used to understand the compromised environment.
