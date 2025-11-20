Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T00:01:30Z
**Timeframe of Analysis:** 2025-10-18T23:20:01Z to 2025-10-19T00:00:01Z
**Log Files Used:**
- agg_log_20251018T232001Z.json
- agg_log_20251018T234001Z.json
- agg_log_20251019T000001Z.json

**Executive Summary**

This report summarizes 18,765 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and command execution. A significant number of attacks targeted VoIP services, as evidenced by the high count of events on port 5060 and the prevalence of the 'ET VOIP MultiTech SIP UDP Overflow' signature. Attackers were observed attempting to manipulate SSH authorized_keys files and perform system reconnaissance. The most frequently observed CVE was CVE-2005-4050.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 9366
- Suricata: 2863
- Honeytrap: 2999
- Sentrypeer: 2063
- Ciscoasa: 1236
- Dionaea: 64
- Tanner: 47
- Redishoneypot: 29
- H0neytr4p: 26
- Mailoney: 20
- ConPot: 20
- Honeyaml: 13
- ElasticPot: 5
- Adbhoney: 4
- Dicompot: 4
- Heralding: 6

***Top Attacking IPs***
- 134.199.193.147: 999
- 196.251.88.103: 1001
- 72.146.232.13: 1212
- 198.23.190.58: 1197
- 23.94.26.58: 1154
- 194.50.16.73: 989
- 198.12.68.114: 842
- 167.172.130.181: 288
- 103.82.37.34: 248
- 115.190.76.77: 203
- 182.93.50.90: 203
- 14.103.249.172: 184
- 103.154.111.3: 184
- 107.170.36.5: 167

***Top Targeted Ports/Protocols***
- 5060: 2063
- 22: 1767
- UDP/5060: 1384
- 5903: 225
- 8333: 192
- 5901: 116
- 5905: 77
- 5904: 77
- TCP/22: 68
- 5909: 51
- 5907: 50
- 5908: 48
- 80: 41
- 6379: 29

***Most Common CVEs***
- CVE-2005-4050: 1369
- CVE-2010-0569: 2
- CVE-2001-0414: 4
- CVE-1999-0183: 3
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2019-11500 CVE-2019-11500: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 36
- lockr -ia .ssh: 36
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 36
- cat /proc/cpuinfo | grep name | wc -l: 36
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 36
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 36
- uname -a: 37
- whoami: 36
- top: 36
- uname: 36
- lscpu | grep Model: 36
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 36
- ls -lh $(which ls): 35
- which ls: 35
- crontab -l: 35
- w: 35
- uname -m: 35
- cat /proc/cpuinfo | grep model | grep name | wc -l: 35
- Enter new UNIX password: : 29
- Enter new UNIX password:": 29

***Signatures Triggered***
- ET VOIP MultiTech SIP UDP Overflow: 1369
- ET DROP Dshield Block Listed Source group 1: 387
- ET SCAN NMAP -sS window 1024: 171
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 169
- ET INFO Reserved Internal IP Traffic: 56
- ET SCAN Potential SSH Scan: 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 34
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 29

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 35
- root/Qaz123qaz: 12
- guest/33: 6
- centos/centos2020: 6
- root/3245gs5662d34: 5
- guest/guest2019: 4
- operator/operator123456: 4
- support/777: 4
- root/3lastix: 4
- root/3l4st.2014: 4
- operator/operator11: 4
- config/config55: 4
- root/root2022: 4
- root/3l4st1x.23: 4

***Files Uploaded/Downloaded***
- 11: 2
- fonts.gstatic.com: 2
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 2
- ie8.css?ver=1.0: 2
- html5.js?ver=3.7.3: 2

***HTTP User-Agents***
- No data available

***SSH Clients***
- No data available

***SSH Servers***
- No data available

***Top Attacker AS Organizations***
- No data available

**Key Observations and Anomalies**

- A high concentration of attacks originates from a relatively small number of IP addresses, suggesting targeted or persistent attackers.
- The overwhelming number of Cowrie events points to a focus on compromising devices via SSH/Telnet, likely to expand botnets.
- The repeated use of commands to remove and replace SSH authorized keys is a clear indicator of attempts to maintain persistent access to compromised systems.
- The consistent triggering of 'ET VOIP MultiTech SIP UDP Overflow' suggests a widespread, automated campaign against VoIP infrastructure.
- The variety of credentials used indicates dictionary attacks using common or previously breached usernames and passwords.
