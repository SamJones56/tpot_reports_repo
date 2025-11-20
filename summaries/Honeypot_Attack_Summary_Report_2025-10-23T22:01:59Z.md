Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T22:01:36Z
**Timeframe:** 2025-10-23T21:20:01Z to 2025-10-23T22:00:01Z
**Files Used:**
- agg_log_20251023T212001Z.json
- agg_log_20251023T214001Z.json
- agg_log_20251023T220001Z.json

**Executive Summary**
This report summarizes 7,203 attacks recorded by the honeypot network. The most targeted honeypot was Cowrie, indicating a high volume of SSH and telnet-based attacks. A significant number of events were also logged by the Ciscoasa and Honeytrap honeypots. The primary attack vectors appear to be SSH brute-forcing and exploitation of VoIP vulnerabilities, with a notable number of scans detected by Suricata. The most frequent attackers originated from IPs `173.249.50.59` and `95.39.201.205`.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 2865
- Ciscoasa: 1775
- Honeytrap: 1309
- Suricata: 690
- Sentrypeer: 384
- H0neytr4p: 41
- Redishoneypot: 31
- Tanner: 23
- ConPot: 22
- Miniprint: 15
- Mailoney: 15
- Dionaea: 13
- ElasticPot: 5
- Adbhoney: 4
- Heralding: 4
- ssh-rsa: 4
- Ipphoney: 2
- Wordpot: 1

***Top Attacking IPs:***
- 173.249.50.59
- 95.39.201.205
- 13.212.79.99
- 181.188.172.6
- 152.32.134.231
- 43.139.190.91
- 41.94.88.49
- 107.170.36.5
- 185.243.5.146
- 80.94.95.238

***Top Targeted Ports/Protocols:***
- 5060 (UDP/TCP)
- 22 (TCP)
- 8333
- 5905
- 5904
- 443
- 6379
- TCP/5432
- 25
- 9100

***Most Common CVEs:***
- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAA... rckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`

***Signatures Triggered:***
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET VOIP MultiTech SIP UDP Overflow
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34
- monah/monah123
- micah/micah123
- ashleyb/ashleyb123
- rileyroo/rileyroo
- parola/parola
- chinga/chinga123
- hawker/hawker
- nida/nida
- carlota/carlota123

***Files Uploaded/Downloaded:***
- No file uploads or downloads were detected in this period.

***HTTP User-Agents:***
- No HTTP user agents were recorded in this period.

***SSH Clients and Servers:***
- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations:***
- No attacker AS organizations were identified in the logs.

**Key Observations and Anomalies**
- A recurring command sequence was observed across multiple SSH sessions, attempting to remove existing SSH keys, add a new authorized key, and modify file attributes. This suggests a coordinated campaign to maintain persistent access to compromised systems.
- The high number of scans targeting port 5060 (SIP) and the triggering of the `ET VOIP MultiTech SIP UDP Overflow` signature point to a continued interest in exploiting VoIP-related vulnerabilities.
- The presence of `CVE-2005-4050` suggests that attackers are still attempting to exploit older, well-known vulnerabilities.
- A significant portion of the Suricata alerts are related to blocklisted IPs and network scans, indicating a large amount of automated reconnaissance activity.
