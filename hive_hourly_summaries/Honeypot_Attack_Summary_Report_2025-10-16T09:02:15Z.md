Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T09:01:23Z
**Timeframe:** 2025-10-16T08:20:01Z to 2025-10-16T09:00:01Z
**Files Used:**
- agg_log_20251016T082001Z.json
- agg_log_20251016T084001Z.json
- agg_log_20251016T090001Z.json

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing 25,367 events from three log files. The majority of attacks were captured by the Dionaea honeypot, with significant activity also observed on Suricata, Honeytrap, Sentrypeer, and Cowrie. The most targeted port was 445 (SMB), indicating a high volume of scanning for vulnerabilities related to Windows file sharing. A wide range of reconnaissance and exploitation commands were observed, including attempts to add SSH keys and gather system information.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Dionaea: 10204
- Suricata: 3321
- Honeytrap: 2971
- Cowrie: 2776
- Sentrypeer: 2602
- Heralding: 1630
- Ciscoasa: 1441
- H0neytr4p: 210
- Tanner: 70
- Mailoney: 38
- ConPot: 36
- Adbhoney: 34
- Redishoneypot: 21
- ElasticPot: 5
- Honeyaml: 4
- Dicompot: 4

**Top 10 Attacking IPs:**
- 31.27.211.170: 3133
- 125.163.32.197: 2035
- 180.241.210.77: 1940
- 45.134.26.47: 1644
- 172.31.36.128: 1420
- 14.97.11.58: 1200
- 78.188.37.174: 896
- 49.231.189.37: 892
- 23.94.26.58: 808
- 185.243.5.158: 474

**Top 10 Targeted Ports/Protocols:**
- 445: 10152
- 5060: 2602
- vnc/5900: 1630
- 443: 201
- TCP/5900: 351
- 22: 344
- 8333: 164
- 5903: 209
- UDP/5060: 40
- 23: 59

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Top 10 Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 17
- `lockr -ia .ssh`: 17
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 17
- `uname -a`: 16
- `cat /proc/cpuinfo | grep name | wc -l`: 15
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 15
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 15
- `ls -lh $(which ls)`: 15
- `which ls`: 15
- `crontab -l`: 15

**Top 10 Signatures Triggered:**
- ET INFO VNC Authentication Failure (2002920): 1596
- ET DROP Dshield Block Listed Source group 1 (2402000): 386
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42 (2400041): 204
- ET SCAN NMAP -sS window 1024 (2009582): 157
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41 (2400040): 152
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 95
- ET INFO Reserved Internal IP Traffic (2002752): 54
- ET SCAN Sipsak SIP scan (2008598): 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 43 (2403342): 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 46 (2403345): 10

**Top 10 Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 15
- User-Agent: Go-http-client/1.1/Connection: close: 12
- nobody/alpine: 6
- centos/p@ssw0rd: 6
- nobody/123321: 6
- support/logon: 6
- centos/111: 6
- root/3245gs5662d34: 5
- config/55: 4
- ftpuser/ftppassword: 4

**Files Uploaded/Downloaded:**
- sh: 98
- .i;: 3
- xhtml1-transitional.dtd: 1
- 19: 1
- ): 1
- json: 1

**Key Observations and Anomalies:**
- The high number of VNC authentication failures (Signature 2002920) and connections to `vnc/5900` suggests a coordinated campaign targeting VNC servers.
- The most common commands are related to reconnaissance and establishing persistence, such as gathering system information and adding SSH keys. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is particularly noteworthy for its attempt to overwrite existing SSH configurations.
- A significant number of attacks originate from a small number of IP addresses, with `31.27.211.170` being the most active.
- The targeting of port 445 (SMB) remains a prevalent threat, likely due to the continued existence of vulnerable systems.
- There are no observed attacks using common user agents, which could indicate the use of custom scripts or tools by attackers.
- No SSH client or server versions were exchanged in the observed sessions, suggesting that many connections were terminated before a full handshake could be completed.
