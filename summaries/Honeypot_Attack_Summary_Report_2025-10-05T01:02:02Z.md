Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T01:01:37Z
**Timeframe:** 2025-10-05T00:20:02Z - 2025-10-05T01:00:01Z
**Files Used:**
- agg_log_20251005T002002Z.json
- agg_log_20251005T004001Z.json
- agg_log_20251005T010001Z.json

**Executive Summary**

This report summarizes 12,165 attacks recorded by our honeypot network. The majority of attacks were SSH brute-force attempts and scans on port 25 (SMTP) and port 445 (SMB). The most active attacker IP was 86.54.42.238. A number of known vulnerabilities were exploited, including CVE-2005-4050. The most common commands executed by attackers involved reconnaissance and establishing persistence by adding SSH keys to `authorized_keys`.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 5438
- Mailoney: 2467
- Ciscoasa: 1550
- Suricata: 962
- Dionaea: 689
- Sentrypeer: 580
- Honeytrap: 256
- Heralding: 43
- H0neytr4p: 77
- Tanner: 28
- ElasticPot: 20
- Honeyaml: 20
- Miniprint: 12
- ConPot: 7
- Dicompot: 4
- Adbhoney: 4
- Ipphoney: 3
- Redishoneypot: 2

***Top Attacking IPs:***
- 86.54.42.238: 1642
- 176.65.141.117: 820
- 111.68.104.76: 400
- 61.219.181.31: 458
- 117.102.100.58: 429
- 103.210.21.178: 403
- 161.49.118.82: 365
- 36.95.221.140: 361
- 14.225.213.188: 350
- 172.86.95.98: 360
- 14.225.205.58: 395
- 103.186.1.120: 350
- 114.47.6.50: 251
- 91.237.163.112: 322
- 46.253.45.10: 288
- 171.104.143.176: 273
- 211.20.14.156: 246
- 115.190.95.198: 130
- 114.132.216.145: 134
- 210.79.190.46: 133

***Top Targeted Ports/Protocols:***
- 25: 2470
- 445: 639
- 22: 644
- 5060: 580
- 443: 77
- 1433: 28
- 80: 38
- vnc/5900: 43
- 9200: 18
- TCP/1433: 41
- 23: 20

***Most Common CVEs:***
- CVE-2005-4050: 36
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-1999-0183: 1
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2001-0414: 1
- CVE-2023-26801 CVE-2023-26801: 1

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 44
- `lockr -ia .ssh`: 44
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 44
- `cat /proc/cpuinfo | grep name | wc -l`: 43
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 43
- `ls -lh $(which ls)`: 43
- `which ls`: 43
- `crontab -l`: 43
- `w`: 41
- `uname -m`: 41
- `uname -a`: 41
- `whoami`: 41
- `lscpu | grep Model`: 41
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 41
- `Enter new UNIX password: `: 32
- `Enter new UNIX password:`: 32

***Signatures Triggered:***
- ET DROP Dshield Block Listed Source group 1: 287
- 2402000: 287
- ET SCAN NMAP -sS window 1024: 102
- 2009582: 102
- ET INFO Reserved Internal IP Traffic: 48
- 2002752: 48
- ET SCAN Suspicious inbound to MSSQL port 1433: 36
- 2010935: 36
- ET VOIP MultiTech SIP UDP Overflow: 36
- 2003237: 36
- ET INFO VNC Authentication Failure: 42
- 2002920: 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 25
- 2403349: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 20
- 2403345: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 21
- 2403342: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 14
- 2403350: 14

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34: 41
- novinhost/novinhost.org: 13
- root/3245gs5662d34: 11
- novinhost/3245gs5662d34: 10
- root/nPSpP4PBW0: 12
- test/zhbjETuyMffoL8F: 6
- root/2glehe5t24th1issZs: 6
- root/Abcd@12345: 4
- root/zhbjETuyMffoL8F: 4
- ftp-user/ftp-user: 5
- scanner/scanner123: 3

***Files Uploaded/Downloaded:***
- None

***HTTP User-Agents:***
- None

***SSH Clients:***
- None

***SSH Servers:***
- None

***Top Attacker AS Organizations:***
- None

**Key Observations and Anomalies**

- A significant amount of scanning activity originated from the IP address 86.54.42.238, primarily targeting SMTP.
- The majority of commands executed post-compromise are focused on reconnaissance and establishing persistent access through SSH keys.
- There is a noticeable amount of scanning for MSSQL (port 1433) and VNC (port 5900).
- No successful file transfers were observed.
- The list of CVEs indicates that attackers are still attempting to exploit old and well-known vulnerabilities.

This concludes the Honeypot Attack Summary Report.