Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T10:01:25Z
**Timeframe:** 2025-10-17T09:20:01Z to 2025-10-17T10:00:01Z
**Files Used:** `agg_log_20251017T092001Z.json`, `agg_log_20251017T094001Z.json`, `agg_log_20251017T100001Z.json`

### Executive Summary

This report summarizes 27,159 events collected from the honeypot network over a period of approximately 40 minutes. The majority of the activity was detected by the Sentrypeer honeypot, with a significant amount of traffic targeting port 5060 (SIP). The most prominent attacking IP address was `2.57.121.61`. A number of common vulnerabilities were scanned for, and attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot**
* Sentrypeer: 15888
* Cowrie: 5268
* Honeytrap: 2104
* Mailoney: 864
* Suricata: 1038
* Ciscoasa: 1004
* Dionaea: 710
* Tanner: 122
* H0neytr4p: 68
* Wordpot: 48
* ConPot: 11
* Honeyaml: 12
* Adbhoney: 11
* ElasticPot: 4
* Ipphoney: 1
* Redishoneypot: 6

**Top Attacking IPs**
* 2.57.121.61: 15097
* 77.90.185.47: 1607
* 183.110.116.126: 441
* 172.86.95.115: 302
* 172.86.95.98: 291
* 196.251.80.29: 266
* 209.74.89.175: 203
* 189.194.140.170: 208
* 202.152.201.166: 182
* 45.7.171.18: 228
* 193.32.179.61: 213
* 91.107.118.186: 213
* 103.165.236.27: 184
* 107.170.36.5: 156
* 181.210.8.69: 154
* 185.255.91.50: 149
* 27.254.192.185: 140
* 162.214.211.246: 134
* 103.139.192.221: 119
* 115.231.10.56: 113

**Top Targeted Ports/Protocols**
* 5060: 15888
* 22: 777
* 25: 864
* 80: 174
* 445: 186
* TCP/21: 146
* 5903: 141
* 8333: 124
* 5901: 75
* 21: 72
* 443: 54
* 5904: 48
* 5905: 47
* 23: 36
* 1028: 24
* UDP/161: 22
* 5908: 31
* 5909: 30
* 5907: 13
* 8025: 13

**Most Common CVEs**
* CVE-2002-0013 CVE-2002-0012: 13
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
* CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
* CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 1
* CVE-2001-0414: 1
* CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1

**Commands Attempted by Attackers**
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 23
* lockr -ia .ssh: 23
* cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 23
* cat /proc/cpuinfo | grep name | wc -l: 23
* Enter new UNIX password: : 22
* Enter new UNIX password:": 22
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 23
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 23
* ls -lh $(which ls): 23
* which ls: 23
* crontab -l: 23
* w: 23
* uname -m: 23
* cat /proc/cpuinfo | grep model | grep name | wc -l: 23
* top: 23
* uname: 23
* uname -a: 23
* whoami: 23
* lscpu | grep Model: 23
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 23

**Signatures Triggered**
* ET DROP Dshield Block Listed Source group 1: 251
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 96
* ET SCAN NMAP -sS window 1024: 93
* ET FTP FTP PWD command attempt without login: 71
* ET FTP FTP CWD command attempt without login: 71
* ET INFO Reserved Internal IP Traffic: 36
* ET INFO CURL User Agent: 32
* ET COMPROMISED Known Compromised or Hostile Host Traffic group 10: 13
* ET CINS Active Threat Intelligence Poor Reputation IP group 46: 12
* GPL SNMP request udp: 11
* ET CINS Active Threat Intelligence Poor Reputation IP group 51: 9
* ET CINS Active Threat Intelligence Poor Reputation IP group 52: 9
* ET SCAN Suspicious inbound to PostgreSQL port 5432: 8
* ET VOIP REGISTER Message Flood UDP: 2
* ET HUNTING RDP Authentication Bypass Attempt: 2
* ET CINS Active Threat Intelligence Poor Reputation IP group 48: 1
* ET CINS Active Threat Intelligence Poor Reputation IP group 50: 1

**Users / Login Attempts**
* 345gs5662d34/345gs5662d34: 23
* centos/888888: 6
* centos/112233: 6
* root/123@Robert: 5
* ftpuser/ftppassword: 8
* operator/operator2016: 4
* supervisor/supervisor2006: 4
* debian/qwer1234: 4
* default/default1234: 4
* admin/123qwe: 3
* deploy/1111: 3
* sana/sana123: 3
* root/Ph@123456: 3
* server/server1: 3
* root/115003: 3
* school/123: 3
* ftpuser/3245gs5662d34: 3
* root/116288jhr: 4
* nadia/123: 2
* integra/123: 2

**Files Uploaded/Downloaded**
* 34.165.197.224:8088: 2
* apply.cgi: 2
* Mozi.m: 1

**HTTP User-Agents**
* No data

**SSH Clients**
* No data

**SSH Servers**
* No data

**Top Attacker AS Organizations**
* No data

### Key Observations and Anomalies

*   The overwhelming majority of traffic was directed at port 5060, indicating a large-scale, automated campaign targeting SIP services, likely for VoIP abuse or toll fraud.
*   The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was consistently used, suggesting a coordinated effort to inject a specific SSH key for persistent access. The "mdrfckr" comment in the key is a notable identifier.
*   The variety of CVEs scanned for, though low in number, indicates that some attackers are still attempting to exploit older, well-known vulnerabilities.
*   The file `Mozi.m` was downloaded, which is associated with the Mozi botnet, a P2P botnet that primarily targets IoT devices. This suggests that the honeypot was targeted by this botnet.
