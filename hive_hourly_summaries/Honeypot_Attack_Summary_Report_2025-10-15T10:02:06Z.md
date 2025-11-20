Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T10:01:40Z
**Timeframe of Analysis:** 2025-10-15T09:20:01Z to 2025-10-15T10:00:01Z
**Log Files Analyzed:**
- agg_log_20251015T092001Z.json
- agg_log_20251015T094001Z.json
- agg_log_20251015T100001Z.json

### Executive Summary

This report summarizes 19,802 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, Sentrypeer, and Suricata honeypots. Attackers primarily focused on exploiting vulnerabilities in SSH and SIP, with significant activity also targeting SMB services. A number of known CVEs were targeted, including CVE-2022-27255. A high volume of automated attacks were observed, characterized by repeated login attempts and the execution of malicious shell commands aimed at deploying malware and securing unauthorized access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 5271
- Honeytrap: 4228
- Sentrypeer: 3658
- Suricata: 3342
- Ciscoasa: 1741
- Mailoney: 860
- Dionaea: 440
- Heralding: 141
- Dicompot: 30
- Tanner: 27
- H0neytr4p: 23
- Adbhoney: 10
- Honeyaml: 12
- ElasticPot: 8
- Redishoneypot: 6
- ConPot: 5

**Top Attacking IPs:**
- 185.243.5.121: 1974
- 14.224.170.239: 1325
- 206.191.154.180: 1292
- 23.94.26.58: 1029
- 176.65.141.119: 821
- 196.251.88.103: 511
- 172.86.95.115: 461
- 62.141.43.183: 322
- 193.24.123.88: 326
- 103.57.64.214: 246
- 172.86.95.98: 178
- 173.212.238.152: 183
- 192.227.128.4: 172
- 146.190.144.138: 221
- 103.82.92.209: 220
- 40.82.214.8: 197
- 123.31.20.81: 197
- 197.5.145.8: 148
- 165.154.14.28: 151
- 45.134.26.47: 145

**Top Targeted Ports/Protocols:**
- 5060: 3658
- TCP/445: 1324
- 22: 832
- 25: 843
- UDP/5060: 589
- 1433: 271
- 8333: 160
- 5903: 189
- vnc/5900: 141
- 445: 114
- 5908: 83
- 5909: 83
- 5901: 73
- 23: 64
- 5907: 49
- TCP/1433: 68

**Most Common CVEs:**
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 38
- lockr -ia .ssh: 38
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 38
- free -m | grep Mem ...: 13
- ls -lh $(which ls): 13
- which ls: 13
- crontab -l: 13
- w: 13
- uname -m: 13
- cat /proc/cpuinfo | grep model | grep name | wc -l: 13
- top: 13
- uname: 13
- uname -a: 14
- whoami: 13
- lscpu | grep Model: 13
- df -h | head -n 2 ...: 13
- Enter new UNIX password: : 11
- Enter new UNIX password:": 11
- cat /proc/cpuinfo | grep name | wc -l: 12
- cat /proc/cpuinfo | grep name | head -n 1 ...: 12

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1323
- ET SCAN Sipsak SIP scan: 466
- ET DROP Dshield Block Listed Source group 1: 449
- ET SCAN NMAP -sS window 1024: 142
- ET INFO VNC Authentication Failure: 96
- ET SCAN Suspicious inbound to MSSQL port 1433: 57
- ET INFO Reserved Internal IP Traffic: 56
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 33
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 42
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 20
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 22

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 36
- root/Password@2025: 16
- root/Qaz123qaz: 17
- root/123@@@: 13
- debian/debian2013: 6
- root/root99: 6
- ftpuser/ftppassword: 5
- ftpuser/3245gs5662d34: 5
- centos/987654321: 5
- config/config2022: 5
- test/888: 4
- root/ugkhbcm: 4
- test/00000: 4
- root/mobilearts: 4
- debian/raspberry: 4
- root/poziom!@#: 4
- operator/123: 4
- root/zL727EUh: 4
- nobody/222222: 4
- sa/: 4
- root/285dda9e66c8: 4
- centos/888: 4

**Files Uploaded/Downloaded:**
- Mozi.m;: 2
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2
- 11: 1
- fonts.gstatic.com: 1
- css?family=Libre+Franklin...: 1
- ie8.css?ver=1.0: 1
- html5.js?ver=3.7.3: 1

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

### Key Observations and Anomalies

- **Consistent SSH brute-forcing:** A persistent set of commands involving the manipulation of the `.ssh/authorized_keys` file was observed across all log files, indicating a widespread and automated campaign to gain persistent SSH access.
- **Malware delivery attempts:** Multiple attempts to download and execute `urbotnetisass` payloads for various architectures (ARM, x86, MIPS) were recorded. This suggests a campaign to build a botnet.
- **SIP scanning:** A high volume of traffic on port 5060, flagged by Suricata as "ET SCAN Sipsak SIP scan", points to extensive scanning for vulnerable VoIP systems.
- **DoublePulsar activity:** The most frequently triggered signature was for the DoublePulsar backdoor, suggesting that attackers are still actively scanning for systems vulnerable to exploits associated with this tool.
