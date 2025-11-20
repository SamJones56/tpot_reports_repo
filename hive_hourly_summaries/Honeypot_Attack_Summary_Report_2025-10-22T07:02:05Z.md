Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T07:01:28Z
**Timeframe:** 2025-10-22T06:20:01Z to 2025-10-22T07:00:02Z
**Files Used:**
- agg_log_20251022T062001Z.json
- agg_log_20251022T064001Z.json
- agg_log_20251022T070002Z.json

**Executive Summary**

This report summarizes 29,990 events collected from the honeypot network. The majority of attacks were detected by the Suricata, Cowrie, and Heralding honeypots. The most prominent attack vector was VNC authentication attempts, reflected in the high count of events on port 5900. A significant number of SSH-based attacks were also observed, with attackers attempting various commands to gather system information and install unauthorized SSH keys.

**Detailed Analysis**

***Attacks by Honeypot***

- Suricata: 9512
- Cowrie: 9503
- Heralding: 4766
- Honeytrap: 3706
- Ciscoasa: 1672
- Dionaea: 253
- Sentrypeer: 265
- Redishoneypot: 104
- Mailoney: 113
- ConPot: 48
- Tanner: 22
- ElasticPot: 8
- Miniprint: 6
- H0neytr4p: 7
- Adbhoney: 2
- Wordpot: 2
- Honeyaml: 1

***Top Attacking IPs***

- 111.175.37.46: 4804
- 10.208.0.3: 4767
- 185.243.96.105: 4767
- 49.204.24.36: 1398
- 119.93.41.106: 1198
- 88.214.50.58: 381
- 67.220.72.53: 351
- 103.140.73.162: 311
- 185.255.91.28: 341
- 213.222.164.230: 273
- 88.210.63.16: 239
- 107.170.36.5: 234
- 182.117.144.122: 260
- 159.203.46.134: 208
- 202.10.40.65: 214
- 107.175.209.254: 193
- 176.98.178.211: 194
- 185.116.160.35: 189
- 186.13.24.118: 164
- 103.165.218.190: 162

***Top Targeted Ports/Protocols***

- vnc/5900: 4766
- 22: 1653
- TCP/445: 2596
- 5060: 265
- 5903: 211
- TCP/1433: 149
- 1433: 141
- 8333: 146
- 445: 56
- 6379: 99
- 25: 113
- 5901: 106
- 5904: 72
- 5905: 73
- TCP/22: 55

***Most Common CVEs***

- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2025-34036
- CVE-2021-3449
- CVE-1999-0517

***Commands Attempted by Attackers***

- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...
- Enter new UNIX password:
- chmod +x clean.sh; sh clean.sh; rm -rf clean.sh; ...

***Signatures Triggered***

- ET INFO VNC Authentication Failure
- 2002920
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN Potential SSH Scan
- 2001219
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- 2403348
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- 2403347

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- /Passw0rd
- /1q2w3e4r
- odin/odin
- /1qaz2wsx
- /passw0rd
- root/Bcg2014!
- root/3245gs5662d34
- sa/
- sa/1qaz2wsx

***Files Uploaded/Downloaded***

- string.js
- SOAP-ENV:Envelope>
- 11
- fonts.gstatic.com

***HTTP User-Agents***

- None observed in this period.

***SSH Clients and Servers***

- No specific SSH client or server software versions were logged.

***Top Attacker AS Organizations***

- No AS organization data was available in the logs.

**Key Observations and Anomalies**

- A high volume of VNC and SSH-related attacks suggests automated scanning and exploitation attempts targeting these services.
- Attackers are consistently attempting to install their own SSH keys for persistent access, as seen in the repeated use of commands modifying the `.ssh/authorized_keys` file.
- The presence of DoublePulsar-related signatures indicates that some attacks may be related to the exploitation of SMB vulnerabilities.
- A variety of system reconnaissance commands are being used, indicating that attackers are attempting to profile the compromised systems for further exploitation.
- Several CVEs were triggered, including older and more recent ones, showing a wide range of vulnerability scanning.
