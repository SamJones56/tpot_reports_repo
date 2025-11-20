Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T15:50:10Z
**Timeframe:** 2025-10-01T13:20:01Z to 2025-10-01T14:00:01Z
**Files Used:**
- agg_log_20251001T132001Z.json
- agg_log_20251001T134001Z.json
- agg_log_20251001T140001Z.json

**Executive Summary**
This report summarizes 28,885 events collected from the honeypot network over a 40-minute period. The majority of attacks were SIP scans targeting port 5060, primarily from IP address 92.205.59.208. A significant number of SSH brute-force attacks were also observed, with attackers attempting to gain access using common and default credentials. Multiple CVEs were targeted, and attackers attempted to download and execute malicious scripts after gaining access.

**Detailed Analysis**

***Attacks by Honeypot***
- Sentrypeer: 17,191
- Cowrie: 5,472
- Mailoney: 1,505
- Honeytrap: 1,478
- Suricata: 1,254
- Ciscoasa: 1,231
- Dionaea: 490
- Miniprint: 64
- ConPot: 54
- Tanner: 38
- Adbhoney: 27
- H0neytr4p: 25
- Honeyaml: 18
- Dicompot: 12
- Redishoneypot: 9
- ssh-rsa: 8
- ElasticPot: 5
- Ipphoney: 4

***Top Attacking IPs***
- 92.205.59.208: 12,245
- 15.235.37.85: 5,031
- 92.242.166.161: 822
- 86.54.42.238: 682
- 118.70.150.110: 448
- 79.137.72.26: 416
- 185.156.73.167: 320
- 185.156.73.166: 314
- 92.63.197.55: 314
- 120.48.43.176: 300
- 106.13.181.42: 264

***Top Targeted Ports/Protocols***
- 5060: 17,191
- 25: 1,503
- 22: 661
- 445: 448
- 8333: 111
- UDP/5060: 98
- 9100: 64
- TCP/22: 63
- 80: 42
- 23: 44
- TCP/80: 38

***Most Common CVEs***
- CVE-2002-0013, CVE-2002-0012
- CVE-2001-0414
- CVE-2023-26801

***Commands Attempted by Attackers***
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem
- crontab -l
- whoami
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET VOIP REGISTER Message Flood UDP
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/2glehe5t24th1issZs
- root/3245gs5662d34
- root/LeitboGi0ro
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- superadmin/admin123
- root/

***Files Uploaded/Downloaded***
- wget.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- w.sh
- c.sh
- discovery
- soap-envelope

***HTTP User-Agents***
- No HTTP user-agents were logged in this period.

***SSH Clients and Servers***
- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**
- The overwhelming majority of traffic is SIP-based, originating from a single IP, suggesting a coordinated scan or attack.
- A recurring pattern of commands indicates attackers are attempting to secure their access by adding their own SSH key to `authorized_keys` and removing other users' access.
- The attackers are attempting to download and execute scripts for various architectures (ARM, x86, MIPS), indicating an attempt to compromise a wide range of IoT and embedded devices.
- Several signatures for well-known scanning tools and blocklisted IPs were triggered, indicating that the attacks are not sophisticated and are likely automated.
- The presence of commands to remove security scripts (`secure.sh`, `auth.sh`) suggests that attackers are aware of common honeypot and security measures and are attempting to disable them.
