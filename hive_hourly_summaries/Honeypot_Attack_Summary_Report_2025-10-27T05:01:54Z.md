Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T05:01:27Z
**Timeframe:** 2025-10-27T04:20:01Z to 2025-10-27T05:00:01Z
**Files Analyzed:**
- agg_log_20251027T042001Z.json
- agg_log_20251027T044001Z.json
- agg_log_20251027T050001Z.json

**Executive Summary**

This report summarizes 16,603 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks targeted Cowrie, Sentrypeer, and Suricata honeypots. The most frequent attacks originated from IP address 198.23.190.58. Port 5060 (SIP) was the most targeted port. Several CVEs were detected, with CVE-2005-4050 being the most common. Attackers attempted various commands, including reconnaissance and efforts to install malware.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 3873
- Sentrypeer: 3613
- Suricata: 3331
- Honeytrap: 2767
- Ciscoasa: 1912
- Dionaea: 714
- Adbhoney: 90
- Tanner: 79
- Mailoney: 115
- ConPot: 59
- ElasticPot: 14
- H0neytr4p: 9
- Heralding: 16
- Redishoneypot: 7
- Honeyaml: 4

***Top Attacking IPs***
- 198.23.190.58: 2306
- 144.172.108.231: 1174
- 160.22.87.9: 532
- 185.243.5.148: 492
- 134.122.60.171: 333
- 110.49.3.18: 322
- 185.243.5.158: 363
- 103.45.234.227: 242
- 69.63.77.146: 285
- 107.170.36.5: 255
- 193.24.211.28: 225
- 139.59.24.22: 239
- 88.210.63.16: 157
- 45.119.81.249: 168

***Top Targeted Ports/Protocols***
- 5060: 3613
- 445: 568
- TCP/445: 528
- UDP/5060: 777
- 22: 564
- 80: 66
- 5903: 130
- 5901: 116
- 25: 115

***Most Common CVEs***
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2021-3449
- CVE-1999-0517
- CVE-1999-0183
- CVE-2016-20016
- CVE-2005-3296
- CVE-2025-34036

***Commands Attempted by Attackers***
- Basic reconnaissance commands (uname -a, whoami, lscpu)
- Attempts to download and execute malicious scripts (wget, curl)
- Modification of SSH authorized_keys
- Clearing of logs and security measures (rm -rf /tmp/secure.sh)

***Signatures Triggered***
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET EXPLOIP [PTsecurity] DoublePulsar Backdoor installation communication
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic

***Users / Login Attempts***
- root
- 345gs5662d34
- ubuntu
- bash
- admin
- test
- jla

***Files Uploaded/Downloaded***
- wget.sh
- w.sh
- c.sh
- arm.uhavenobotsxd
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd
- string.js

***HTTP User-Agents***
- No HTTP User-Agents were logged in this period.

***SSH Clients and Servers***
- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A significant number of attacks focused on reconnaissance, suggesting automated scanning tools are widely in use.
- The high volume of attacks on port 5060 (SIP) indicates a continued focus on exploiting VoIP systems.
- The presence of commands aimed at modifying SSH keys highlights the risk of attackers attempting to maintain persistent access.
- The `DoublePulsar` signature indicates attempts to use a known NSA-leaked exploit, showing that old vulnerabilities are still being actively targeted.
- The variety of downloaded files with different architectures (ARM, x86, MIPS) suggests that attackers are attempting to compromise a wide range of IoT and embedded devices.
- A notable command `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;` was observed, indicating an attempt to remove competing malware or security scripts.
- The CVE `CVE-2025-34036` is an anomaly, as it appears to be a CVE for a future year. This may be a malformed log entry or a test by a security researcher.