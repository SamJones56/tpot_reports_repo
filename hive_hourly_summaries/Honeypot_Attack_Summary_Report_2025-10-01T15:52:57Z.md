Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T15:52:37Z
**Timeframe of Analyzed Files:** 2025-10-01T14:20:01Z to 2025-10-01T15:00:01Z
**Files Analyzed:**
- agg_log_20251001T142001Z.json
- agg_log_20251001T144001Z.json
- agg_log_20251001T150001Z.json

**Executive Summary**
This report summarizes 29,997 events recorded across three honeypot log files. The majority of attacks were captured by the Sentrypeer honeypot, with significant activity also detected on Cowrie and Honeytrap. The most prominent attacking IP address was 92.205.59.208, responsible for a large volume of the traffic. Port 5060 (SIP) was the most targeted port. A number of CVEs were detected, with CVE-2024-1709 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
- Sentrypeer: 17,342
- Cowrie: 6,820
- Honeytrap: 3,741
- Suricata: 903
- Ciscoasa: 811
- Dionaea: 204
- Tanner: 66
- H0neytr4p: 28
- ConPot: 22
- Dicompot: 21
- Adbhoney: 14
- Honeyaml: 14
- Ipphoney: 7
- Mailoney: 4

**Top Attacking IPs:**
- 92.205.59.208: 17,400
- 129.212.183.91: 1,494
- 103.130.215.15: 1,267
- 45.134.26.20: 1,000
- 45.140.17.144: 823
- 165.227.98.222: 784
- 45.134.26.62: 501
- 45.140.17.153: 500
- 117.72.52.28: 476
- 157.66.34.56: 207

**Top Targeted Ports/Protocols:**
- 5060: 17,342
- 22: 1,171
- 445: 172
- UDP/5060: 105
- 80: 72
- 8333: 67
- TCP/22: 42
- 443: 26
- 9443: 23
- 31337: 20

**Most Common CVEs:**
- CVE-2024-1709: 6
- CVE-2002-0013, CVE-2002-0012: 4
- CVE-2024-4577, CVE-2002-0953: 2
- CVE-2024-4577: 2
- CVE-2021-35394: 1
- CVE-2021-41773: 1
- CVE-2021-42013: 1

**Commands Attempted by Attackers:**
- A total of 30 unique commands were attempted. The most common commands were reconnaissance and system manipulation commands such as `uname -a`, `whoami`, `cat /proc/cpuinfo`, and attempts to modify SSH authorized_keys.

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 169
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 133
- ET VOIP REGISTER Message Flood UDP: 104
- ET SCAN NMAP -sS window 1024: 95
- ET HUNTING RDP Authentication Bypass Attempt: 62
- ET SCAN Potential SSH Scan: 31
- ET INFO Reserved Internal IP Traffic: 29
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 14
- ET SCAN Suspicious inbound to MSSQL port 1433: 12
- ET WEB_SPECIFIC_APPS ConnectWise ScreenConnect - Attempted SetupWizard Auth Bypass CWE-288 (CVE-2024-1709): 6

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 16
- root/nPSpP4PBW0: 7
- foundry/foundry: 6
- root/LeitboGi0ro: 5
- superadmin/admin123: 4
- gitlab/gitlab: 3
- root/3245gs5662d34: 5
- test/zhbjETuyMffoL8F: 3
- ripple/ripple123: 3

**Files Uploaded/Downloaded:**
- sh: 98
- arm.urbotnetisass: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass: 3
- x86_32.urbotnetisass: 3
- Space.mips: 2
- welcome.jpg): 1
- writing.jpg): 1
- tags.jpg): 1

**HTTP User-Agents:**
- No HTTP user-agents were recorded in the logs.

**SSH Clients:**
- No SSH clients were recorded in the logs.

**SSH Servers:**
- No SSH servers were recorded in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**
- The high volume of traffic from a single IP address (92.205.59.208) targeting port 5060 suggests a targeted or automated attack against SIP services.
- The variety of CVEs detected indicates that attackers are attempting to exploit a range of vulnerabilities.
- The commands executed by attackers show a clear pattern of attempting to gather system information, establish persistence via SSH keys, and download additional malware.
- A significant number of files with names like `*.urbotnetisass` were downloaded, suggesting a specific malware campaign.
