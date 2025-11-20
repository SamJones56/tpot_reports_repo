Honeypot Attack Summary Report

Report generated on: 2025-10-01T08:01:38Z
Timeframe: 2025-10-01T07:20:01Z to 2025-10-01T08:00:02Z
Files used to generate this report:
- agg_log_20251001T072001Z.json
- agg_log_20251001T074001Z.json
- agg_log_20251001T080002Z.json

Executive Summary
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 22,857 events were recorded. The majority of attacks targeted the Cowrie honeypot. The most prominent attacking IP address was 161.35.152.121, responsible for a significant portion of the attacks. SSH (port 22) and SMB (port 445) were the most targeted services. Several CVEs were identified, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistence.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 14,471
- Honeytrap: 2,618
- Dionaea: 2,184
- Suricata: 1,446
- Ciscoasa: 1,406
- Mailoney: 423
- Tanner: 73
- Redishoneypot: 56
- H0neytr4p: 55
- ElasticPot: 42
- Sentrypeer: 18
- Adbhoney: 12
- Heralding: 3
- Honeyaml: 4
- ConPot: 1
- Miniprint: 45

Top Attacking IPs:
- 161.35.152.121: 11,231
- 196.218.240.91: 1,967
- 92.242.166.161: 401
- 185.156.73.166: 368
- 185.156.73.167: 362
- 92.63.197.55: 354
- 103.234.151.178: 297
- 89.22.238.192: 272
- 138.68.167.183: 265
- 64.227.102.57: 164
- 209.141.57.124: 109

Top Targeted Ports/Protocols:
- 22 (SSH): 2,674
- 445 (SMB): 2,105
- 25 (SMTP): 423
- 8333 (Bitcoin): 155
- 80 (HTTP): 75
- 9100 (JetDirect): 45
- 23 (Telnet): 29

Most Common CVEs:
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2023-26801

Commands Attempted by Attackers:
- System reconnaissance commands (uname, lscpu, whoami, etc.)
- Establishing persistence via SSH authorized_keys
- Downloading and executing malware (urbotnetisass)
- Clearing logs and killing processes
- Changing user passwords

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET WEB_SPECIFIC_APPS Microhard Systems 3G/4G Cellular Ethernet and Serial Gateway - Default Credentials
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

Users / Login Attempts:
- A variety of username/password combinations were attempted, with a focus on default credentials for root and admin accounts. Common usernames included 'root', 'admin', 'user', and 'test'.

Files Uploaded/Downloaded:
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

HTTP User-Agents:
- No HTTP user-agents were recorded in this period.

SSH Clients and Servers:
- No SSH clients or servers were recorded in this period.

Top Attacker AS Organizations:
- No attacker AS organizations were recorded in this period.

Key Observations and Anomalies
- The overwhelming number of attacks from 161.35.152.121 suggests a targeted or automated attack from a single source.
- The commands attempted indicate a clear pattern of reconnaissance, followed by attempts to download and execute malware, and establish persistence.
- The variety of malware payloads (arm, x86, mips) suggests an attempt to target a wide range of architectures.
- The presence of CVEs, although small in number, indicates that some attackers are attempting to exploit known vulnerabilities.
- The high number of login attempts with default credentials highlights the importance of changing default passwords.