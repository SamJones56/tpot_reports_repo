**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-25T12:02:31Z
**Timeframe:** 2025-10-25T11:20:01Z to 2025-10-25T12:00:01Z
**Files Used:**
- agg_log_20251025T112001Z.json
- agg_log_20251025T114001Z.json
- agg_log_20251025T120001Z.json

**Executive Summary**

This report summarizes 23,153 events collected from the honeypot network over a 40-minute interval. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also logged by Heralding and Suricata. The most prominent attacking IP address was 185.243.96.105. The most targeted service was VNC on port 5900. A variety of CVEs were observed, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access via SSH authorized_keys.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 8898
- Heralding: 4418
- Suricata: 3797
- Honeytrap: 2778
- Ciscoasa: 1813
- Dionaea: 939
- Sentrypeer: 191
- Mailoney: 121
- Tanner: 70
- H0neytr4p: 56
- Adbhoney: 25
- ConPot: 15
- Redishoneypot: 15
- ElasticPot: 10
- Ipphoney: 3
- Miniprint: 2
- Honeyaml: 2

***Top Attacking IPs***
- 185.243.96.105: 4409
- 120.210.47.125: 1369
- 103.77.160.211: 1239
- 109.205.211.9: 1117
- 157.245.72.224: 495
- 103.241.43.72: 425
- 36.93.247.226: 396
- 20.123.120.169: 305
- 101.36.117.148: 285
- 195.178.191.5: 356

***Top Targeted Ports/Protocols***
- vnc/5900: 4418
- TCP/445: 1365
- 22: 1315
- 445: 714
- 5060: 191
- 3306: 162
- 23: 141
- 5903: 131
- 8333: 111
- 25: 121

***Most Common CVEs***
- CVE-2002-1149: 5
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-1999-0183: 2
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2001-0414: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2016-20016 CVE-2016-20016: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 41
- lockr -ia .ssh: 41
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 41
- cat /proc/cpuinfo | grep name | wc -l: 41
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 41
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 41
- ls -lh $(which ls): 41
- which ls: 41
- crontab -l: 41
- w: 41

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1362
- 2024766: 1362
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 874
- 2023753: 874
- ET HUNTING RDP Authentication Bypass Attempt: 414
- 2034857: 414
- ET DROP Dshield Block Listed Source group 1: 353
- 2402000: 353
- ET SCAN NMAP -sS window 1024: 186
- 2009582: 186

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 37
- /Passw0rd: 19
- /passw0rd: 19
- /1q2w3e4r: 14
- root/3245gs5662d34: 11
- /1qaz2wsx: 8
- root/EshareEshare: 4
- root/eskimo2013: 4
- root/Estamparajar0: 4
- gaurav/gaurav@123: 4

***Files Uploaded/Downloaded***
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
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
- bot.mpsl: 2
- 129.212.146.61:8088: 2
- apply.cgi: 2

***HTTP User-Agents***
- No HTTP User-Agents were observed in this period.

***SSH Clients and Servers***
- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***
- No attacker AS organization data was available in the logs.

**Key Observations and Anomalies**

1.  **High-Volume Scanners:** The IP address 185.243.96.105 was responsible for a substantial portion of the total events, indicating a targeted or automated scanning campaign.
2.  **VNC and SMB Exploitation:** The most targeted port was 5900 (VNC), followed by ports related to SMB and RDP (445) and SSH (22). This suggests a focus on remote access and control services.
3.  **Persistent Access Attempts:** The most common commands are part of a clear sequence to gain and maintain access. They involve creating an `.ssh` directory, adding a specific public key to `authorized_keys`, and then locking the file to prevent changes.
4.  **System Reconnaissance:** Following the attempt to establish persistence, attackers consistently ran commands to gather system information (CPU, memory, OS details).
5.  **Malware Downloads:** Several entries in the `files_uploaded_downloaded` list point to attempts to download and execute malicious scripts (e.g., `wget.sh`, `w.sh`, `c.sh`, and several `*.urbotnetisass` files), likely part of a botnet infection campaign.
6.  **DoublePulsar Activity:** The most frequently triggered Suricata signature relates to the DoublePulsar backdoor, indicating attempts to exploit vulnerabilities associated with this tool.
