Honeypot Attack Summary Report

Report generated at: 2025-10-04T13:01:25Z
Data from files:
- agg_log_20251004T122001Z.json
- agg_log_20251004T124001Z.json
- agg_log_20251004T130001Z.json

Executive Summary
This report summarizes 10,353 events collected from multiple honeypots. The most targeted services were Cowrie (SSH), Dionaea (malware collection), and Mailoney (SMTP). A significant portion of attacks originated from a small number of IP addresses, with 15.235.131.242, 176.65.141.117 and 103.58.75.230 being the most active. The most frequently targeted ports were 445 (SMB) and 25 (SMTP). Several CVEs were targeted, with a focus on older vulnerabilities. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control of the compromised system.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 2691
- Dionaea: 2797
- Mailoney: 1699
- Ciscoasa: 1600
- Suricata: 978
- Sentrypeer: 180
- Honeytrap: 134
- H0neytr4p: 57
- Tanner: 50
- Redishoneypot: 23
- Adbhoney: 25
- Heralding: 60
- ConPot: 29
- Honeyaml: 16
- ElasticPot: 9
- Dicompot: 3
- Wordpot: 1
- Ipphoney: 1

Top Attacking IPs:
- 15.235.131.242: 1183
- 176.65.141.117: 1640
- 103.58.75.230: 1025
- 182.53.12.81: 516
- 197.5.145.102: 360
- 164.92.186.228: 297
- 147.0.206.46: 236
- 60.199.224.2: 356
- 171.244.40.122: 232
- 185.242.226.74: 253
- 4.247.148.92: 139
- 87.201.127.149: 100
- 45.186.251.70: 115
- 46.105.87.113: 120
- 46.21.246.81: 103
- 103.115.24.11: 207

Top Targeted Ports/Protocols:
- 445: 2779
- 25: 1699
- 22: 331
- 5060: 180
- 80: 57
- 443: 57
- 23: 69
- 6379: 23
- TCP/1080: 255
- vnc/5900: 57
- 8500: 36
- TCP/80: 30
- TCP/22: 17
- TCP/3389: 9
- 10001: 20
- TCP/5432: 17

Most Common CVEs:
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2021-41773

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname -a
- whoami
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- Enter new UNIX password:

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- GPL INFO SOCKS Proxy attempt
- 2100615
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET INFO CURL User Agent

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- root/Qwerty_123
- root/Abc1234567890
- yuri/yuri123
- ftpuser/ftpuser@2025
- snort/snort
- developer/dev123
- web/P@ssw0rd
- work/work123
- nexus/Welcome1

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
- sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- sign_in
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png

HTTP User-Agents:
- (No user agents recorded in this period)

SSH Clients and Servers:
- (No specific clients or servers recorded in this period)

Top Attacker AS Organizations:
- (No AS organization data in this period)

Key Observations and Anomalies
- The volume of attacks is high and sustained, indicating automated scanning and exploitation attempts.
- Attackers are using a consistent set of commands across different compromised systems, suggesting the use of automated scripts for post-exploitation.
- The targeting of old CVEs suggests that attackers are still finding success with legacy vulnerabilities.
- There is a significant amount of scanning activity for services like SMB and SMTP, which are common targets for worms and botnets.
- The presence of commands related to removing and modifying SSH keys is a strong indicator of attempts to maintain persistent access to compromised systems.
- The downloading of various architectures of `urbotnetisass` suggests a sophisticated malware campaign capable of targeting a wide range of devices.