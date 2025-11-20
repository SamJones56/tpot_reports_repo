Honeypot Attack Summary Report

Report Generation Time: 2025-10-02T01:01:22Z
Timeframe: 2025-10-02T00:20:01Z to 2025-10-02T01:00:01Z
Files Used:
- agg_log_20251002T002001Z.json
- agg_log_20251002T004001Z.json
- agg_log_20251002T010001Z.json

Executive Summary

This report summarizes 19,140 attacks recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was 103.130.215.15, and the most targeted port was 445/TCP (SMB). Attackers attempted various commands, including reconnaissance, establishing SSH access, and downloading malicious payloads. Several CVEs were targeted, and multiple intrusion detection signatures were triggered.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 10057
- Dionaea: 2753
- Honeytrap: 2329
- Suricata: 1548
- Ciscoasa: 1370
- Mailoney: 863
- H0neytr4p: 43
- Adbhoney: 42
- Sentrypeer: 34
- Tanner: 32
- Heralding: 19
- Redishoneypot: 14
- Miniprint: 14
- Honeyaml: 9
- ConPot: 8
- ElasticPot: 2
- Ipphoney: 2
- Wordpot: 1

Top Attacking IPs:
- 103.130.215.15: 4904
- 171.102.83.142: 1826
- 129.212.180.229: 1776
- 170.245.229.86: 853
- 64.188.92.102: 859
- 176.65.141.117: 820
- 185.156.73.166: 348
- 92.63.197.55: 346
- 185.156.73.167: 345
- 92.63.197.59: 315

Top Targeted Ports/Protocols:
- 445: 2683
- 22: 1888
- 25: 863
- 8333: 183
- 5901: 70
- 443: 49
- TCP/80: 35

Most Common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2018-10562 CVE-2018-10561
- CVE-2021-35394 CVE-2021-35394

Commands Attempted by Attackers:
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...
- Enter new UNIX password:

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic

Users / Login Attempts:
- openser/
- root/nPSpP4PBW0
- pi/raspberry
- root/
- 345gs5662d34/345gs5662d34
- root/passw0rd
- admin/1234
- root/Ab123456

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

HTTP User-Agents:
- (No data)

SSH Clients:
- (No data)

SSH Servers:
- (No data)

Top Attacker AS Organizations:
- (No data)

Key Observations and Anomalies

- A significant amount of activity was related to attempts to download and execute shell scripts (e.g., `w.sh`, `c.sh`, `wget.sh`) and ELF executables (`urbotnetisass`), indicating automated attacks by botnets.
- The high number of attacks on port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
- The commands executed show a clear pattern of attackers trying to gain persistence by adding their SSH key to the `authorized_keys` file.
- The variety of credentials used in login attempts suggests brute-force attacks using common and default usernames and passwords.
