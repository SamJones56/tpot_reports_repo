Honeypot Attack Summary Report

Report generated on 2025-10-22T21:01:43Z for the timeframe of 2025-10-22T20:20:01Z to 2025-10-22T21:00:01Z.
Files used to generate this report:
- agg_log_20251022T202001Z.json
- agg_log_20251022T204001Z.json
- agg_log_20251022T210001Z.json

Executive Summary:
This report summarizes 16,549 malicious activities recorded by honeypots over the last hour. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequent attacks originated from IP address 91.124.88.15, and the most targeted port was 5038. Numerous CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 5583
- Honeytrap: 4999
- Ciscoasa: 1727
- Suricata: 1683
- Sentrypeer: 1262
- Dionaea: 1060

Top attacking IPs:
- 91.124.88.15: 1273
- 119.93.166.151: 1012
- 14.103.177.14: 492
- 197.248.8.33: 366
- 170.239.86.101: 364

Top targeted ports/protocols:
- 5038: 1273
- 5060: 1262
- 445: 1025
- 22: 733
- 8333: 224

Most common CVEs:
- CVE-2005-4050: 107
- CVE-2002-0013 CVE-2002-0012: 23
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 17
- CVE-2022-27255 CVE-2022-27255: 3
- CVE-2024-3721 CVE-2024-3721: 3
- CVE-2021-35394 CVE-2021-35394: 3
- CVE-1999-0183: 1

Commands attempted by attackers:
- uname -a: 35
- cd ~ && rm -rf .ssh ...: 34
- lockr -ia .ssh: 34
- cat /proc/cpuinfo | grep name | wc -l: 34
- w: 34
- whoami: 34
- Enter new UNIX password: : 24

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1: 361
- 2402000: 361
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 239
- 2023753: 239
- ET SCAN NMAP -sS window 1024: 181
- 2009582: 181
- ET VOIP MultiTech SIP UDP Overflow: 107
- 2003237: 107
- ET HUNTING RDP Authentication Bypass Attempt: 83
- 2034857: 83

Users / login attempts:
- 345gs5662d34/345gs5662d34: 33
- root/: 8
- root/3245gs5662d34: 8
- root/c0nv3rg14N3tw0rk119!!MVPTHEcompany90bilal: 4
- root/c0sm0Red1092: 4
- root/C13l1t0V01p: 4

Files uploaded/downloaded:
- wget.sh;: 8
- bot.mpsl;: 3
- w.sh;: 2
- c.sh;: 2
- k.php?a=x86_64,EAG438ZN1D5H7ZC7H: 1

HTTP User-Agents:
- No HTTP User-Agents were logged.

SSH clients:
- No SSH clients were logged.

SSH servers:
- No SSH servers were logged.

Top attacker AS organizations:
- No attacker AS organizations were logged.

Key Observations and Anomalies:
- A significant number of commands were aimed at manipulating SSH keys, suggesting a focus on maintaining long-term access to compromised systems.
- The high number of login attempts with the username/password `345gs5662d34/345gs5662d34` indicates a coordinated brute-force attack from multiple sources.
- The triggered signatures show a mix of scanning activity (NMAP, MS Terminal Server) and exploits against specific vulnerabilities (VOIP, RDP).
- No data was logged for HTTP User-Agents, SSH clients/servers, or AS organizations, which may indicate that the attacks were focused on other protocols or that this information was not captured by the honeypots.
