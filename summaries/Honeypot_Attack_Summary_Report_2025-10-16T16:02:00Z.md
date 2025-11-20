Honeypot Attack Summary Report

Report Generation Time: 2025-10-16T16:01:37Z
Timeframe: 2025-10-16T15:20:01Z to 2025-10-16T16:00:01Z
Files used to generate this report:
- agg_log_20251016T152001Z.json
- agg_log_20251016T154001Z.json
- agg_log_20251016T160001Z.json

Executive Summary:
This report summarizes 29,143 attacks recorded by honeypots over the last hour. The most targeted services were VNC (port 5900) and SIP (port 5060). A significant portion of the attacks originated from the IP address 45.134.26.47. Attackers were observed attempting to gain access via SSH and execute commands to add their own SSH keys for persistent access. Several CVEs were targeted, with a focus on older vulnerabilities.

Detailed Analysis:

Attacks by honeypot:
- Suricata: 7,082
- Honeytrap: 6,322
- Cowrie: 6,180
- Heralding: 5,792
- Sentrypeer: 2,137
- Ciscoasa: 1,346
- Dionaea: 75
- H0neytr4p: 78
- Mailoney: 46
- and others with fewer attacks.

Top attacking IPs:
- 45.134.26.47: 5,792
- 107.155.93.174: 3,992
- 10.208.0.3: 3,834
- 10.140.0.3: 2,056
- 47.100.73.98: 1,016
- 23.94.26.58: 718
- 172.86.95.115: 398
- 185.243.5.158: 377
- 172.86.95.98: 382

Top targeted ports/protocols:
- vnc/5900: 5,789
- 5060: 2,137
- 22: 1,043
- TCP/5900: 266
- 5903: 189
- 8333: 171

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2001-0414: 1
- CVE-2023-26801 CVE-2023-26801: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 22
- lockr -ia .ssh: 22
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 21
- cat /proc/cpuinfo | grep name | wc -l: 15
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 15
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 15
- uname: 15
- uname -a: 15
- whoami: 15
- lscpu | grep Model: 15

Signatures triggered:
- ET INFO VNC Authentication Failure: 5,890
- ET DROP Dshield Block Listed Source group 1: 267
- ET SCAN NMAP -sS window 1024: 129
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 130
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 153

Users / login attempts:
- 345gs5662d34/345gs5662d34: 20
- root/Qaz123qaz: 11
- root/123@@@: 9
- ftpuser/ftppassword: 8
- root/QWE123!@#qwe: 6
- unknown/unknown444: 6

Files uploaded/downloaded:
- 2;: 3

HTTP User-Agents:
- (No user agents recorded in this period)

SSH clients and servers:
- (No specific clients or servers recorded in this period)

Top attacker AS organizations:
- (No AS organizations recorded in this period)

Key Observations and Anomalies:
- A high volume of VNC authentication failures was observed, indicating widespread scanning for open VNC servers.
- The consistent use of commands to add an SSH key to `authorized_keys` suggests a coordinated campaign to establish persistent access to compromised systems.
- The targeting of old CVEs like CVE-2002-0013 indicates that attackers are still finding success with legacy vulnerabilities.
- The IP 45.134.26.47 was responsible for a large number of attacks, primarily targeting VNC.
- Internal IP addresses (10.0.0.0/8 range) were also a significant source of attacks, which could indicate compromised devices on the internal network or a misconfiguration.
