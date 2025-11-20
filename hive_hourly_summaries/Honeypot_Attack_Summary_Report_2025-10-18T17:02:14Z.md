Honeypot Attack Summary Report

Report generated on: 2025-10-18T17:01:38Z
Timeframe of logs: 2025-10-18T16:20:01Z to 2025-10-18T17:00:01Z
Files used to generate this report:
- agg_log_20251018T162001Z.json
- agg_log_20251018T164001Z.json
- agg_log_20251018T170001Z.json

Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 21,498 attacks were recorded across various honeypots. The most targeted services were email (SMTP), SSH, and VNC. A significant number of attacks originated from the IP address 172.245.214.35, accounting for over 26% of the total attacks. Attackers were observed attempting to exploit several vulnerabilities, with CVE-2005-4050 being the most frequent. A common attack pattern involved attempts to add an SSH key to the authorized_keys file for persistent access.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 6818
- Mailoney: 5740
- Suricata: 4261
- Honeytrap: 1933
- Heralding: 993
- Ciscoasa: 1236
- Sentrypeer: 258
- Tanner: 83
- Dionaea: 45
- Adbhoney: 26
- Redishoneypot: 25
- H0neytr4p: 29
- ElasticPot: 27
- ConPot: 15
- Ipphoney: 4
- Dicompot: 3
- Honeyaml: 2

Top attacking IPs:
- 172.245.214.35: 5653
- 31.58.144.28: 2502
- 197.43.61.231: 1935
- 10.140.0.3: 1064
- 176.9.111.156: 972
- 72.146.232.13: 917
- 196.251.69.192: 497
- 88.210.63.16: 473
- 196.251.69.191: 498
- 107.170.36.5: 245

Top targeted ports/protocols:
- 25: 5741
- TCP/445: 1935
- 22: 1514
- vnc/5900: 993
- 5060: 258
- 5903: 219
- TCP/5900: 114
- 8333: 98
- 5901: 115
- 80: 83

Most common CVEs:
- CVE-2005-4050
- CVE-2021-44228 CVE-2021-44228
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2001-0414
- CVE-2024-11120 CVE-2024-6047
- CVE-2024-3721 CVE-2024-3721
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2002-0013 CVE-2002-0012

Commands attempted by attackers:
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- whoami
- Enter new UNIX password:
- crontab -l
- w
- uname -m
- top

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET INFO VNC Authentication Failure
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN Potential SSH Scan

Users / login attempts:
- 345gs5662d34/345gs5662d34
- guest/guest2011
- config/marketing
- debian/4444
- root/44
- blank/12345
- root/2much4me
- root/!Q2w3e4r
- tools/tools
- root/passw0rd

Files uploaded/downloaded:
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- 11
- binary.sh
- wget.sh;
- Mozi.a+varcron
- w.sh;
- c.sh;

HTTP User-Agents:
- No user agents recorded.

SSH clients:
- No SSH clients recorded.

SSH servers:
- No SSH servers recorded.

Top attacker AS organizations:
- No AS organizations recorded.

Key Observations and Anomalies
- The high volume of attacks from a single IP (172.245.214.35) suggests a targeted or automated campaign.
- The prevalence of the command to add an SSH key indicates a focus on establishing persistent access to compromised systems.
- The `DoublePulsar Backdoor` signature suggests attempts to exploit systems that may have been previously compromised by the FuzzBunch exploit kit.
- The variety of credentials used in login attempts indicates brute-force attacks using common or previously breached username/password combinations.
- No successful breaches have been detected. All recorded activities are attempts that were captured by the honeypot sensors.
