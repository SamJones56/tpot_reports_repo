Honeypot Attack Summary Report

Report generated at: 2025-10-05T00:01:27Z
Timeframe of logs: 2025-10-04T23:20:01Z to 2025-10-05T00:00:01Z
Log files used for this report:
- agg_log_20251004T232001Z.json
- agg_log_20251004T234001Z.json
- agg_log_20251005T000001Z.json

Executive Summary
This report summarizes 6805 attacks recorded across multiple honeypots. The majority of attacks were SMTP-based, with significant activity also targeting SSH, Telnet, and VoIP services. A number of CVEs were targeted, with CVE-2005-4050 being the most prominent. Attackers were observed attempting to gain access via brute-force login attempts and execute commands to gather system information and establish persistent access.

Detailed Analysis

Attacks by honeypot:
- Mailoney: 1663
- Cowrie: 1581
- Ciscoasa: 1524
- Suricata: 1012
- Sentrypeer: 628
- Heralding: 94
- Honeytrap: 81
- Tanner: 71
- H0neytr4p: 45
- Dionaea: 31
- ConPot: 16
- Honeyaml: 13
- ElasticPot: 5
- Redishoneypot: 6
- Dicompot: 3

Top attacking IPs:
- 86.54.42.238
- 176.65.141.117
- 172.86.95.98
- 186.4.131.49
- 103.176.20.115
- 210.79.190.46
- 45.186.251.70
- 198.12.68.114
- 14.103.121.78
- 155.4.244.107
- 23.94.26.58
- 185.243.5.68
- 2.57.121.148
- 202.79.29.108

Top targeted ports/protocols:
- 25
- 5060
- 22
- 80
- 443
- 23
- UDP/5060
- TCP/22
- TCP/80
- vnc/5900
- 1433
- 9200

Most common CVEs:
- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500
- CVE-2024-4577
- CVE-2002-0953
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-41773
- CVE-2021-42013
- CVE-2024-3721
- CVE-1999-0183

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344
- ET SCAN Potential SSH Scan
- 2001219

Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/LeitboGi0ro
- novinhost/novinhost.org
- /00000000
- /0000000
- /0000
- admin/251289
- admin/25121977
- admin/251080
- admin/25101993
- admin/25101981

Files uploaded/downloaded:
- sh: 98

HTTP User-Agents:
- No user agents recorded in this period.

SSH clients:
- No SSH clients recorded in this period.

SSH servers:
- No SSH servers recorded in this period.

Top attacker AS organizations:
- No AS organizations recorded in this period.

Key Observations and Anomalies
- A significant amount of reconnaissance and brute-force activity was directed towards mail (SMTP) and voice (SIP) services.
- The most frequently attempted command sequence involves modifying SSH authorized_keys to add a persistent backdoor.
- The CVE-2005-4050, related to a vulnerability in older SIP implementations, was the most commonly targeted CVE.
- The majority of attacks originate from a small number of IP addresses, suggesting a coordinated campaign.
