Honeypot Attack Summary Report

Report Generation Time: 2025-10-08T10:01:38Z
Timeframe of Report: 2025-10-08T09:20:01Z to 2025-10-08T10:00:01Z
Files used to generate this report:
- agg_log_20251008T092001Z.json
- agg_log_20251008T094001Z.json
- agg_log_20251008T100001Z.json

Executive Summary:
This report summarizes 18,559 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from the IP address 5.167.79.4. Port 25 (SMTP) and 22 (SSH) were the most targeted ports. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 9368
- Honeytrap: 2780
- Mailoney: 1717
- Suricata: 1804
- Ciscoasa: 1615
- Dionaea: 796
- Sentrypeer: 180
- H0neytr4p: 111
- Redishoneypot: 53
- Tanner: 84
- ConPot: 18
- Adbhoney: 8
- Honeyaml: 11
- ElasticPot: 10
- Wordpot: 2
- Ipphoney: 2

Top attacking IPs:
- 5.167.79.4: 1251
- 86.54.42.238: 821
- 176.65.141.117: 820
- 5.141.26.114: 565
- 209.38.91.18: 513
- 200.87.199.38: 551
- 158.174.210.161: 233
- 103.211.71.25: 205
- 34.212.14.239: 216
- 192.227.213.240: 391

Top targeted ports/protocols:
- 25: 1717
- 22: 1363
- 445: 742
- TCP/445: 550
- 5060: 180
- 2053: 243
- 443: 100
- 80: 85
- 5903: 93
- 8333: 78

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 19
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-2016-20016 CVE-2016-20016: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 46
- lockr -ia .ssh: 46
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 45
- Enter new UNIX password: : 41
- Enter new UNIX password::: 41
- cat /proc/cpuinfo | grep name | wc -l: 42
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 41
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 41
- ls -lh $(which ls): 41
- which ls: 41

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 545
- 2024766: 545
- ET DROP Dshield Block Listed Source group 1: 328
- 2402000: 328
- ET SCAN NMAP -sS window 1024: 158
- 2009582: 158
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 25
- 2403346: 25

Users / login attempts:
- 345gs5662d34/345gs5662d34: 45
- sysadmin/sysadmin@1: 29
- ubuntu/3245gs5662d34: 14
- root/qweasdzxc123: 7
- operator/operator6: 6
- support/Support12345: 6
- unknown/unknown6: 6
- admin/admin77: 6
- root/abcd123: 6
- unknown/unknown0: 6

Files uploaded/downloaded:
- ?format=json: 2
- rondo.kqa.sh|sh&echo: 4

HTTP User-Agents:
- No HTTP User-Agents were observed in the logs.

SSH clients:
- No SSH clients were observed in the logs.

SSH servers:
- No SSH servers were observed in the logs.

Top attacker AS organizations:
- No attacker AS organizations were observed in the logs.

Key Observations and Anomalies:
- A significant number of commands are related to manipulating SSH keys, suggesting attackers are attempting to maintain persistent access.
- The command `tftp; wget; /bin/busybox MMDKE` was observed, which could be an attempt to download and execute a malicious payload.
- The majority of attacks are automated, using common usernames and passwords.
- There is a noticeable focus on compromising services like SMTP (port 25) and SSH (port 22).
- The presence of DoublePulsar related signatures indicates that some attackers are still attempting to use older, well-known exploits.
