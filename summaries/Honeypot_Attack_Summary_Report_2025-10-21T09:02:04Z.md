Honeypot Attack Summary Report

Report generated on 2025-10-21T09:01:39Z, summarizing data from 2025-10-21T08:20:01Z to 2025-10-21T09:00:01Z.
Files used for this report:
- agg_log_20251021T082001Z.json
- agg_log_20251021T084001Z.json
- agg_log_20251021T090001Z.json

Executive Summary
This report summarizes 17,551 attacks recorded over a 40-minute interval across three log files. The most targeted services were Cowrie (SSH), Dionaea (SMB), and Honeytrap. A significant portion of attacks originated from the IP address 94.153.137.178, primarily targeting port 445 (SMB). Several CVEs were targeted, with CVE-2022-27255 being the most frequent. Attackers attempted various commands, many of which were aimed at reconnaissance and establishing persistent access by modifying SSH authorized keys.

Detailed Analysis

Attacks by honeypot:
- Cowrie: 6237
- Honeytrap: 3671
- Suricata: 3572
- Dionaea: 3212
- Sentrypeer: 663
- Tanner: 69
- Adbhoney: 10
- Ciscoasa: 26
- Redishoneypot: 15
- ConPot: 15
- H0neytr4p: 15
- Mailoney: 17
- Miniprint: 8
- ElasticPot: 5
- Honeyaml: 7
- Ipphoney: 4
- Dicompot: 2
- Heralding: 3

Top attacking IPs:
- 94.153.137.178: 3139
- 122.52.185.66: 1483
- 72.146.232.13: 1217
- 198.23.190.58: 617
- 14.103.230.55: 345
- 154.72.233.36: 298
- 185.243.5.158: 235
- 61.80.237.194: 238
- 107.170.36.5: 252
- 34.57.181.41: 178

Top targeted ports/protocols:
- 445: 4684
- 22: 1116
- 5060: 981
- 5903: 228
- 5901: 122
- 8333: 105
- 80: 63
- 33232: 90
- 33178: 45
- 33240: 45

Most common CVEs:
- CVE-2022-27255
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-3449
- CVE-2018-10562
- CVE-2018-10561
- CVE-2002-1149
- CVE-2005-4050
- CVE-2024-3721
- CVE-1999-0517

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- uname -m
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN Sipsak SIP scan
- 2008598
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582

Users / login attempts:
- 345gs5662d34/345gs5662d34
- user01/Password01
- root/3245gs5662d34
- root/Alta3002
- root/altarede
- deploy/123123
- root/Alvyweb211290
- root/Amatz!WEB2014

Files uploaded/downloaded:
- gpon8080&ipv=0
- json

HTTP User-Agents:
- N/A

SSH clients and servers:
- N/A

Top attacker AS organizations:
- N/A

Key Observations and Anomalies
- A large number of attacks are attributed to a single IP address, 94.153.137.178, suggesting a targeted campaign or a botnet.
- The high number of SMB exploits indicates that attackers are actively scanning for vulnerable Windows machines.
- The commands attempted suggest a focus on gaining persistent access to the compromised machine via SSH keys, and gathering system information.
- No HTTP user agents, SSH clients, or AS organizations were recorded in this period.
- The "tftp; wget; /bin/busybox DVRHG" command suggests an attempt to download and execute a malicious payload.
