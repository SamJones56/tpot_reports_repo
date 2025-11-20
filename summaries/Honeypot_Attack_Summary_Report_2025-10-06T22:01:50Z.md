Honeypot Attack Summary Report

Report generated on 2025-10-06T22:01:35Z, summarizing data from the last 6 minutes.
Files used to generate this report:
- agg_log_20251006T212001Z.json
- agg_log_20251006T214002Z.json
- agg_log_20251006T220002Z.json

Executive Summary
This report summarizes 15,385 attacks recorded across multiple honeypots. The most targeted services were Cowrie (SSH/Telnet), Honeytrap, and Suricata. A significant portion of the attacks were SSH brute force attempts, SMB exploits, and scans for open ports. The most active attacking IP was 190.77.187.8.

Detailed Analysis

Attacks by honeypot:
- Cowrie: 5030
- Honeytrap: 3144
- Suricata: 3135
- Mailoney: 2085
- Ciscoasa: 1203
- Sentrypeer: 428
- Dionaea: 112
- Redishoneypot: 55
- H0neytr4p: 56
- Tanner: 57
- Adbhoney: 25
- ConPot: 24
- Honeyaml: 20
- Dicompot: 6
- ElasticPot: 4
- Wordpot: 1

Top attacking IPs:
- 190.77.187.8
- 86.54.42.238
- 80.94.95.238
- 176.65.141.117
- 41.226.27.251
- 107.173.61.177
- 172.86.95.98
- 167.71.221.242
- 103.220.207.174
- 198.12.114.232

Top targeted ports/protocols:
- TCP/445
- 25
- 22
- 5060
- 8333
- 23
- 5903
- 6379
- 80
- 443

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2001-0414
- CVE-2006-2369
- CVE-2019-11500 CVE-2019-11500

Commands attempted by attackers:
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752

Users / login attempts:
- 345gs5662d34/345gs5662d34
- ubuntu/3245gs5662d34
- github/P@ssw0rd
- admin/11021974
- admin/10121981
- admin/101180
- admin/10111995
- admin/10111978
- github/12345
- stack/stack1234

Files uploaded/downloaded:
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- wget.sh;
- w.sh;
- c.sh;

HTTP User-Agents:
- No user agents were logged in this timeframe.

SSH clients and servers:
- No SSH clients or servers were logged in this timeframe.

Top attacker AS organizations:
- No AS organizations were logged in this timeframe.

Key Observations and Anomalies
- The high number of attacks on port 445 (SMB), primarily from the IP 190.77.187.8, suggests a targeted campaign against this service, likely related to the DoublePulsar backdoor.
- A recurring command pattern was observed where attackers attempt to add their SSH key to the authorized_keys file for persistent access.
- Several reconnaissance commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` were frequently used, indicating attackers are fingerprinting the system before attempting further exploitation.
- A variety of CVEs were scanned for, with a focus on older vulnerabilities.
- A significant number of login attempts used common default credentials (e.g., admin/admin, root/12345).
