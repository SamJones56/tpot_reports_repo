Honeypot Attack Summary Report

Report generated at: 2025-10-04T14:01:29Z
Data from the following files were used to generate this report:
- agg_log_20251004T132001Z.json
- agg_log_20251004T134002Z.json
- agg_log_20251004T140001Z.json

**Executive Summary**

This report summarizes 11,145 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks targeted ports 445 (SMB) and 22 (SSH). A significant number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

**Detailed Analysis**

***Attacks by honeypot***

- Cowrie: 5965
- Ciscoasa: 1614
- Dionaea: 1199
- Suricata: 930
- Mailoney: 852
- Sentrypeer: 196
- Honeytrap: 168
- Miniprint: 61
- H0neytr4p: 38
- ConPot: 31
- Honeyaml: 26
- Adbhoney: 15
- Redishoneypot: 12
- Tanner: 18
- ElasticPot: 6
- Ipphoney: 5
- Dicompot: 9

***Top attacking IPs***

- 217.154.124.9
- 4.144.169.44
- 78.30.1.94
- 176.65.141.117
- 51.159.59.17
- 27.150.21.208
- 216.10.242.161
- 65.254.93.52
- 160.251.207.140
- 193.122.200.89

***Top targeted ports/protocols***

- 445
- 22
- 25
- 5060
- UDP/161
- 9100
- TCP/22
- 80
- 443
- 23

***Most common CVEs***

- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2018-10562 CVE-2018-10561
- CVE-2006-2369
- CVE-2005-4050

***Commands attempted by attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- whoami
- lscpu | grep Model
- Enter new UNIX password:

***Signatures triggered***

- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Potential SSH Scan
- 2001219
- GPL SNMP request udp
- 2101417
- GPL SNMP public access udp
- 2101411

***Users / login attempts***

- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/nPSpP4PBW0
- titu/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/09N1RCa1Hs31
- GET / HTTP/1.1/Host: 104.199.212.115:23
- User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36/Accept: */*
- Accept-Encoding: gzip/

***Files uploaded/downloaded***

- wget.sh;
- gpon8080&ipv=0
- Mozi.a+varcron
- w.sh;
- c.sh;

***HTTP User-Agents***

- No HTTP User-Agents were logged in this period.

***SSH clients and servers***

- No specific SSH clients or servers were logged in this period.

***Top attacker AS organizations***

- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A significant number of commands are focused on disabling security measures (e.g., `chattr -ia .ssh`) and reconnaissance (`cat /proc/cpuinfo`, `uname -a`, `whoami`).
- The command to add an SSH key to `authorized_keys` is a common technique for attackers to maintain persistent access.
- Several commands related to downloading and executing scripts (`wget`, `curl`, `sh`) were observed, indicating attempts to install malware or other tools.
- There were multiple attempts to change user passwords, as indicated by the "Enter new UNIX password: " prompt.
- The presence of "Mozi.a+varcron" in downloaded files suggests activity from the Mozi botnet.
- The high number of attacks on port 25 (SMTP) from a single IP address (176.65.141.117) suggests a targeted spam or mail-based attack campaign.
