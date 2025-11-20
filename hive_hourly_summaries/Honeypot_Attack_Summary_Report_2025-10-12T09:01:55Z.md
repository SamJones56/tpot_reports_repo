Honeypot Attack Summary Report

Report Generated: 2025-10-12T09:01:31Z
Timeframe: 2025-10-12T08:20:01Z to 2025-10-12T09:00:01Z
Files Used: agg_log_20251012T082001Z.json, agg_log_20251012T084001Z.json, agg_log_20251012T090001Z.json

Executive Summary

This report summarizes 29,829 attacks recorded by the honeypot network. The majority of attacks were captured by the Dionaea, Honeytrap, and Cowrie honeypots. The most targeted ports were 445 (SMB) and 5038. The top attacking IP addresses were 122.121.74.82 and 173.239.216.40. Several CVEs were detected, with CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, including efforts to modify SSH authorized_keys.

Detailed Analysis

* Attacks by honeypot:
- Dionaea
- Honeytrap
- Cowrie
- Suricata
- Ciscoasa
- Sentrypeer
- Tanner
- Mailoney
- Miniprint
- Redishoneypot
- H0neytr4p
- Adbhoney
- Honeyaml
- Ipphoney
- ssh-rsa
- ConPot

* Top attacking IPs:
- 122.121.74.82
- 173.239.216.40
- 160.25.81.48
- 196.251.88.103
- 45.91.193.63
- 45.128.199.212
- 31.40.204.154
- 193.24.123.88
- 183.80.234.148
- 36.50.176.144
- 152.32.134.231
- 94.182.152.17
- 81.211.72.167
- 43.229.78.35
- 62.141.43.183
- 122.175.19.236
- 89.218.69.66
- 196.251.71.24
- 59.98.83.57
- 59.98.148.5

* Top targeted ports/protocols:
- 445
- 5038
- 5060
- 22
- 1433
- UDP/5060
- TCP/21
- 80
- 5903
- 21
- 3306
- TCP/1433
- 25
- 5908
- 5909
- 5901
- 23
- 9093
- 10013
- 8333

* Most common CVEs:
- CVE-2022-27255
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013
- CVE-1999-0517

* Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

* Signatures triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

* Users / login attempts:
- cron/
- 345gs5662d34/345gs5662d34
- super/super
- debian/77
- root/emad
- root/sipwise
- root/!@#
- admin/1q2w3e
- user/0000
- root/Matthew
- user/marjory1
- user/tttttttttttttttt
- user/corw1n
- user/chinamotion
- user/aout
- user/111111

* Files uploaded/downloaded:
- sh
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

* HTTP User-Agents:
- No data recorded in this period.

* SSH clients:
- No data recorded in this period.

* SSH servers:
- No data recorded in this period.

* Top attacker AS organizations:
- No data recorded in this period.

Key Observations and Anomalies

- A significant amount of scanning activity was observed, particularly for SMB (port 445) and SIP (port 5060).
- The repeated attempts to modify SSH `authorized_keys` files indicate a common tactic to establish persistent access.
- The presence of commands to download and execute `urbotnetisass` payloads suggests a coordinated botnet campaign.
- A variety of CVEs were targeted, showing that attackers are attempting to exploit a range of vulnerabilities.
- The login attempts show a mix of default credentials and more targeted usernames.
