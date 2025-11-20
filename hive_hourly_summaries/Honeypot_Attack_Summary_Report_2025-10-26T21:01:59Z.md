Honeypot Attack Summary Report

Report generated at: 2025-10-26T21:01:26Z
Timeframe: 2025-10-26T20:20:01Z to 2025-10-26T21:00:01Z
Files used for this report:
- agg_log_20251026T202001Z.json
- agg_log_20251026T204001Z.json
- agg_log_20251026T210001Z.json

Executive Summary
This report summarizes 26,005 events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot, with a total of 15,744 events. The most prominent attacking IP address was 172.188.91.73, responsible for 11,104 events. Port 22 (SSH) was the most targeted port, with 2,906 attempts. A variety of CVEs were observed, with CVE-2005-4050 being the most frequent. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 15,744
- Honeytrap: 3,747
- Sentrypeer: 1,956
- Ciscoasa: 1,834
- Suricata: 1,555
- Dionaea: 779
- H0neytr4p: 165
- Mailoney: 135
- Redishoneypot: 19
- ConPot: 17
- Honeyaml: 16
- Tanner: 14
- Adbhoney: 9
- Dicompot: 8
- ElasticPot: 6
- Ipphoney: 1

Top Attacking IPs:
- 172.188.91.73
- 144.172.108.231
- 45.86.200.9
- 103.245.18.122
- 185.243.5.148
- 185.243.5.158
- 14.103.228.246
- 36.104.147.6
- 115.21.183.150
- 152.42.216.249
- 107.170.36.5
- 221.161.235.168
- 27.254.235.2
- 14.238.128.219
- 27.254.235.4
- 107.174.52.86

Top Targeted Ports/Protocols:
- 22
- 5060
- 5038
- 445
- 8333
- 443
- 25
- 5903
- 5901
- TCP/22
- UDP/5060

Most Common CVEs:
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2006-2369

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -a
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
- uname
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password: 
- Enter new UNIX password:

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- ubuntu/tizi@123
- bash/Drag1823hcacatcuciocolataABC111
- root/02041992Ionela%^&
- jla/xurros22$
- root/3245gs5662d34

Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- 2012296

HTTP User-Agents:
- No user agents were logged.

SSH Clients:
- No SSH clients were logged.

SSH Servers:
- No SSH servers were logged.

Top Attacker AS Organizations:
- No AS organizations were logged.

Key Observations and Anomalies
- The high volume of attacks from the IP address 172.188.91.73 suggests a targeted or persistent attacker.
- The prevalence of commands related to SSH key manipulation indicates a clear intent to establish persistent backdoor access.
- A significant number of reconnaissance commands were executed, suggesting attackers are actively mapping out the system architecture for further exploitation.
- The variety of honeypots that were triggered indicates a broad spectrum of automated attacks are being launched against the monitored infrastructure.
- The presence of file downloads (wget.sh, w.sh, c.sh) indicates attempts to introduce external payloads onto the system.
- The triggered Suricata signatures show a mix of scanning activity, blocklisted IP traffic, and some specific VoIP and RDP related alerts.
