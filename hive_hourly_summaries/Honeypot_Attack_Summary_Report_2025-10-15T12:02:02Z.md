Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T12:01:36Z
**Timeframe of Report:** 2025-10-15T11:20:01Z to 2025-10-15T12:00:01Z
**Files Used to Generate Report:**
- agg_log_20251015T112001Z.json
- agg_log_20251015T114001Z.json
- agg_log_20251015T120001Z.json

**Executive Summary**
This report summarizes 29,978 events collected from the honeypot network. The majority of attacks were credential stuffing and scanning attempts. The most active honeypots were Heralding and Suricata. The most common attack vector was VNC on port 5900, originating from the IP address 45.134.26.47. A number of CVEs were targeted, and attackers attempted to run various commands, including reconnaissance and malware downloads.

**Detailed Analysis**

**Attacks by Honeypot:**
- Heralding: 10570
- Suricata: 9164
- Honeytrap: 3940
- Cowrie: 2510
- Sentrypeer: 2151
- Ciscoasa: 1110
- Dionaea: 295
- Tanner: 109
- H0neytr4p: 46
- Honeyaml: 25
- Mailoney: 23
- Redishoneypot: 15
- ElasticPot: 9
- ConPot: 6
- Adbhoney: 5

**Top Attacking IPs:**
- 45.134.26.47: 10571
- 172.31.36.128: 4505
- 10.17.0.5: 2281
- 10.140.0.3: 1594
- 185.243.5.121: 1289
- 45.134.26.20: 1003
- 206.191.154.180: 942
- 45.134.26.62: 500
- 46.32.178.94: 317
- 193.24.123.88: 280
- 172.86.95.115: 320
- 172.86.95.98: 306
- 198.23.248.151: 154
- 62.141.43.183: 213
- 167.250.224.25: 80

**Top Targeted Ports/Protocols:**
- vnc/5900: 10570
- 5060: 2151
- 22: 349
- 1433: 244
- 8333: 139
- 80: 113
- 5903: 126
- UDP/5060: 54
- TCP/22: 43
- 5908: 55
- 5909: 55
- 5901: 49
- 23: 51

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2002-1149
- CVE-2019-11500 CVE-2019-11500
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2025-57819 CVE-2025-57819

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
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
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- cat /proc/uptime 2 > /dev/null | cut -d. -f1
- Enter new UNIX password:
- Enter new UNIX password:

**Signatures Triggered:**
- ET INFO VNC Authentication Failure: 8307
- 2002920: 8307
- ET DROP Dshield Block Listed Source group 1: 198
- 2402000: 198
- ET SCAN NMAP -sS window 1024: 100
- 2009582: 100
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 53
- 2023753: 53
- ET SCAN Potential SSH Scan: 38
- 2001219: 38
- ET INFO Reserved Internal IP Traffic: 38
- 2002752: 38
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 26
- 2012297: 26
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 24
- 2012296: 24
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 44
- 2010517: 44
- GPL TELNET Bad Login: 18
- 2101251: 18
- ET SCAN Suspicious inbound to MSSQL port 1433: 49
- 2010935: 49

**Users / Login Attempts:**
- root/zx3275po
- user/654321
- 345gs5662d34/345gs5662d34
- default/password321
- root/tass
- support/7777
- supervisor/12345
- centos/123654
- debian/123321
- root/lqrs!15d7
- nobody/33333
- root/1234@qwer
- nginx/nginx
- config/qwerty1234
- root/root2000
- root/3245gs5662d34
- test/test888
- root/68NGHcx6TuwTT8T
- root/aJp7U_QGHNqyTCkpUQhY

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- Go-http-client/1.1

**SSH Clients and Servers:**
- No SSH client or server information was found in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organization information was found in the logs.

**Key Observations and Anomalies**
- A significant amount of scanning and brute-force activity was observed from the IP address 45.134.26.47, primarily targeting VNC services.
- Attackers were observed attempting to download and execute various malware payloads, such as `urbotnetisass`.
- A number of commands were executed to gather system information, which is a common reconnaissance technique.
- There were several attempts to add an SSH key to the `authorized_keys` file, which would allow the attacker to maintain persistent access.
- Some new CVEs, such as CVE-2025-57819, were observed in the logs.

This concludes the Honeypot Attack Summary Report.
