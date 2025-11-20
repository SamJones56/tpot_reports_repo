
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T23:01:29Z
**Timeframe:** 2025-10-13T22:20:01Z to 2025-10-13T23:00:01Z
**Files Used:**
- agg_log_20251013T222001Z.json
- agg_log_20251013T224001Z.json
- agg_log_20251013T230001Z.json

## Executive Summary

This report summarizes 18,511 security events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most targeted ports were 5060 (SIP) and 22 (SSH). A significant number of brute-force attempts and command execution were observed, with a focus on establishing remote access and deploying malware.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 10514
- Sentrypeer: 2949
- Honeytrap: 1312
- Suricata: 1310
- Dionaea: 945
- Mailoney: 868
- Tanner: 192
- H0neytr4p: 120
- Wordpot: 105
- Adbhoney: 55
- Miniprint: 51
- Honeyaml: 24
- Redishoneypot: 23
- Dicompot: 17
- ElasticPot: 10
- Ciscoasa: 9
- Heralding: 3
- ConPot: 3
- Ipphoney: 1

### Top Attacking IPs
- 185.243.5.146: 1103
- 45.236.188.4: 870
- 134.199.200.89: 863
- 86.54.42.238: 820
- 223.100.22.69: 780
- 196.251.88.103: 719
- 185.243.5.148: 686
- 193.253.220.32: 668
- 196.189.155.74: 479
- 45.8.22.226: 413
- 172.86.95.115: 400
- 43.204.23.161: 400
- 172.86.95.98: 368
- 162.240.212.247: 347
- 114.67.80.206: 331
- 152.32.206.160: 281
- 186.96.151.198: 261
- 69.166.232.9: 260
- 103.226.138.95: 241
- 103.7.118.229: 232

### Top Targeted Ports/Protocols
- 5060: 2949
- 22: 1485
- 445: 861
- 25: 868
- 80: 304
- 443: 120
- TCP/22: 55
- 9100: 48
- TCP/80: 47
- UDP/5060: 41
- 1453: 39
- 23: 37
- 27017: 32
- 2323: 27
- 6379: 20
- 81: 16
- 6667: 16
- 8888: 15
- 7443: 14
- TCP/443: 5

### Most Common CVEs
- CVE-2006-0189: 11
- CVE-2022-27255 CVE-2022-27255: 11
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2005-4050: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2001-0414: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 54
- lockr -ia .ssh: 54
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 54
- cat /proc/cpuinfo | grep name | wc -l: 54
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 54
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 54
- ls -lh $(which ls): 54
- which ls: 54
- crontab -l: 54
- w: 53
- uname -m: 53
- cat /proc/cpuinfo | grep model | grep name | wc -l: 53
- top: 53
- uname: 53
- uname -a: 53
- whoami: 53
- lscpu | grep Model: 53
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 53
- Enter new UNIX password: : 23
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 23
- Enter new UNIX password:: 14
- echo "root:y18F1BaS1Dvy"|chpasswd|bash: 1

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 378
- 2402000: 378
- ET SCAN NMAP -sS window 1024: 156
- 2009582: 156
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN Potential SSH Scan: 31
- 2001219: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 21
- 2403346: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 21
- 2403344: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 20
- 2403349: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 20
- 2403343: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 19
- 2403341: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 18
- 2403348: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 17
- 2403347: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 16
- 2403342: 16
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29: 12
- 2400028: 12
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 9
- 2010939: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 9
- 2403345: 9

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 52
- root/3245gs5662d34: 27
- root/123@@@: 20
- root/Password@2025: 18
- root/Qaz123qaz: 16
- ftpuser/ftppassword: 9
- guest/guest2020: 6
- support/support2019: 6
- support/password123: 6
- admin/8888888: 6
- operator/operator333: 6
- root/57947584: 6
- root/5555555: 4
- user/qwerty123: 4
- centos/55555: 4
- root/Passw0rd: 4
- centos/marketing: 4
- root/Voip110: 4
- supervisor/supervisor2019: 4
- nobody/99999: 4
- nobody/nobody2016: 4
- root/rootroot: 4
- ubnt/11: 4
- root/zaadmin: 3
- root/Moheb@1374: 3

### Files Uploaded/Downloaded
- sh: 98
- 11: 3
- fonts.gstatic.com: 3
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 3
- ie8.css?ver=1.0: 2
- html5.js?ver=3.7.3: 2
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3
- ns#: 2
- Mozi.a+jaws: 2

### HTTP User-Agents
- No data recorded.

### SSH Clients
- No data recorded.

### SSH Servers
- No data recorded.

### Top Attacker AS Organizations
- No data recorded.

## Key Observations and Anomalies
- A large number of commands are focused on disabling security features, gathering system information, and installing SSH keys for persistent access.
- The `urbotnetisass` malware was downloaded multiple times, targeting different architectures. This suggests a widespread campaign.
- The presence of commands like `chattr -ia .ssh` indicates an attempt to modify immutable files, which is a common technique to gain persistence.
- The variety of credentials used suggests that attackers are using large dictionaries of common and default passwords.
- The high number of scans on port 5060 (SIP) is indicative of VoIP-based attacks, likely aimed at exploiting vulnerabilities in SIP servers.
