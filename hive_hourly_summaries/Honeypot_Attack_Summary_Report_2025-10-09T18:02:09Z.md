Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T18:01:29Z
**Timeframe:** 2025-10-09T17:20:01Z to 2025-10-09T18:00:01Z
**Log Files:**
- agg_log_20251009T172001Z.json
- agg_log_20251009T174001Z.json
- agg_log_20251009T180001Z.json

### Executive Summary

This report summarizes 16,943 malicious events recorded by honeypots over a 40-minute period. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH brute-force attempts. The most active attacking IP was 167.250.224.25. A significant number of attacks also targeted email (port 25) and VNC services. The most frequently observed CVE was CVE-2005-4050, related to a vulnerability in Macromedia ColdFusion.

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 8412
- Honeytrap: 3069
- Suricata: 2154
- Mailoney: 863
- Ciscoasa: 1593
- Sentrypeer: 536
- Adbhoney: 89
- Dionaea: 83
- Redishoneypot: 37
- H0neytr4p: 38
- ConPot: 36
- Tanner: 33
- Heralding: 67
- Honeyaml: 17
- ElasticPot: 8
- Ipphoney: 5
- Dicompot: 3

**Top Attacking IPs**
- 167.250.224.25: 2010
- 139.196.218.159: 1254
- 86.54.42.238: 821
- 212.87.220.20: 828
- 80.94.95.238: 579
- 103.189.234.25: 539
- 161.35.71.172: 465
- 43.225.158.169: 401
- 148.222.199.237: 407
- 196.251.80.30: 342
- 88.210.63.16: 381
- 198.23.190.58: 292
- 138.124.158.147: 539
- 77.50.63.250: 194
- 185.81.152.174: 189
- 183.131.109.159: 124
- 159.89.121.144: 108
- 103.250.11.235: 90
- 84.22.149.133: 114
- 68.183.193.0: 68

**Top Targeted Ports/Protocols**
- 22: 1323
- 25: 867
- 5060: 536
- 5903: 209
- UDP/5060: 147
- 8333: 93
- 5901: 76
- 5908: 83
- 5909: 82
- 6379: 37
- 5555: 37
- UDP/161: 43
- 3306: 38
- 80: 33
- vnc/5900: 67
- 23: 17
- 443: 24
- 1050: 39
- 2078: 26
- 5601: 24

**Most Common CVEs**
- CVE-2005-4050: 126
- CVE-2002-0013 CVE-2002-0012: 22
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 19
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0517: 1
- CVE-2009-2765: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 29
- lockr -ia .ssh: 29
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 29
- cat /proc/cpuinfo | grep name | wc -l: 29
- Enter new UNIX password: : 29
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 29
- crontab -l: 29
- uname -m: 29
- top: 29
- uname -a: 29
- whoami: 29
- uname -s -v -n -r -m: 3
- cd /data/local/tmp; ...: 1
- cd /data/local/tmp/; rm *; ...: 1

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 565
- 2023753: 565
- ET DROP Dshield Block Listed Source group 1: 358
- 2402000: 358
- ET SCAN NMAP -sS window 1024: 152
- 2009582: 152
- ET VOIP MultiTech SIP UDP Overflow: 126
- 2003237: 126
- ET HUNTING RDP Authentication Bypass Attempt: 98
- 2034857: 98
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET INFO VNC Authentication Failure: 66
- 2002920: 66
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 17
- 2403347: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 24
- 2403342: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 27
- 2403341: 27

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 28
- root/: 21
- odoo15/odoo15!: 9
- odoo15/3245gs5662d34: 9
- nobody/nobody88: 6
- nobody/nobody10: 4
- nobody/nobody12: 6
- supervisor/supervisor3: 6
- root/88888888: 6
- debian/debian5: 6
- root/ISS@bel@1234: 4
- root/ISS@bel@12345: 4
- root/ISSABEL@1234: 4
- root/Iss@bel@123: 4

**Files Uploaded/Downloaded**
- 11: 8
- fonts.gstatic.com: 8
- css?family=Libre+Franklin...: 7
- ie8.css?ver=1.0: 7
- html5.js?ver=3.7.3: 7
- Mozi.m: 1
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2

**HTTP User-Agents**
- No user agents were logged in this period.

**SSH Clients**
- No SSH clients were logged in this period.

**SSH Servers**
- No SSH servers were logged in this period.

**Top Attacker AS Organizations**
- No AS organizations were logged in this period.

### Key Observations and Anomalies

- The high number of commands related to modifying SSH authorized_keys files indicates a persistent campaign to establish lasting remote access.
- The `boatnet` and `urbotnetisass` file downloads suggest attempts to install IoT botnet malware.
- The variety of usernames and passwords attempted, especially those related to "ISSABEL", suggests targeted attacks against specific PBX software.
- A significant number of security signatures triggered were related to scanning activities, indicating that many attackers were in a reconnaissance phase.