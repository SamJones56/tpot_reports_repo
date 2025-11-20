Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T05:01:29Z
**Timeframe:** 2025-10-17T04:20:01Z to 2025-10-17T05:00:01Z
**Files Used:**
- agg_log_20251017T042001Z.json
- agg_log_20251017T044001Z.json
- agg_log_20251017T050001Z.json

**Executive Summary**

This report summarizes 23,922 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected by Suricata, Dionaea, and Honeytrap. Attackers predominantly targeted SMB (port 445) and SSH (port 22). A number of CVEs were detected, with a high concentration of older vulnerabilities being exploited. A significant number of brute-force login attempts were observed, primarily targeting root accounts.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 9372
- Suricata: 4536
- Dionaea: 3550
- Honeytrap: 3083
- Ciscoasa: 1649
- Sentrypeer: 1332
- ConPot: 139
- Mailoney: 76
- Tanner: 75
- Wordpot: 37
- H0neytr4p: 30
- Honeyaml: 10
- Miniprint: 6
- Redishoneypot: 6
- Heralding: 3
- ElasticPot: 3
- Ipphoney: 3
- Adbhoney: 2

**Top Attacking IPs:**
- 176.49.68.187
- 176.211.19.7
- 36.65.199.71
- 66.116.196.243
- 74.207.247.144
- 125.229.20.145
- 158.51.124.56
- 140.106.25.217
- 175.139.240.217
- 223.221.36.42

**Top Targeted Ports/Protocols:**
- 445 (SMB)
- TCP/445
- 5060 (SIP)
- 22 (SSH)
- UDP/161 (SNMP)
- 161 (SNMP)
- 5903
- 8333
- 80 (HTTP)
- 5901

**Most Common CVEs:**
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2021-3449
- CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255
- CVE-2019-11500
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2020-10987
- CVE-2023-31983
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056
- CVE-2002-1149
- CVE-2023-49103
- CVE-2024-50340
- CVE-2005-4050
- CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
- CVE-2001-0414

**Commands Attempted by Attackers:**
- uname -a
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- Enter new UNIX password:
- chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; ...

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- GPL SNMP request udp
- GPL SNMP public access udp
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 44

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/QWE123!@#qwe
- root/123@@@
- root/Qaz123qaz
- ftpuser/ftppassword
- root/3245gs5662d34
- guest/3333333
- operator/operator2014
- blank/1q2w3e4r
- root/0n3w0rld

**Files Uploaded/Downloaded:**
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=
- rondo.qre.sh||busybox
- rondo.qre.sh||curl
- rondo.qre.sh)|sh
- `busybox`
- rondo.sbx.sh|sh&echo${IFS}
- login_pic.asp
- ns#
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- sh

**HTTP User-Agents:**
- No user agents were logged in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- **High Volume of SMB Exploitation:** A large number of events were related to the DoublePulsar backdoor, indicating continued exploitation of the vulnerabilities associated with the Shadow Brokers leak.
- **Prevalence of Older CVEs:** Many of the CVEs being scanned for are from the early 2000s, suggesting that attackers are still targeting legacy systems that may not be patched.
- **Automated SSH Attacks:** The patterns of commands executed and login attempts suggest highly automated attacks, likely from botnets, aimed at reconnaissance and establishing persistence. The use of commands to add SSH keys to `authorized_keys` is a common tactic for maintaining access.
- **SNMP Scanning:** A significant number of SNMP-related signatures were triggered, indicating that attackers are actively scanning for and attempting to exploit devices with public-facing SNMP services.
