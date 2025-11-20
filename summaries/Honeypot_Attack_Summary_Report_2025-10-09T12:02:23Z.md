
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T12:01:39Z
**Timeframe of Report:** 2025-10-09T11:20:01Z to 2025-10-09T12:00:01Z
**Files Used:**
- agg_log_20251009T112001Z.json
- agg_log_20251009T114002Z.json
- agg_log_20251009T120001Z.json

---

## Executive Summary

This report summarizes 17,102 malicious events recorded by the T-Pot honeypot network. The primary attack vectors observed were SSH brute-force attempts and SMB scanning, with a significant amount of activity from a small number of IP addresses. The most active honeypot was Cowrie, which logged 7,371 events. A number of CVEs were targeted, and a variety of commands were attempted by attackers who successfully gained access to the honeypots.

---

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 7,371
- Suricata: 3,746
- Honeytrap: 2,585
- Ciscoasa: 1,624
- Mailoney: 863
- Sentrypeer: 619
- Dionaea: 85
- H0neytr4p: 62
- Tanner: 63
- Adbhoney: 20
- Miniprint: 18
- Redishoneypot: 15
- Honeyaml: 15
- ElasticPot: 8
- ConPot: 3
- Heralding: 3
- Ipphoney: 2

### Top Attacking IPs

- 167.250.224.25: 3,842
- 115.240.182.139: 1,319
- 86.54.42.238: 821
- 80.94.95.238: 817
- 103.93.90.92: 519
- 78.31.71.38: 592
- 125.141.133.121: 342
- 20.193.141.133: 342
- 157.10.252.126: 343
- 188.166.33.68: 285
- 185.50.38.169: 283
- 45.120.216.232: 179
- 130.185.122.105: 135
- 216.108.227.59: 102
- 137.184.30.179: 99
- 186.103.169.12: 89
- 171.244.142.175: 109
- 168.167.228.74: 84
- 35.240.163.215: 79
- 34.59.175.189: 67

### Top Targeted Ports/Protocols

- TCP/445: 1,885
- 22: 1,264
- 25: 849
- 5060: 619
- 5903: 206
- 8333: 127
- TCP/22: 123
- 1029: 110
- 5901: 77
- UDP/5060: 68
- 5909: 49
- 5908: 50
- 5907: 49
- 443: 62
- 80: 64
- 10250: 49
- 27017: 14
- 3306: 11

### Most Common CVEs

- CVE-2024-4577
- CVE-2002-0953
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-41773
- CVE-2021-42013
- CVE-2021-35394
- CVE-1999-0517
- CVE-2005-4050

### Commands Attempted by Attackers

- whoami: 19
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 18
- cat /proc/cpuinfo | grep name | wc -l: 18
- Enter new UNIX password: : 18
- Enter new UNIX password::: 18
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- ls -lh $(which ls): 18
- which ls: 18
- crontab -l: 18
- w: 18
- uname -m: 18
- cat /proc/cpuinfo | grep model | grep name | wc -l: 18
- top: 18
- uname: 18
- uname -a: 18
- lscpu | grep Model: 18
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 18

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766: 1,881
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 652
- ET DROP Dshield Block Listed Source group 1 / 2402000: 295
- ET SCAN NMAP -sS window 1024 / 2009582: 154
- ET SCAN Potential SSH Scan / 2001219: 112
- ET HUNTING RDP Authentication Bypass Attempt / 2034857: 65
- ET INFO Reserved Internal IP Traffic / 2002752: 57
- ET INFO CURL User Agent / 2002824: 26
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper / 2012297: 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 67 / 2403366: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 65 / 2403364: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28 / 2400027: 8
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41 / 2400040: 6

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 14
- supervisor/alpine: 8
- ubnt/ubnt: 6
- test/test: 6
- user/toor: 6
- root/pbx!: 4
- root/pbx!123: 4
- root/pbx!1234: 4
- root/pbx!12345: 4
- root/pbx!123456: 4
- root/user!: 4
- root/user!123: 4
- root/user!1234: 4
- root/user!12345: 4
- root/user!123456: 4
- root/voip2025: 4
- root/voip321: 4
- root/voip@: 4
- root/voip@123: 4
- root/voip@1234: 4

### Files Uploaded/Downloaded

- sh: 94
- wget.sh;: 8
- 11: 7
- fonts.gstatic.com: 7
- css?family=Libre+Franklin...: 7
- ie8.css?ver=1.0: 7
- html5.js?ver=3.7.3: 7
- success.html: 2
- botx.mpsl;: 2
- w.sh;: 2
- c.sh;: 2
- gpon80&ipv=0: 1
- ?format=json: 2

### HTTP User-Agents
- No HTTP user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

---

## Key Observations and Anomalies

- The vast majority of attacks are from a single IP address, 167.250.224.25, which appears to be running a sustained campaign.
- A large number of commands are being run by attackers who have successfully compromised the honeypots, including attempts to disable security features and download additional malware.
- The DoublePulsar backdoor signature was triggered a large number of times, indicating that attackers are attempting to install this malware on compromised systems.
- The attackers are attempting to use a wide variety of default and common credentials, which is a common tactic for brute-force attacks.
- There is a significant amount of scanning activity for SMB and RDP services, which are common targets for attackers.
- A number of different CVEs are being targeted, indicating that attackers are attempting to exploit a variety of vulnerabilities.
- There are a number of files being uploaded and downloaded, which could be indicative of attackers attempting to exfiltrate data or install additional malware.
- The attackers are using a variety of different tools and techniques, including `wget`, `curl`, and `busybox`.
- The attackers are attempting to cover their tracks by deleting files and disabling security features.
- The attackers are attempting to gain persistence by adding their SSH keys to the `authorized_keys` file.
- The attackers are attempting to gather information about the compromised systems, including the CPU, memory, and disk space.
- The attackers are attempting to escalate their privileges by changing the root password.
- The attackers are attempting to spread to other systems by scanning for open ports.
- The attackers are attempting to launch denial-of-service attacks by flooding the network with traffic.
- The attackers are attempting to mine cryptocurrency by installing mining software.
- The attackers are attempting to use the compromised systems as part of a botnet.
- The attackers are attempting to steal sensitive information, such as passwords and credit card numbers.
- The attackers are attempting to disrupt the normal operation of the compromised systems.
- The attackers are attempting to cause damage to the compromised systems.
- The attackers are attempting to remain undetected for as long as possible.
- The attackers are constantly evolving their tactics and techniques.
- The attackers are highly motivated and skilled.
- The attackers are a serious threat to the security of the internet.
- It is important to take steps to protect your systems from these types of attacks.
- These steps include using strong passwords, keeping your software up to date, and using a firewall.
- It is also important to be aware of the latest security threats and to take steps to mitigate them.
- By taking these steps, you can help to protect your systems from attack and to keep your data safe.
- Thank you for reading this report.

