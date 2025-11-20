Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T05:01:33Z
**Timeframe:** 2025-10-09T04:20:01Z to 2025-10-09T05:00:01Z
**Files Used:**
- agg_log_20251009T042001Z.json
- agg_log_20251009T044001Z.json
- agg_log_20251009T050001Z.json

**Executive Summary**

This report summarizes 17,233 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the attacks originated from IP address 111.68.111.216, which was primarily involved in targeting TCP port 445. Several CVEs were detected, with CVE-2021-3449, CVE-2001-0414, and CVE-2019-11500 being the most frequent. Attackers attempted a variety of commands, primarily focused on system enumeration and establishing remote access.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 5,558
- Suricata: 3,574
- Honeytrap: 3,156
- Dionaea: 2,071
- Ciscoasa: 1,710
- Mailoney: 887
- ConPot: 104
- Sentrypeer: 62
- Honeyaml: 32
- Tanner: 30
- Adbhoney: 13
- H0neytr4p: 16
- ElasticPot: 8
- Redishoneypot: 9
- Dicompot: 3

***Top Attacking IPs***

- 111.68.111.216: 1,430
- 194.163.151.59: 1,078
- 14.224.136.214: 1,264
- 94.103.12.49: 885
- 176.65.141.117: 820
- 80.94.95.238: 685
- 182.73.176.186: 418
- 114.219.56.203: 319
- 46.1.103.71: 356
- 194.147.34.192: 228

***Top Targeted Ports/Protocols***

- TCP/445: 1,428
- 445: 1,281
- 22: 849
- 25: 887
- TCP/21: 220
- 5903: 201
- 8333: 153
- 21: 105
- 1025: 97
- 5901: 72

***Most Common CVEs***

- CVE-2021-3449
- CVE-2001-0414
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- tftp; wget; /bin/busybox EZQKM

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,425
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 519
- ET DROP Dshield Block Listed Source group 1: 467
- ET SCAN NMAP -sS window 1024: 155
- ET FTP FTP PWD command attempt without login: 109
- ET FTP FTP CWD command attempt without login: 110
- ET INFO Reserved Internal IP Traffic: 57
- ET HUNTING RDP Authentication Bypass Attempt: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 25

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- config/config44
- unknown/test
- root/asd12345
- operator/raspberry
- user/raspberry
- supervisor/987654321
- root/111111111
- unknown/unknown2020
- operator/password321

***Files Uploaded/Downloaded***

- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**Key Observations and Anomalies**

- A high number of attacks were focused on SMB (port 445), with a large portion attributed to a single IP address (111.68.111.216), triggering the "DoublePulsar Backdoor" signature. This suggests a targeted campaign to exploit SMB vulnerabilities.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently observed, indicating a common tactic to install a persistent SSH key for backdoor access.
- There is a mix of broad, automated scanning (indicated by the variety of targeted ports and IPs) and more specific, targeted attacks (as seen with the SMB activity).
- The CVEs detected are relatively old, suggesting that attackers are still finding success with well-known vulnerabilities against unpatched systems.
