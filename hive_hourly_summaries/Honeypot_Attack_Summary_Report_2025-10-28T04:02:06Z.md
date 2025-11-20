Here is the consolidated Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-28T04:01:33Z
**Timeframe:** 2025-10-28T03:20:01Z to 2025-10-28T04:00:02Z
**Files Used:**
* agg_log_20251028T032001Z.json
* agg_log_20251028T034001Z.json
* agg_log_20251028T040002Z.json

**Executive Summary**

This report summarizes 17,781 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. A significant portion of the attacks were reconnaissance scans and brute-force attempts targeting services like SMB (port 445), SIP (port 5060), and SSH (port 22). Attackers were observed attempting to download and execute malicious payloads, and a variety of CVEs were targeted. The top attacking IP addresses originate from a diverse range of networks.

**Detailed Analysis**

***Attacks by honeypot:***
* Cowrie: 4751
* Dionaea: 3765
* Honeytrap: 3333
* Suricata: 1965
* Ciscoasa: 1872
* Sentrypeer: 1751
* Mailoney: 136
* Tanner: 61
* Redishoneypot: 47
* Adbhoney: 31
* H0neytr4p: 22
* Miniprint: 14
* ElasticPot: 13
* ConPot: 17
* Honeyaml: 2
* Ipphoney: 1

***Top attacking IPs:***
* 103.4.102.216: 1676
* 106.14.67.229: 1122
* 144.172.108.231: 1092
* 180.232.204.50: 1078
* 45.132.75.33: 857
* 221.121.100.32: 767
* 167.71.11.218: 525
* 20.2.136.52: 361
* 163.172.99.31: 353
* 185.193.240.246: 144
* 185.243.5.121: 257
* 88.210.63.16: 188
* 107.170.36.5: 245
* 211.254.212.59: 208
* 212.25.35.66: 193
* 69.63.77.146: 181
* 167.250.224.25: 142
* 152.32.201.226: 129
* 124.29.200.242: 89
* 77.83.207.203: 125
* 91.224.92.34: 111
* 68.183.149.135: 74
* 68.183.207.213: 63

***Top targeted ports/protocols:***
* 445: 3716
* 5060: 1751
* 22: 854
* 5901: 216
* 25: 136
* 1167: 117
* 5903: 131
* 8333: 98
* TCP/22: 108
* 1234: 68
* 80: 58
* TCP/80: 71
* 5904: 76
* 5905: 74
* 6379: 37
* 5907: 49
* 5908: 50
* 5909: 50
* 5902: 44
* 3128: 44
* 23: 23

***Most common CVEs:***
* CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
* CVE-2019-11500
* CVE-2021-3449
* CVE-1999-0183
* CVE-2017-3506, CVE-2017-3606
* CVE-2019-16920
* CVE-2021-35395
* CVE-2016-20017
* CVE-2024-12856, CVE-2024-12885
* CVE-2014-6271
* CVE-2023-52163
* CVE-2023-47565
* CVE-2023-31983
* CVE-2024-10914
* CVE-2009-2765
* CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056
* CVE-2024-3721
* CVE-2006-3602, CVE-2006-4458, CVE-2006-4542
* CVE-2021-42013
* CVE-2018-7600

***Commands attempted by attackers:***
* Reconnaissance: `uname -a`, `whoami`, `cat /proc/cpuinfo`, `lscpu`, `free -m`, `w`, `crontab -l`
* Payload download and execution: `cd /data/local/tmp/; rm *; busybox wget http://...`, `curl http://...`, `chmod +x ...`, `./...`
* SSH key manipulation: `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
* Password changes: `echo -e "..."|passwd|bash`

***Signatures triggered:***
* ET DROP Dshield Block Listed Source group 1
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET SCAN NMAP -sS window 1024
* ET HUNTING RDP Authentication Bypass Attempt
* ET SCAN Potential SSH Scan
* ET INFO Reserved Internal IP Traffic
* ET CINS Active Threat Intelligence Poor Reputation IP
* ET DROP Spamhaus DROP Listed Traffic Inbound

***Users / login attempts:***
* A wide variety of username/password combinations were attempted, with `root`, `admin`, and other common service names being the most frequent targets. Examples include: `root/jwc8carter`, `admin/admin01`, `pi/raspberry`, `ubnt/ubnt`.

***Files uploaded/downloaded:***
* Malicious shell scripts: `w.sh`, `c.sh`, `wget.sh`
* ELF executables for various architectures: `arm.uhavenobotsxd`, `mips.uhavenobotsxd`, `x86_32.uhavenobotsxd`
* Web-related files: `soap-envelope`, `server.cgi`, `system.html`

***HTTP User-Agents:***
* No HTTP user-agents were recorded in this period.

***SSH clients and servers:***
* No specific SSH clients or servers were identified in this period.

***Top attacker AS organizations:***
* No attacker AS organizations were identified in this period.

**Key Observations and Anomalies**

* A significant number of commands were aimed at downloading and executing botnet-related malware.
* The targeting of a wide range of CVEs indicates that attackers are using automated tools to scan for multiple vulnerabilities.
* The high volume of traffic to port 445 (SMB) suggests widespread scanning for vulnerabilities like EternalBlue.
* The presence of commands to manipulate SSH authorized keys is a common technique for attackers to maintain persistent access to a compromised system.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.
