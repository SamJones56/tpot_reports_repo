**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-02T12:01:32Z
**Timeframe:** 2025-10-02T11:20:01Z to 2025-10-02T12:00:01Z
**Files Used:**
- agg_log_20251002T112001Z.json
- agg_log_20251002T114001Z.json
- agg_log_20251002T120001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 15,769 attacks were recorded. The most targeted honeypot was Honeytrap, and the most frequent attacker IP was 45.234.176.18. The primary targeted port was port 25 (SMTP). A number of CVEs were detected, and various commands were attempted by attackers, primarily focused on reconnaissance and establishing unauthorized access.

**Detailed Analysis**

***

**Attacks by Honeypot**

*   Honeytrap: 8474
*   Cowrie: 2123
*   Ciscoasa: 1704
*   Mailoney: 1545
*   Dionaea: 902
*   Suricata: 860
*   Adbhoney: 32
*   Tanner: 27
*   H0neytr4p: 20
*   ConPot: 20
*   Sentrypeer: 19
*   Redishoneypot: 14
*   ElasticPot: 13
*   Miniprint: 10
*   Dicompot: 4
*   Honeyaml: 2

***

**Top Attacking IPs**

*   45.234.176.18: 7833
*   176.65.141.117: 1502
*   103.65.235.68: 462
*   179.1.143.50: 356
*   185.156.73.166: 295
*   92.63.197.55: 289
*   41.58.186.130: 287
*   92.63.197.59: 270
*   27.147.191.233: 245
*   41.106.128.125: 233
*   14.103.112.5: 144
*   101.250.60.4: 134

***

**Top Targeted Ports/Protocols**

*   25: 1545
*   445: 857
*   22: 331
*   TCP/5432: 62
*   8333: 58
*   TCP/22: 51
*   80: 27
*   1433: 22
*   23: 21
*   TCP/1080: 19
*   5060: 17
*   TCP/1433: 16
*   443: 19
*   TCP/8080: 12
*   9200: 11
*   UDP/53: 13

***

**Most Common CVEs**

*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2010-0569
*   CVE-2016-5696

***

**Commands Attempted by Attacker**

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cd /data/local/tmp/; rm *; busybox wget ...`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `uname -a`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `system`
*   `shell`
*   `q`
*   `/ip cloud print`

***

**Signatures Triggered**

*   ET DROP Dshield Block Listed Source group 1: 152
*   ET SCAN NMAP -sS window 1024: 148
*   ET SCAN Suspicious inbound to PostgreSQL port 5432: 51
*   ET INFO Reserved Internal IP Traffic: 49
*   ET SCAN Potential SSH Scan: 33
*   ET INFO CURL User Agent: 21
*   GPL INFO SOCKS Proxy attempt: 19
*   ET SCAN Suspicious inbound to MSSQL port 1433: 16
*   ET CINS Active Threat Intelligence Poor Reputation IP group 67: 10
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 14
*   ET EXPLOIT RST Flood With Window: 8

***

**Users / Login Attempts**

*   345gs5662d34/345gs5662d34: 8
*   root/nPSpP4PBW0: 3
*   sa/123: 2
*   root/vps123: 2
*   root/disc: 2
*   admin/zabbix!: 2
*   admin/wfp: 2
*   admin/nxf: 2
*   admin/testsite: 2
*   admin/@B0g0r123: 2
*   root/LeitboGi0ro: 2
*   foundry/foundry: 2
*   root/f8t00z2i: 2
*   test/zhbjETuyMffoL8F: 3
*   postgres/postgres123: 2
*   superadmin/admin123: 2

***

**Files Uploaded/Downloaded**

*   arm.urbotnetisass
*   arm5.urbotnetisass
*   arm6.urbotnetisass
*   arm7.urbotnetisass
*   x86_32.urbotnetisass
*   mips.urbotnetisass
*   mipsel.urbotnetisass
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3

***

**HTTP User-Agents**

*   Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

***

**SSH Clients and Servers**

*   No SSH clients or servers were recorded in this timeframe.

***

**Top Attacker AS Organizations**

*   No attacker AS organizations were recorded in this timeframe.

***

**Key Observations and Anomalies**

*   The overwhelming majority of attacks were from the IP address 45.234.176.18, primarily targeting the Honeytrap honeypot. This suggests a targeted campaign from a single source.
*   The most common commands attempted by attackers involve reconnaissance of the system and attempts to establish persistent access by adding SSH keys.
*   The downloaded files, such as `arm.urbotnetisass`, are likely malware payloads for different architectures, indicating that the attackers are attempting to compromise a wide range of devices.
*   The presence of `Dshield Block Listed`, `Spamhaus DROP Listed`, and `CINS Active Threat Intelligence` signatures indicates that many of the attacking IPs are known bad actors.

This concludes the Honeypot Attack Summary Report.