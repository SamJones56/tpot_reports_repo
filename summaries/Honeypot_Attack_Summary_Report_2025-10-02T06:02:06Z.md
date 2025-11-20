Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T06:01:21Z
**Timeframe:** 2025-10-02T05:20:01Z - 2025-10-02T06:00:01Z
**Files Used:** agg_log_20251002T052001Z.json, agg_log_20251002T054001Z.json, agg_log_20251002T060001Z.json

**Executive Summary**

This report summarizes 21,271 attacks recorded by honeypot sensors between 05:20 and 06:00 UTC on October 2nd, 2025. The most active honeypot was Honeytrap, and the most frequent attacker IP was 103.220.207.174. A variety of CVEs were targeted, and attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by honeypot:***
*   Honeytrap: 8092
*   Cowrie: 5858
*   Dionaea: 3576
*   Suricata: 1605
*   Ciscoasa: 1069
*   Mailoney: 846
*   Miniprint: 32
*   Tanner: 58
*   H0neytr4p: 31
*   Adbhoney: 28
*   Sentrypeer: 27
*   ElasticPot: 11
*   Honeyaml: 16
*   ConPot: 10
*   Redishoneypot: 6
*   Dicompot: 3
*   Ipphoney: 3

***Top attacking IPs:***
*   103.220.207.174: 6341
*   46.100.101.163: 3100
*   129.212.187.81: 1731
*   64.227.125.115: 1244
*   176.65.141.117: 820
*   179.43.97.86: 338
*   34.84.82.194: 340
*   185.156.73.166: 362
*   92.63.197.55: 356
*   92.63.197.59: 326
*   46.149.176.177: 315
*   179.33.186.151: 312
*   88.214.50.58: 266
*   122.175.19.236: 123
*   157.66.144.17: 98
*   167.99.49.89: 104
*   117.9.168.153: 103
*   207.166.168.62: 99
*   128.199.157.145: 99
*   14.63.217.28: 98

***Top targeted ports/protocols:***
*   445: 3446
*   22: 927
*   25: 841
*   8333: 111
*   11211: 37
*   TCP/1433: 66
*   5901: 61
*   TCP/80: 46
*   1433: 58
*   TCP/8080: 26
*   80: 60
*   23: 35
*   5060: 29
*   UDP/5060: 9
*   UDP/161: 12
*   81: 20
*   443: 25
*   3306: 21
*   9100: 32
*   8086: 15

***Most common CVEs:***
*   CVE-2002-0013 CVE-2002-0012: 10
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
*   CVE-2019-11500 CVE-2019-11500: 3
*   CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 2
*   CVE-2019-16920 CVE-2019-16920: 2
*   CVE-2009-2765: 2
*   CVE-2014-6271: 2
*   CVE-2023-31983 CVE-2023-31983: 2
*   CVE-2023-47565 CVE-2023-47565: 2
*   CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 2
*   CVE-2023-52163 CVE-2023-52163: 1
*   CVE-2024-10914 CVE-2024-10914: 1
*   CVE-2024-3721 CVE-2024-3721: 1
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
*   CVE-2021-42013 CVE-2021-42013: 1
*   CVE-2023-26801 CVE-2023-26801: 1
*   CVE-2020-10987 CVE-2020-10987: 1

***Commands attempted by attackers:***
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
*   lockr -ia .ssh: 20
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 20
*   cat /proc/cpuinfo | grep name | wc -l: 20
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
*   ls -lh $(which ls): 20
*   which ls: 20
*   crontab -l: 21
*   w: 21
*   uname -m: 20
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 20
*   top: 20
*   uname: 20
*   uname -a: 20
*   whoami: 20
*   lscpu | grep Model: 20
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
*   rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 4
*   cd /data/local/tmp/; rm *; busybox wget ...: 4

***Signatures triggered:***
*   ET DROP Dshield Block Listed Source group 1: 350
*   ET SCAN NMAP -sS window 1024: 164
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 142
*   ET HUNTING RDP Authentication Bypass Attempt: 66
*   ET INFO Reserved Internal IP Traffic: 60
*   ET SCAN Suspicious inbound to MSSQL port 1433: 63
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 32
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49: 22
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 27
*   ET CINS Active Threat Intelligence Poor Reputation IP group 41: 19
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43: 24
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 13
*   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 14
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 12

***Users / login attempts:***
*   345gs5662d34/345gs5662d34: 18
*   root/3245gs5662d34: 6
*   root/nPSpP4PBW0: 5
*   ssh/ssh123: 3
*   git/123: 3
*   root/adminHW: 3
*   test/test1234: 3
*   root/LeitboGi0ro: 4
*   root/docker: 3
*   foundry/foundry: 3
*   root/p@ssw0rd: 2
*   developer/developer: 2
*   gitlab/gitlab123: 2
*   apache/apache: 2
*   root/QWERTY123: 2
*   elsearch/elsearch: 2
*   nvidia/nvidia: 2
*   es/es123456: 2
*   tom/tom: 2
*   gitlab/gitlab: 2

***Files uploaded/downloaded:***
*   11: 9
*   fonts.gstatic.com: 9
*   css?family=Libre+Franklin...: 9
*   ie8.css?ver=1.0: 9
*   html5.js?ver=3.7.3: 9
*   arm.urbotnetisass;: 5
*   arm.urbotnetisass: 5
*   arm5.urbotnetisass;: 5
*   arm5.urbotnetisass: 5
*   arm6.urbotnetisass;: 5
*   arm6.urbotnetisass: 5
*   arm7.urbotnetisass;: 5
*   arm7.urbotnetisass: 5
*   x86_32.urbotnetisass;: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass;: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass;: 4
*   mipsel.urbotnetisass: 4
*   apply.cgi: 4
*   wget.sh;: 4
*   34.165.197.224: 4
*   rondo.dgx.sh||busybox: 3
*   rondo.dgx.sh||curl: 3
*   rondo.dgx.sh)|sh&: 3
*   server.cgi...: 4
*   rondo.qre.sh||busybox: 4
*   rondo.qre.sh||curl: 4
*   rondo.qre.sh)|sh: 4

**Key Observations and Anomalies**

*   A significant amount of reconnaissance and automated attacks were observed, particularly targeting SSH (port 22) and SMB (port 445).
*   The attacker with IP 103.220.207.174 was responsible for a large portion of the total attacks.
*   Attackers attempted to download and execute malicious shell scripts, as seen in the commands and files sections. The use of `wget` and `curl` to fetch payloads from remote servers is a common tactic.
*   Multiple attempts to add an SSH key to the `authorized_keys` file were observed, indicating a clear intent to establish persistent access.
*   The CVEs targeted span a wide range of years and products, suggesting that attackers are using a broad set of exploits to find vulnerable systems.

This concludes the Honeypot Attack Summary Report.