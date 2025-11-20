Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T17:01:29Z
**Timeframe:** 2025-09-30T16:20:01Z - 2025-09-30T17:00:01Z
**Files Used:** agg_log_20250930T162001Z.json, agg_log_20250930T164001Z.json, agg_log_20250930T170001Z.json

**Executive Summary**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 9137 attacks were recorded. The most targeted services were Cowrie (SSH), Suricata (IDS), and Honeytrap. The top attacking IP address was 187.201.26.33. A significant amount of activity was aimed at port 445/TCP, likely related to SMB exploits. Several CVEs were detected, and a variety of malicious commands were attempted, including downloading and executing scripts.

**Detailed Analysis**

**Attacks by Honeypot**

*   Cowrie: 2416
*   Suricata: 2471
*   Honeytrap: 1685
*   Ciscoasa: 1372
*   Mailoney: 833
*   Dionaea: 104
*   Tanner: 72
*   Miniprint: 60
*   Adbhoney: 39
*   ConPot: 39
*   Sentrypeer: 20
*   H0neytr4p: 17
*   Redishoneypot: 5
*   Dicompot: 3
*   Ipphoney: 1

**Top Attacking IPs**

*   187.201.26.33: 1307
*   86.54.42.238: 821
*   45.78.224.161: 746
*   64.23.189.160: 239
*   78.10.232.82: 228
*   206.42.56.228: 228
*   94.41.18.235: 245
*   185.156.73.167: 359
*   185.156.73.166: 351
*   92.63.197.55: 340
*   92.63.197.59: 312
*   147.185.40.116: 140
*   123.253.22.8: 71
*   45.112.72.65: 66
*   36.67.70.198: 57

**Top Targeted Ports/Protocols**

*   TCP/445: 1302
*   25: 833
*   22: 369
*   8333: 138
*   23: 97
*   80: 64
*   3306: 69
*   9100: 60
*   2323: 48
*   TCP/80: 69
*   TCP/1433: 26
*   1025: 24
*   TCP/22: 29
*   8008: 19
*   8000: 19

**Most Common CVEs**

*   CVE-2002-0013 CVE-2002-0012
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2024-4577 CVE-2002-0953
*   CVE-2024-4577 CVE-2024-4577
*   CVE-2021-35394 CVE-2021-35394
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2001-0414
*   CVE-2024-40891 CVE-2024-40891
*   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
*   CVE-2021-42013 CVE-2021-42013

**Commands Attempted by Attackers**

*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   Enter new UNIX password: 
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   top
*   uname
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   cd /data/local/tmp/; rm *; busybox wget ...
*   INFO PRODINFO
*   rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...

**Signatures Triggered**

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1300
*   ET DROP Dshield Block Listed Source group 1: 336
*   ET SCAN NMAP -sS window 1024: 192
*   ET INFO Reserved Internal IP Traffic: 58
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 34
*   ET INFO curl User-Agent Outbound: 12
*   ET HUNTING curl User-Agent to Dotted Quad: 12
*   ET SCAN Suspicious inbound to PostgreSQL port 5432: 11
*   ET SCAN Suspicious inbound to MSSQL port 1433: 23
*   ET INFO CURL User Agent: 24

**Users / Login Attempts**

*   testuser/: 66
*   345gs5662d34/345gs5662d34: 6
*   root/LeitboGi0ro: 3
*   minecraft/3245gs5662d34: 3
*   foundry/foundry: 3
*   mbp/mbp: 3
*   root/2glehe5t24th1issZs: 3
*   anonymous/: 2
*   root/gading: 2
*   root/abcABC123: 2

**Files Uploaded/Downloaded**

*   sh: 98
*   wget.sh;: 8
*   arm.urbotnetisass;: 4
*   arm.urbotnetisass: 4
*   arm5.urbotnetisass;: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass;: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass;: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass;: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass;: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass;: 4
*   mipsel.urbotnetisass: 4
*   w.sh;: 2
*   c.sh;: 2
*   boatnet.mpsl;: 1

**Key Observations and Anomalies**

*   The high number of attacks on port 445/TCP from a single IP (187.201.26.33) suggests a targeted SMB vulnerability scan or exploit attempt.
*   The commands attempted indicate a focus on establishing persistent access via SSH keys and downloading and executing malicious scripts.
*   The `urbotnetisass` files downloaded suggest an attempt to install a botnet client on various architectures.
*   The presence of the DoublePulsar backdoor signature indicates attempts to exploit SMB vulnerabilities, likely related to the EternalBlue exploit.
*   No significant HTTP User-Agents, SSH clients, SSH servers, or AS organizations were observed in the logs.
