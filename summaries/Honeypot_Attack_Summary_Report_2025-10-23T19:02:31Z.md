Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T19:01:50Z
**Timeframe:** 2025-10-23T18:20:01Z to 2025-10-23T19:00:01Z

**Files Used to Generate Report:**
- agg_log_20251023T182001Z.json
- agg_log_20251023T184001Z.json
- agg_log_20251023T190001Z.json

**Executive Summary**

This report summarizes 26,632 events collected from the honeypot network. The most active honeypots were Tanner (web), H0neytr4p (web), and Suricata (NIDS). A significant portion of the attacks originated from the IP address 139.87.113.204. The most targeted ports were 80 (HTTP), 443 (HTTPS), and 445 (SMB). Scans for vulnerabilities related to Log4j (CVE-2021-44228) and older web server vulnerabilities were prevalent. Attackers were observed attempting to gain shell access and download malicious files.

**Detailed Analysis**

***Attacks by Honeypot***
- Tanner: 6756
- H0neytr4p: 5192
- Suricata: 4150
- Cowrie: 3035
- Dionaea: 2550
- Honeytrap: 1719
- Heralding: 1449
- Ciscoasa: 1027
- Sentrypeer: 487
- ConPot: 135
- Mailoney: 86
- ElasticPot: 30
- Redishoneypot: 6
- Dicompot: 6
- Adbhoney: 3
- Honeyaml: 1

***Top Attacking IPs***
- 139.87.113.204: 14763
- 10.140.0.3: 1649
- 185.243.96.105: 1453
- 45.171.150.123: 1232
- 128.234.98.110: 800
- 196.251.88.103: 473
- 200.218.226.68: 360
- 107.170.36.5: 151
- 190.99.154.38: 159
- 124.221.255.188: 137
- 122.155.223.9: 146
- 203.106.164.74: 164

***Top Targeted Ports/Protocols***
- 80: 6756
- 443: 5192
- 445: 2036
- vnc/5900: 1443
- 5060: 487
- TCP/80: 1106
- UDP/161: 461
- 22: 475

***Most Common CVEs***
- CVE-2021-44228: 235
- CVE-2002-0013 CVE-2002-0012: 243
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 222
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 53
- CVE-2000-0411 CVE-1999-0172: 33
- CVE-2003-0825: 22
- CVE-2002-1149: 64
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 12
- CVE-2025-5777: 7
- CVE-2025-27636: 5
- CVE-2022-27255: 4
- CVE-2021-36380: 2
- CVE-2021-45382: 2
- CVE-2024-24919: 2
- CVE-2025-61884: 2
- CVE-2020-26919: 2
- CVE-2007-0350: 2
- CVE-2021-31755: 2
- CVE-2021-35395: 2
- CVE-2024-0769: 1
- CVE-2024-2389: 1
- CVE-2024-50340: 1
- CVE-2024-0012: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:

***Signatures Triggered***
- ET INFO VNC Authentication Failure
- GPL WEB_SERVER /etc/passwd
- ET SCAN Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack
- GPL SNMP public access udp
- ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt
- ET DROP Dshield Block Listed Source group 1
- ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)

***Users / Login Attempts***
- uti5Kqnr/pproCrD4
- 345gs5662d34/345gs5662d34
- anyuser/anypass
- root/constantino
- root/CorpomedicA593

***Files Uploaded/Downloaded***
- 139.87.113.204:44618
- 115.212.199.104.bc.googleusercontent.com
- perl|perl
- arm.urbotnetisass
- FGx8SNCa4txePA.mips;

***HTTP User-Agents***
- No HTTP User-Agents were recorded in the logs.

***SSH Clients and Servers***
- No SSH clients or servers were recorded in the logs.

***Top Attacker AS Organizations***
- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- The IP address 139.87.113.204 was responsible for a disproportionately high volume of traffic, primarily targeting web-related ports.
- There is a continued focus on exploiting the Log4j vulnerability (CVE-2021-44228).
- A number of commands executed by attackers are aimed at establishing persistent SSH access by modifying the `.ssh/authorized_keys` file.
- The VNC protocol (port 5900) is a significant target, with a large number of authentication failures, indicating brute-force attempts.
- Attackers are attempting to download and execute malicious binaries, as seen in the "Files Uploaded/Downloaded" section.
