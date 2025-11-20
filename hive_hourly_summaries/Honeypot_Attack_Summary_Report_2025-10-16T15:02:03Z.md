Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T15:01:36Z
**Timeframe:** 2025-10-16T14:20:01Z to 2025-10-16T15:00:02Z
**Files Used:**
- agg_log_20251016T142001Z.json
- agg_log_20251016T144001Z.json
- agg_log_20251016T150002Z.json

**Executive Summary:**
This report summarizes 28,826 events collected from the honeypot infrastructure. The most prominent activity is VNC brute-force attacks, primarily from the IP address 45.134.26.47. A significant number of SSH-based attacks were also observed, with attackers attempting to install their SSH keys for persistent access. The majority of attacks were logged by the Heralding, Suricata, and Honeytrap honeypots.

**Detailed Analysis:**

***Attacks by Honeypot:***
- Heralding: 7,017
- Suricata: 6,081
- Honeytrap: 5,093
- Cowrie: 2,769
- Sentrypeer: 2,528
- Wordpot: 1,917
- Ciscoasa: 1,502
- Mailoney: 882
- Tanner: 821
- Redishoneypot: 79
- Dionaea: 76
- H0neytr4p: 23
- ElasticPot: 18
- Honeyaml: 10
- Adbhoney: 6
- ConPot: 2
- Ipphoney: 2

***Top Attacking IPs:***
- 45.134.26.47: 6,967
- 107.155.93.174: 2,851
- 10.208.0.3: 2,477
- 10.140.0.3: 1,998
- 86.54.42.238: 822
- 23.94.26.58: 842
- 195.178.110.199: 699
- 172.86.95.115: 450
- 185.243.5.158: 412
- 172.86.95.98: 429
- 188.166.97.19: 369
- 31.193.130.183: 186
- 198.23.190.58: 154
- 141.98.10.182: 175
- 107.170.36.5: 156

***Top Targeted Ports/Protocols:***
- vnc/5900: 7,017
- 80: 2,736
- 5060: 2,528
- 25: 882
- 22: 430
- TCP/5900: 357
- 5903: 218
- 6379: 79
- 8333: 89
- 5901: 127
- UDP/5060: 104
- 5904: 74
- 5905: 73
- 9000: 34
- 23: 56
- 5908: 49
- 5909: 46
- 5907: 48
- 3306: 22

***Most Common CVEs:***
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2020-2551
- CVE-2001-0414
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`

***Signatures Triggered:***
- ET INFO VNC Authentication Failure / 2002920: 9,046
- ET DROP Dshield Block Listed Source group 1 / 2402000: 328
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41 / 2400040: 156
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42 / 2400041: 209
- ET SCAN NMAP -sS window 1024 / 2009582: 162
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) / 2010517: 108
- ET VOIP MultiTech SIP UDP Overflow / 2003237: 58
- ET SCAN Sipsak SIP scan / 2008598: 43
- ET INFO Reserved Internal IP Traffic / 2002752: 55
- ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753: 32

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34: 14
- root/Qaz123qaz: 7
- unknown/1q2w3e4r: 6
- unknown/121212: 6
- ubnt/999: 6
- root/20122012: 4
- operator/operator2025: 4
- root/20132013: 4
- user/user555: 4
- root/20132014: 4
- root/root2023: 4
- root/20142015: 4
- ftpuser/ftppassword: 5

***Files Uploaded/Downloaded:***
- None observed.

***HTTP User-Agents:***
- None observed.

***SSH Clients:***
- None observed.

***SSH Servers:***
- None observed.

***Top Attacker AS Organizations:***
- None observed.

**Key Observations and Anomalies:**
- **High-Volume VNC Attacks:** The dataset is dominated by VNC (port 5900) authentication failures, with "ET INFO VNC Authentication Failure" being the most triggered signature by a large margin. This indicates widespread, automated scanning and brute-force attempts against VNC servers.
- **Persistent SSH Access Attempts:** A recurring command pattern involves modifying the `.ssh` directory and adding a public SSH key to `authorized_keys`. This is a clear indicator of attackers attempting to establish persistent, passwordless access to compromised systems.
- **Concentrated Attack Sources:** A small number of IP addresses are responsible for the majority of attack traffic, particularly 45.134.26.47 and 107.155.93.174. This suggests that these may be dedicated attack servers or compromised machines being used for malicious activities.
