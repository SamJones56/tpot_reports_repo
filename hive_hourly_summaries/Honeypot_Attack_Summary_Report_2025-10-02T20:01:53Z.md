Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T20:01:36Z
**Timeframe:** 2025-10-02T19:20:01Z to 2025-10-02T20:00:01Z
**Files Used:**
- agg_log_20251002T192001Z.json
- agg_log_20251002T194001Z.json
- agg_log_20251002T200001Z.json

**Executive Summary**
This report summarizes 12,832 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Ciscoasa, Sentrypeer, and Suricata honeypots. A significant number of attacks originated from IP address 176.65.141.117. The most targeted ports were 5060 (SIP) and 25 (SMTP). Several CVEs were detected, with CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 3534
- Ciscoasa: 2629
- Sentrypeer: 2224
- Suricata: 2203
- Mailoney: 1741
- Honeytrap: 190
- Dionaea: 95
- Adbhoney: 71
- Tanner: 35
- Honeyaml: 35
- H0neytr4p: 29
- Redishoneypot: 26
- ConPot: 12
- Dicompot: 4
- Miniprint: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 176.65.141.117: 1640
- 198.23.190.58: 1553
- 23.175.48.211: 1256
- 185.156.73.166: 354
- 92.63.197.55: 350
- 92.63.197.59: 320
- 216.10.242.161: 303
- 104.244.74.84: 213
- 211.253.9.49: 223
- 134.199.228.210: 229
- 14.103.127.230: 228
- 182.43.147.13: 236
- 27.155.77.43: 239

**Top Targeted Ports/Protocols:**
- 5060: 2224
- 25: 1741
- UDP/5060: 712
- 22: 537
- TCP/445: 281
- 445: 26
- 23: 46
- 80: 51
- TCP/80: 64
- 443: 29
- 6379: 23
- TCP/1080: 27

**Most Common CVEs:**
- CVE-2022-27255: 69
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2019-11500: 6
- CVE-2021-35394: 2
- CVE-2021-3449: 2
- CVE-2023-26801: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...

**Signatures Triggered:**
- ET SCAN Sipsak SIP scan: 635
- ET DROP Dshield Block Listed Source group 1: 289
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 274
- ET SCAN NMAP -sS window 1024: 172
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 69
- ET INFO Reserved Internal IP Traffic: 60

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 13
- root/nPSpP4PBW0: 9
- root/2glehe5t24th1issZs: 6
- foundry/foundry: 5
- test/zhbjETuyMffoL8F: 4
- seekcy/Joysuch@Locate2020: 3
- root/marcel: 2
- ubuntu/test12345: 2
- moderator/moderator: 2
- agent/agent: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 24
- w.sh;: 6
- c.sh;: 6
- arm.urbotnetisass;: 4
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- boatnet.mpsl;: 2

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers recorded in this period.

**Top Attacker AS Organizations:**
- No AS organization data available in this period.

**Key Observations and Anomalies**
- The high volume of SIP (5060) and SMTP (25) traffic suggests targeted scans for communication servers.
- The repeated attempts to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`) indicate automated attempts to deploy malware or establish persistence.
- A significant number of commands are focused on modifying SSH authorized_keys, indicating attempts to maintain access to compromised systems.
- The prevalence of the Realtek SDK vulnerability (CVE-2022-27255) suggests that attackers are actively targeting IoT devices.
- The DoublePulsar signature indicates attempts to exploit systems previously compromised by the EternalBlue exploit.
