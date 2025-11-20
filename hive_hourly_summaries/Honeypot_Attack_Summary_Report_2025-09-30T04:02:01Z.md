Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T04:01:24Z
**Timeframe:** 2025-09-30T03:20:01Z to 2025-09-30T04:00:01Z
**Files Used:**
*   agg_log_20250930T032001Z.json
*   agg_log_20250930T034001Z.json
*   agg_log_20250930T040001Z.json

### Executive Summary

This report summarizes 18,912 events collected from our honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was `160.25.118.10`, responsible for a significant portion of the malicious traffic. A large number of attacks targeted port 445, indicating widespread SMB scanning, likely related to exploits such as EternalBlue. Several CVEs were observed, with the most frequent being `CVE-2002-0013` and `CVE-2002-0012`. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 12034
*   Suricata: 2787
*   Honeytrap: 2389
*   Ciscoasa: 1451
*   Dionaea: 108
*   Redishoneypot: 31
*   Adbhoney: 23
*   Tanner: 29
*   H0neytr4p: 15
*   ElasticPot: 10
*   Mailoney: 10
*   Sentrypeer: 12
*   ConPot: 7
*   Honeyaml: 6

**Top Attacking IPs:**
*   160.25.118.10: 7694
*   118.99.86.117: 1353
*   4.144.169.44: 1245
*   85.208.253.156: 177
*   20.169.164.223: 173
*   156.238.16.164: 211
*   179.27.96.190: 167
*   132.248.247.237: 322
*   45.115.217.248: 277
*   185.156.73.166: 378

**Top Targeted Ports/Protocols:**
*   TCP/445: 1354
*   22: 2145
*   445: 51
*   5901: 83
*   8333: 96
*   6379: 23
*   TCP/22: 59
*   23: 53
*   80: 17
*   9090: 28

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 7
*   CVE-2019-11500 CVE-2019-11500: 5
*   CVE-2021-3449 CVE-2021-3449: 4
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
*   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 21
*   `lockr -ia .ssh`: 21
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 21
*   `cat /proc/cpuinfo | grep name | wc -l`: 21
*   `uname -a`: 22
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 20
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 20
*   `ls -lh $(which ls)`: 20
*   `which ls`: 20
*   `crontab -l`: 20

**Signatures Triggered:**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1351
*   2024766: 1351
*   ET DROP Dshield Block Listed Source group 1: 463
*   2402000: 463
*   ET SCAN NMAP -sS window 1024: 192
*   2009582: 192
*   ET INFO Reserved Internal IP Traffic: 59
*   2002752: 59
*   ET SCAN Potential SSH Scan: 43
*   2001219: 43

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 20
*   root/3245gs5662d34: 8
*   test/zhbjETuyMffoL8F: 6
*   root/nPSpP4PBW0: 6
*   ubuntu/ubuntu: 3
*   www/test123: 3
*   foundry/foundry: 3
*   superv/superv123: 3
*   superadmin/admin123: 3
*   root/eve: 3

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass: 4
*   wget.sh;: 4
*   w.sh;: 1
*   c.sh;: 1

**HTTP User-Agents:**
*   None observed in this period.

**SSH Clients and Servers:**
*   None observed in this period.

**Top Attacker AS Organizations:**
*   None observed in this period.

### Key Observations and Anomalies

*   The high volume of traffic from `160.25.118.10` suggests a targeted or highly aggressive scanning campaign.
*   The significant number of hits on TCP port 445, coupled with the "DoublePulsar Backdoor" signature, strongly indicates attempts to exploit the EternalBlue vulnerability (MS17-010).
*   The commands executed by attackers are consistent with initial access and reconnaissance, including attempts to add SSH keys for persistence.
*   The presence of `urbotnetisass` files being downloaded suggests a botnet campaign targeting various architectures (ARM, x86, MIPS).
*   No HTTP user agents, SSH clients, or server versions were logged, which may indicate that these specific honeypots were not triggered or that the attacks were at a lower protocol level.

This report highlights ongoing automated attacks targeting common vulnerabilities. Further analysis of the attacker IPs and payloads is recommended to understand the full scope of the threat.
