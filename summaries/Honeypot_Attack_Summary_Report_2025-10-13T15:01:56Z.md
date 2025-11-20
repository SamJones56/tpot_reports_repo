Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T15:01:34Z
**Timeframe:** 2025-10-13T14:20:01Z to 2025-10-13T15:00:01Z
**Files:** agg_log_20251013T1420:01Z.json, agg_log_20251013T144001Z.json, agg_log_20251013T150001Z.json

### Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 12,800 attacks were recorded across various honeypots. The most targeted services were Cowrie (SSH), Mailoney (SMTP), and Dionaea (SMB). The majority of attacks originated from a wide range of IP addresses, with significant activity from `86.54.42.238` and `159.89.20.223`. Attackers attempted to exploit several vulnerabilities, with a focus on older CVEs. A variety of commands were executed, primarily aimed at reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot**
* Cowrie: 6616
* Mailoney: 1667
* Dionaea: 1682
* Suricata: 1067
* Sentrypeer: 1065
* Honeytrap: 517
* ConPot: 51
* Tanner: 50
* H0neytr4p: 24
* Redishoneypot: 17
* Honeyaml: 21
* Dicompot: 9
* ElasticPot: 4
* Adbhoney: 4
* Ipphoney: 6

**Top Attacking IPs**
* 86.54.42.238: 1640
* 159.89.20.223: 1247
* 94.103.12.49: 950
* 36.229.206.51: 781
* 213.149.166.133: 849
* 165.22.53.243: 354
* 62.141.43.183: 324
* 172.86.95.98: 340
* 172.86.95.115: 338
* 103.187.165.26: 257

**Top Targeted Ports/Protocols**
* 25: 1659
* 445: 1638
* 5060: 1065
* 22: 927
* 23: 110
* 1025: 51
* UDP/5060: 58
* TCP/22: 43
* 80: 54
* 443: 24

**Most Common CVEs**
* CVE-2002-0013 CVE-2002-0012: 27
* CVE-2006-0189: 22
* CVE-2022-27255 CVE-2022-27255: 22
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 17
* CVE-2005-4050: 5
* CVE-2021-3449 CVE-2021-3449: 3
* CVE-2023-26801 CVE-2023-26801: 2
* CVE-2019-11500 CVE-2019-11500: 2

**Commands Attempted by Attackers**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
* `cat /proc/cpuinfo | grep name | wc -l`
* `whoami`
* `lscpu | grep Model`
* `uname -s -v -n -r -m`
* `cd /data/local/tmp/; rm *; busybox wget ...`

**Signatures Triggered**
* ET DROP Dshield Block Listed Source group 1: 285
* ET SCAN NMAP -sS window 1024: 125
* ET INFO Reserved Internal IP Traffic: 60
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 50
* ET SCAN Potential SSH Scan: 25
* ET VOIP SIP UDP Softphone INVITE overflow: 22
* ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 22

**Users / Login Attempts**
* root/123@@@
* 345gs5662d34/345gs5662d34
* root/Qaz123qaz
* debian/777777
* unknown/11
* root/NeFqxfP4Xb9t

**Files Uploaded/Downloaded**
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin...
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass

**HTTP User-Agents**
* None observed

**SSH Clients and Servers**
* No specific clients or servers were identified in the logs.

**Top Attacker AS Organizations**
* No specific AS organizations were identified in the logs.

### Key Observations and Anomalies

*   **High Volume of Mailoney Traffic:** A significant portion of the traffic was directed at the Mailoney (SMTP) honeypot, indicating a possible large-scale spam or reconnaissance campaign.
*   **Repetitive SSH Commands:** The commands executed via the Cowrie honeypot are consistent with automated scripts attempting to gather system information and install SSH keys for persistence.
*   **Android Malware:** The `adb` honeypot captured attempts to download and execute `urbotnetisass` malware variants, specifically targeting Android devices. This is a notable shift from the typical server-focused attacks.
*   **Older CVEs Targeted:** Attackers continue to target older, well-known vulnerabilities, suggesting that many systems remain unpatched.
*   **Lack of User-Agent and AS Org Data:** The absence of HTTP User-Agents and AS Organization data might be due to the nature of the attacks, which were predominantly on non-HTTP services.

This summary provides a snapshot of the threat landscape as observed by the honeypots. Continuous monitoring is recommended to identify emerging trends and threats.