Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T13:01:25Z
**Timeframe:** 2025-10-13T12:20:01Z to 2025-10-13T13:00:01Z
**Files:** agg_log_20251013T122001Z.json, agg_log_20251013T124002Z.json, agg_log_20251013T130001Z.json

### Executive Summary

This report summarizes 13,584 attacks recorded by honeypots over the last hour. The most active honeypot was Cowrie, with 4,656 events. The top attacking IP address was 45.171.150.123, and the most targeted port was 445/TCP (SMB). Several CVEs were detected, with CVE-2006-0189 and CVE-2022-27255 being the most frequent. A significant number of shell commands were executed, indicating attempts to establish control over compromised systems.

### Detailed Analysis

**Attacks by Honeypot**

*   Cowrie: 4656
*   Dionaea: 2589
*   Honeytrap: 1799
*   Sentrypeer: 1276
*   Mailoney: 857
*   Ciscoasa: 675
*   Suricata: 932
*   Redishoneypot: 104
*   Miniprint: 53
*   ConPot: 46
*   Tanner: 46
*   H0neytr4p: 28
*   ElasticPot: 5
*   Honeyaml: 6
*   Ipphoney: 6
*   Adbhoney: 3
*   Heralding: 3

**Top Attacking IPs**

*   45.171.150.123: 869
*   86.54.42.238: 820
*   118.71.137.154: 811
*   36.229.206.51: 779
*   45.234.176.18: 720
*   188.212.135.108: 693
*   67.213.112.65: 240
*   172.86.95.115: 336
*   62.141.43.183: 324
*   172.86.95.98: 314
*   101.201.28.113: 288
*   159.223.184.214: 197
*   154.91.170.15: 173
*   178.17.53.209: 173
*   102.223.92.101: 167
*   36.255.197.108: 194
*   103.189.235.66: 157
*   103.31.39.188: 144
*   103.187.147.252: 118
*   216.10.242.161: 154
*   43.153.67.208: 140
*   47.250.81.225: 112

**Top Targeted Ports/Protocols**

*   445: 2490
*   5060: 1276
*   25: 859
*   22: 651
*   5038: 693
*   23: 130
*   6379: 104
*   UDP/5060: 63
*   9100: 53
*   80: 48
*   443: 33
*   TCP/5432: 22
*   TCP/22: 20
*   TCP/1433: 18
*   27017: 15
*   TCP/80: 11
*   TCP/8080: 19

**Most Common CVEs**

*   CVE-2006-0189: 23
*   CVE-2022-27255 CVE-2022-27255: 23
*   CVE-2005-4050: 12
*   CVE-2002-0013 CVE-2002-0012: 9
*   CVE-2019-11500 CVE-2019-11500: 3
*   CVE-2021-3449 CVE-2021-3449: 3
*   CVE-2021-35394 CVE-2021-35394: 1
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
*   CVE-1999-0517: 1

**Commands Attempted by Attackers**

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 23
*   lockr -ia .ssh: 23
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 23
*   cat /proc/cpuinfo | grep name | wc -l: 23
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 23
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 23
*   which ls: 23
*   ls -lh $(which ls): 23
*   crontab -l: 23
*   w: 23
*   uname -m: 23
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 23
*   top: 23
*   uname: 23
*   uname -a: 23
*   whoami: 23
*   lscpu | grep Model: 23
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 23
*   Enter new UNIX password: : 16
*   Enter new UNIX password:": 14

**Signatures Triggered**

*   ET DROP Dshield Block Listed Source group 1: 230
*   2402000: 230
*   ET SCAN NMAP -sS window 1024: 146
*   2009582: 146
*   ET INFO Reserved Internal IP Traffic: 60
*   2002752: 60
*   ET VOIP SIP UDP Softphone INVITE overflow: 23
*   2002848: 23
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 23
*   2038669: 23

**Users / Login Attempts**

*   345gs5662d34/345gs5662d34: 21
*   support/support2018: 9
*   debian/debian2017: 6
*   config/P@ssw0rd: 6
*   debian/qwerty1234: 5
*   root/123456@qq.com: 5
*   root/Q1w2e3r4t5y6u7i8o9p0: 5
*   root/3245gs5662d34: 5
*   blank/blank2024: 4
*   admin/0000000: 4
*   root/Kh4e59v0: 4
*   info/test: 4
*   ftpuser/ftppassword: 4
*   config/config2019: 4
*   unknown/administrator: 4
*   root/mPower@786: 4
*   config/config2023: 4
*   admin/admin2024: 4

**Files Uploaded/Downloaded**

*   11: 1
*   fonts.gstatic.com: 1
*   mpsl;: 1
*   arm.urbotnetisass;: 1
*   arm.urbotnetisass: 1
*   arm5.urbotnetisass;: 1
*   arm5.urbotnetisass: 1
*   arm6.urbotnetisass;: 1
*   arm6.urbotnetisass: 1
*   arm7.urbotnetisass;: 1
*   arm7.urbotnetisass: 1
*   x86_32.urbotnetisass;: 1
*   x86_32.urbotnetisass: 1
*   mips.urbotnetisass;: 1
*   mips.urbotnetisass: 1
*   mipsel.urbotnetisass;: 1
*   mipsel.urbotnetisass: 1

**HTTP User-Agents**

*   No user agents were logged in this timeframe.

**SSH Clients**

*   No SSH clients were logged in this timeframe.

**SSH Servers**

*   No SSH servers were logged in this timeframe.

**Top Attacker AS Organizations**

*   No AS organizations were logged in this timeframe.

### Key Observations and Anomalies

*   The Cowrie honeypot is attracting the most attention, primarily through SSH and Telnet.
*   The high number of scans on port 445 (SMB) suggests widespread attempts to exploit SMB vulnerabilities.
*   The commands executed by attackers are typical of initial system reconnaissance and attempts to establish persistent access by modifying SSH authorized_keys.
*   The downloaded files (`*.urbotnetisass`) from IP `94.154.35.154` are likely related to the Urbot botnet, targeting various CPU architectures (ARM, x86, MIPS).
*   A wide variety of credentials are being used, indicating brute-force attacks from a large dictionary.

This concludes the Honeypot Attack Summary Report.