Here is the Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-02T23:01:24Z
*   **Timeframe Covered:** 2025-10-02T22:20:01Z to 2025-10-02T23:00:01Z
*   **Log Files:** `agg_log_20251002T222001Z.json`, `agg_log_20251002T224001Z.json`, `agg_log_20251002T230001Z.json`

**Executive Summary**

This report summarizes 12,681 security events captured by the T-Pot honeypot network over the last hour. The majority of attacks targeted the Cowrie, Ciscoasa, and Mailoney honeypots. The most prominent attack vectors were SSH brute-force attempts, scans for open ports, and exploitation of known vulnerabilities. The top attacking IP addresses originate from a diverse range of countries, with a significant portion of the attacks coming from Russia and China.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 3698
*   Ciscoasa: 2620
*   Mailoney: 2516
*   Sentrypeer: 1835
*   Suricata: 1579
*   Honeytrap: 138
*   Dionaea: 94
*   ConPot: 53
*   H0neytr4p: 33
*   Tanner: 30
*   Adbhoney: 21
*   Dicompot: 22
*   Ipphoney: 20
*   Redishoneypot: 9
*   Honeyaml: 7
*   ssh-rsa: 4
*   ElasticPot: 2

***Top Attacking IPs***

*   176.65.141.117: 1640
*   23.175.48.211: 1249
*   86.54.42.238: 821
*   198.12.68.114: 537
*   212.87.220.20: 336
*   103.249.201.48: 391
*   92.63.197.55: 350
*   185.156.73.166: 362
*   92.63.197.59: 320
*   64.227.174.243: 298
*   103.4.145.50: 276
*   61.72.55.130: 262
*   103.189.235.66: 262
*   61.220.127.240: 318
*   27.79.7.177: 182
*   101.89.182.189: 151
*   27.79.43.89: 161
*   34.140.24.231: 168
*   187.45.100.0: 98
*   113.108.95.34: 147

***Top Targeted Ports/Protocols***

*   25: 2516
*   5060: 1835
*   22: 540
*   UDP/5060: 278
*   TCP/1433: 59
*   1433: 53
*   TCP/22: 74
*   TCP/443: 93
*   443: 35
*   80: 37
*   23: 27
*   631: 19
*   27017: 12
*   1025: 34
*   6379: 6
*   5555: 5
*   TCP/1521: 5
*   UDP/161: 12
*   TCP/3389: 8
*   8291: 7

***Most Common CVEs***

*   CVE-2022-27255: 52
*   CVE-2019-11500: 7
*   CVE-2021-3449: 7
*   CVE-2003-0825: 4
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
*   CVE-2002-0013 CVE-2002-0012: 5
*   CVE-2021-35394: 3

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 19
*   `lockr -ia .ssh`: 19
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 19
*   `cat /proc/cpuinfo | grep name | wc -l`: 17
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 17
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 17
*   `ls -lh $(which ls)`: 17
*   `which ls`: 17
*   `crontab -l`: 17
*   `w`: 17
*   `uname -m`: 17
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 17
*   `top`: 17
*   `uname`: 16
*   `uname -a`: 18
*   `whoami`: 16
*   `lscpu | grep Model`: 16
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 16
*   `Enter new UNIX password: `: 9
*   `Enter new UNIX password:`: 9

***Signatures Triggered***

*   ET SCAN Sipsak SIP scan: 212
*   ET DROP Dshield Block Listed Source group 1: 261
*   ET SCAN NMAP -sS window 1024: 172
*   ET SCAN Possible SSL Brute Force attack or Site Crawl: 82
*   ET SCAN Suspicious inbound to MSSQL port 1433: 56
*   ET INFO Reserved Internal IP Traffic: 57
*   ET SCAN Potential SSH Scan: 53
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 52
*   ET CINS Active Threat Intelligence Poor Reputation IP group 67: 12
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 12

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 18
*   root/LeitboGi0ro: 5
*   root/nPSpP4PBW0: 9
*   root/3245gs5662d34: 9
*   test/zhbjETuyMffoL8F: 5
*   sa/1qaz2wsx: 2
*   root/5nWt3P-fF4WosQm5O: 2
*   root/USA: 2
*   admin/avangard: 2
*   admin/arslan: 2
*   admin/aria: 2
*   admin/angelofwar: 2
*   admin/anduril: 2
*   minecraft/3245gs5662d34: 2
*   system/123: 2
*   old/sor123in: 2
*   d/1234: 2
*   root/: 2
*   liang/liang123: 2
*   agent/agent: 4

***Files Uploaded/Downloaded***

*   boatnet.mpsl;: 3
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
*   11: 7
*   fonts.gstatic.com: 7
*   css?family=Libre+Franklin...: 6
*   ie8.css?ver=1.0: 6
*   html5.js?ver=3.7.3: 6

***HTTP User-Agents***
*No user agents recorded in this timeframe.*

***SSH Clients***
*No SSH clients recorded in this timeframe.*

***SSH Servers***
*No SSH servers recorded in this timeframe.*

***Top Attacker AS Organizations***
*No AS organizations recorded in this timeframe.*

**Key Observations and Anomalies**

*   A significant number of attacks are attempting to exploit CVE-2022-27255, a vulnerability in Realtek eCos RSDK/MSDK.
*   The attacker at 176.65.141.117 is particularly aggressive, responsible for over 10% of all recorded events.
*   Attackers are consistently using the same set of commands to enumerate systems and attempt to disable security measures. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` is a common tactic to install a malicious SSH key for persistence.
*   The files being downloaded, such as "boatnet.mpsl;" and "arm.urbotnetisass", are likely malware payloads for various architectures.

This concludes the Honeypot Attack Summary Report. Further analysis of the captured payloads and attacker TTPs is recommended to enhance our defensive posture.
