Here is the Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-28T08:01:40Z
**Timeframe:** 2025-10-28T07:20:01Z to 2025-10-28T08:00:01Z
**Files Used:**
- `agg_log_20251028T072001Z.json`
- `agg_log_20251028T074001Z.json`
- `agg_log_20251028T080001Z.json`

**Executive Summary**

This report summarizes 18,976 events collected from the honeypot network. The primary attack vectors observed were reconnaissance and brute-force attempts targeting services like SSH, SMB, and SIP. A significant portion of the traffic originated from a small number of highly active IP addresses. Noteworthy is the repeated attempt to deploy SSH keys for unauthorized access and the execution of reconnaissance commands to profile the system.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 4313
*   Honeytrap: 3512
*   Suricata: 3253
*   Ciscoasa: 2843
*   Dionaea: 2800
*   Sentrypeer: 1990
*   Tanner: 64
*   Mailoney: 97
*   Honeyaml: 36
*   ConPot: 12
*   H0neytr4p: 19
*   Redishoneypot: 12
*   ElasticPot: 10
*   Adbhoney: 6
*   Dicompot: 3

***Top Attacking IPs***

*   117.232.102.66: 2233
*   200.57.3.4: 1339
*   144.172.108.231: 1154
*   66.116.196.243: 639
*   185.243.5.121: 475
*   107.174.26.130: 336
*   212.30.37.8: 328
*   181.115.147.5: 321
*   163.172.99.31: 349
*   69.63.77.146: 311
*   211.253.9.49: 212
*   196.12.203.185: 233
*   217.160.201.135: 271
*   93.113.63.124: 248
*   158.174.210.161: 276

***Top Targeted Ports/Protocols***

*   445: 2555
*   5060: 1990
*   TCP/445: 1335
*   22: 584
*   5038: 328
*   1433: 195
*   5901: 226
*   8333: 138
*   5903: 124
*   80: 52
*   TCP/80: 30
*   25: 97

***Most Common CVEs***

*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2019-11500
*   CVE-2021-3449
*   CVE-2022-27255
*   CVE-2005-4050
*   CVE-2018-10562
*   CVE-2018-10561
*   CVE-2024-4577
*   CVE-2002-0953
*   CVE-2021-41773
*   CVE-2021-42013

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 25
*   `lockr -ia .ssh`: 25
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 25
*   `cat /proc/cpuinfo | grep name | wc -l`: 25
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 25
*   `ls -lh $(which ls)`: 25
*   `which ls`: 25
*   `crontab -l`: 25
*   `w`: 25
*   `uname -m`: 25
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 25
*   `top`: 25
*   `uname`: 25
*   `uname -a`: 25
*   `whoami`: 25
*   `lscpu | grep Model`: 25
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 25
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 24
*   `Enter new UNIX password: `: 17
*   `Enter new UNIX password:`: 17

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1332
*   ET DROP Dshield Block Listed Source group 1: 445
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 288
*   ET SCAN NMAP -sS window 1024: 199
*   ET HUNTING RDP Authentication Bypass Attempt: 125
*   ET INFO Reserved Internal IP Traffic: 58

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 23
*   root/Kayland21: 4
*   root/kaynakas: 4
*   root/kei87!nUu9: 4
*   root/Kensakumj555569: 4
*   test/1: 4
*   root/keong.racun: 4
*   root/keplehZ: 4
*   user/wn#0913c: 3
*   user/wjshi: 3
*   user/wjman: 3
*   user/wizzsnmp: 3
*   user/whyhjd: 3
*   root/3245gs5662d34: 6
*   root/kayu7mba: 3
*   howard/howard: 3
*   howard/3245gs5662d34: 3
*   meera/meera: 3
*   sa/1qaz2wsx: 5
*   root/m00nlight: 3

***Files Uploaded/Downloaded***

*   sh: 98
*   gpon80&ipv=0: 4
*   &currentsetting.htm=1: 2
*   perl|perl: 1
*   arm.uhavenobotsxd;: 1
*   arm.uhavenobotsxd: 1
*   arm5.uhavenobotsxd;: 1
*   arm5.uhavenobotsxd: 1
*   arm6.uhavenobotsxd;: 1
*   arm6.uhavenobotsxd: 1
*   arm7.uhavenobotsxd;: 1
*   arm7.uhavenobotsxd: 1
*   x86_32.uhavenobotsxd;: 1
*   x86_32.uhavenobotsxd: 1
*   mips.uhavenobotsxd;: 1
*   mips.uhavenobotsxd: 1
*   mipsel.uhavenobotsxd;: 1
*   mipsel.uhavenobotsxd: 1

***HTTP User-Agents***

*   *No user agents recorded in this period.*

***SSH Clients and Servers***

*   *No specific SSH clients or servers recorded in this period.*

***Top Attacker AS Organizations***

*   *No AS organization data recorded in this period.*

**Key Observations and Anomalies**

*   **High-Volume Scans:** A large number of events are related to scanning activities, particularly on ports 445 (SMB) and 5060 (SIP). The `DoublePulsar Backdoor` signature indicates exploitation attempts against vulnerable SMB services.
*   **Repetitive Shell Commands:** Attackers consistently run a script of commands to gather system information (`uname`, `lscpu`, `whoami`) and attempt to install a persistent SSH key. The command `cd ~ && rm -rf .ssh && ...` is a clear indicator of this behavior.
*   **Malware Download Attempts:** There are several attempts to download and execute files (`arm.uhavenobotsxd`, `perl|perl`), suggesting attempts to deploy malware for various architectures.
*   **Concentrated Attacks:** The top attacking IPs are responsible for a large percentage of the total attack volume, suggesting targeted campaigns or botnet activity.

This concludes the Honeypot Attack Summary Report. Further analysis will be conducted on the evolving threat landscape in subsequent reports.
