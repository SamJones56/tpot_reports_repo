Here is the consolidated Honeypot Attack Summary Report.

**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-03T13:01:31Z
*   **Timeframe:** 2025-10-03T12:20:01Z to 2025-10-03T13:00:01Z
*   **Files Used:**
    *   `agg_log_20251003T122001Z.json`
    *   `agg_log_20251003T124001Z.json`
    *   `agg_log_20251003T130001Z.json`

**Executive Summary**

This report summarizes 15,450 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Suricata honeypots. The most frequent attacks originated from IP address 187.23.140.222, and the most targeted port was TCP/445. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. A variety of commands were attempted by attackers, many of which are associated with reconnaissance and establishing persistence.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 4300
    *   Dionaea: 3336
    *   Suricata: 3831
    *   Ciscoasa: 2476
    *   Mailoney: 846
    *   Sentrypeer: 322
    *   Honeytrap: 183
    *   Tanner: 47
    *   H0neytr4p: 37
    *   Miniprint: 17
    *   Redishoneypot: 14
    *   ConPot: 11
    *   Dicompot: 7
    *   ElasticPot: 8
    *   Adbhoney: 4
    *   Honeyaml: 5
    *   Heralding: 3
    *   ssh-ed25519: 2
    *   Ipphoney: 1

*   **Top Attacking IPs:**
    *   187.23.140.222: 1523
    *   200.85.127.158: 1382
    *   106.75.131.128: 1246
    *   83.40.9.221: 2503
    *   176.65.141.117: 820
    *   85.62.71.63: 472
    *   185.156.73.166: 369
    *   92.63.197.59: 315
    *   160.191.89.60: 222
    *   103.179.57.150: 207
    *   210.79.190.22: 236
    *   202.10.40.252: 201
    *   46.105.87.113: 162
    *   152.32.145.111: 163
    *   14.103.177.217: 201
    *   36.50.176.144: 164
    *   194.107.115.65: 169
    *   103.217.145.144: 154
    *   51.68.226.87: 103
    *   61.36.200.131: 103

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 2900
    *   445: 3083
    *   22: 694
    *   25: 842
    *   5060: 322
    *   3306: 203
    *   TCP/22: 38
    *   80: 47
    *   TCP/80: 32
    *   443: 37
    *   23: 39
    *   TCP/1433: 22
    *   TCP/1080: 18
    *   TCP/5432: 17
    *   UDP/5060: 11
    *   6379: 9
    *   9100: 14

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2005-4050
    *   CVE-2018-10562 CVE-2018-10561
    *   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh: 16
    *   lockr -ia .ssh: 16
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "...": 16
    *   cat /proc/cpuinfo | grep name | wc -l: 16
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
    *   ls -lh $(which ls): 16
    *   which ls: 16
    *   crontab -l: 16
    *   uname -a: 17
    *   whoami: 16
    *   lscpu | grep Model: 16
    *   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
    *   w: 15
    *   uname -m: 15
    *   cat /proc/cpuinfo | grep model | grep name | wc -l: 15
    *   top: 15
    *   uname: 15
    *   Enter new UNIX password: : 5
    *   Enter new UNIX password:: 5

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2898
    *   2024766: 2898
    *   ET DROP Dshield Block Listed Source group 1: 193
    *   2402000: 193
    *   ET SCAN NMAP -sS window 1024: 180
    *   2009582: 180
    *   ET INFO Reserved Internal IP Traffic: 57
    *   2002752: 57
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 29
    *   2400031: 29
    *   ET SCAN Potential SSH Scan: 18
    *   2001219: 18
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 67: 20
    *   2403366: 20
    *   ET SCAN Suspicious inbound to MSSQL port 1433: 13
    *   2010935: 13
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 12
    *   2400040: 12

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 15
    *   php/: 200
    *   superadmin/admin123: 6
    *   root/LeitboGi0ro: 5
    *   root/nPSpP4PBW0: 6
    *   root/3245gs5662d34: 5
    *   foundry/foundry: 3
    *   tina/tina: 3
    *   guru/guru: 2
    *   root/Abc#123456: 2
    *   root/abcd.1234: 2
    *   azure/1: 2
    *   admin/qwerty255: 2
    *   admin/1234ppp: 2
    *   admin/A123456789!: 2
    *   admin/cloud@2022: 2
    *   admin/1234asdf1234: 2

*   **Files Uploaded/Downloaded:**
    *   11: 5
    *   fonts.gstatic.com: 5
    *   css?family=Libre+Franklin...: 5
    *   ie8.css?ver=1.0: 5
    *   html5.js?ver=3.7.3: 5
    *   gpon80&ipv=0: 4
    *   k.php?a=x86_64,5LRF93W349Q42189H: 1

*   **HTTP User-Agents:** (No data)
*   **SSH Clients:** (No data)
*   **SSH Servers:** (No data)
*   **Top Attacker AS Organizations:** (No data)

**Key Observations and Anomalies**

*   The high number of attacks targeting port 445, particularly those triggering the "DoublePulsar Backdoor" signature, suggests a continued threat from SMB-related vulnerabilities.
*   The commands executed by attackers indicate a pattern of reconnaissance (e.g., `uname -a`, `lscpu`) followed by attempts to establish persistence by adding an SSH key to `authorized_keys`.
*   The variety of login attempts across different services (e.g., SSH, web applications) highlights the broad scope of automated attacks.
*   The presence of commands related to downloading and executing payloads (e.g., `wget`, `chmod 777`) from a remote server indicates active malware campaigns.

This concludes the Honeypot Attack Summary Report. Further analysis will be conducted in subsequent reports.
