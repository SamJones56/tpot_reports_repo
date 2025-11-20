**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-20T11:01:31Z
*   **Timeframe:** 2025-10-20T10:20:01Z to 2025-10-20T11:00:01Z
*   **Files Used:**
    *   `agg_log_20251020T102001Z.json`
    *   `agg_log_20251020T104001Z.json`
    *   `agg_log_20251020T110001Z.json`

**Executive Summary**

This report summarizes 14,703 attacks recorded by the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. Attackers primarily targeted SSH (port 22) and SIP (port 5060) services. A significant number of brute-force login attempts were observed, along with the execution of post-exploitation commands, including attempts to download and execute malware. Several CVEs were also detected, with a focus on older vulnerabilities.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 7135
    *   Honeytrap: 4382
    *   Suricata: 1686
    *   Sentrypeer: 1117
    *   Adbhoney: 102
    *   Dionaea: 79
    *   H0neytr4p: 48
    *   Mailoney: 38
    *   Redishoneypot: 35
    *   Ciscoasa: 33
    *   Tanner: 22
    *   Honeyaml: 14
    *   ElasticPot: 10
    *   ConPot: 2

*   **Top Attacking IPs:**
    *   134.122.45.20: 1244
    *   5.253.59.122: 970
    *   72.146.232.13: 1251
    *   45.128.199.34: 477
    *   190.167.237.191: 283
    *   43.133.185.172: 267
    *   107.170.36.5: 252
    *   185.243.5.103: 207
    *   103.23.198.201: 273
    *   159.223.37.230: 228
    *   185.243.5.158: 220
    *   171.244.61.82: 194
    *   159.65.154.92: 273
    *   180.76.134.56: 156
    *   77.83.207.203: 141
    *   167.250.224.25: 148
    *   223.83.135.35: 164
    *   121.229.5.171: 152
    *   94.182.174.211: 125
    *   103.176.78.193: 114

*   **Top Targeted Ports/Protocols:**
    *   22: 1385
    *   5060: 1117
    *   1993: 193
    *   5903: 227
    *   8333: 138
    *   5901: 115
    *   4433: 86
    *   UDP/5060: 40
    *   TCP/22: 64
    *   5905: 78
    *   5904: 77
    *   5555: 49
    *   8888: 54
    *   6379: 29
    *   23: 41
    *   15672: 34
    *   15671: 34
    *   9303: 35
    *   5907: 54
    *   5909: 49

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012: 6
    *   CVE-2021-3449 CVE-2021-3449: 3
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
    *   CVE-2019-11500 CVE-2019-11500: 2
    *   CVE-2024-3721 CVE-2024-3721: 1
    *   CVE-2021-35394 CVE-2021-35394: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 19
    *   `lockr -ia .ssh`: 19
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 19
    *   `cat /proc/cpuinfo | grep name | wc -l`: 19
    *   `Enter new UNIX password: `: 16
    *   `Enter new UNIX password:`: 16
    *   `uname -a`: 19
    *   `whoami`: 19
    *   `w`: 19
    *   `crontab -l`: 19
    *   `top`: 19

*   **Signatures Triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 344
    *   ET DROP Dshield Block Listed Source group 1: 381
    *   ET HUNTING RDP Authentication Bypass Attempt: 139
    *   ET SCAN NMAP -sS window 1024: 173
    *   ET INFO Reserved Internal IP Traffic: 60
    *   ET SCAN Sipsak SIP scan: 35
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 25
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 17
    *   ET INFO CURL User Agent: 10

*   **Users / Login Attempts:**
    *   `345gs5662d34/345gs5662d34`: 16
    *   `user01/Password01`: 13
    *   `sa/1234`: 10
    *   `root/Abel2014`: 4
    *   `root/abpbx2k12`: 4
    *   `root/!Q2w3e4r`: 4
    *   `root/Ac0m1P`: 4
    *   `root/AccesoPBX2264`: 4
    *   `root/Acd1502`: 4
    *   `root/acero20`: 4

*   **Files Uploaded/Downloaded:**
    *   `arm.urbotnetisass;`: 2
    *   `arm.urbotnetisass`: 2
    *   `arm5.urbotnetisass;`: 2
    *   `arm5.urbotnetisass`: 2
    *   `arm6.urbotnetisass;`: 2
    *   `arm6.urbotnetisass`: 2
    *   `arm7.urbotnetisass;`: 2
    *   `arm7.urbotnetisass`: 2
    *   `x86_32.urbotnetisass;`: 2
    *   `x86_32.urbotnetisass`: 2
    *   `mips.urbotnetisass;`: 2
    *   `mips.urbotnetisass`: 2
    *   `mipsel.urbotnetisass;`: 2
    *   `mipsel.urbotnetisass`: 2
    *   `rondo.kqa.sh|sh&echo`: 2

*   **HTTP User-Agents:**
    *   None Observed

*   **SSH Clients:**
    *   None Observed

*   **SSH Servers:**
    *   None Observed

*   **Top Attacker AS Organizations:**
    *   None Observed

**Key Observations and Anomalies**

*   A significant amount of post-exploitation activity was observed, including attempts to modify SSH authorized_keys, gather system information, and download and execute malware.
*   The `urbotnetisass` malware was seen in multiple download attempts, targeting various architectures (ARM, x86, MIPS).
*   The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` was frequently used, indicating a clear attempt to establish persistent access.
*   The most frequently triggered Suricata signature was for MS Terminal Server traffic on non-standard ports, which could indicate attempts to exploit RDP vulnerabilities.

This concludes the Honeypot Attack Summary Report.
