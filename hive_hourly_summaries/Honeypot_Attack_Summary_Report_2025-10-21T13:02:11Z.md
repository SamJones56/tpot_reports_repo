Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T13:01:34Z
**Timeframe:** 2025-10-21T12:20:01Z to 2025-10-21T13:00:01Z

**Files Used for Report Generation:**
- `agg_log_20251021T122001Z.json`
- `agg_log_20251021T124001Z.json`
- `agg_log_20251021T130001Z.json`

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes. A total of 15,237 attacks were recorded across various honeypots. The most targeted services were SSH (port 22) and SMB (port 445). A significant number of attacks originated from a small number of IP addresses, with `83.239.178.110`, `64.188.90.37`, and `202.4.117.136` being the most active. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. Several CVEs were targeted, with `CVE-2019-11500` and `CVE-2021-3449` being the most common.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 6498
    *   Suricata: 4082
    *   Honeytrap: 3629
    *   Sentrypeer: 446
    *   Dionaea: 353
    *   Adbhoney: 38
    *   Redishoneypot: 36
    *   Ciscoasa: 42
    *   H0neytr4p: 34
    *   Tanner: 29
    *   Mailoney: 22
    *   Dicompot: 16
    *   ConPot: 4
    *   Honeyaml: 5
    *   ssh-rsa: 2
    *   ElasticPot: 1

*   **Top Attacking IPs:**
    *   83.239.178.110: 1374
    *   202.4.117.136: 1353
    *   64.188.90.37: 1250
    *   185.231.59.125: 1034
    *   72.146.232.13: 1211
    *   38.96.255.250: 1233
    *   40.83.182.122: 293
    *   185.243.5.158: 281
    *   107.170.36.5: 249
    *   104.168.56.59: 214
    *   143.244.134.97: 189
    *   196.203.109.209: 194
    *   199.195.248.191: 99
    *   103.139.192.17: 134
    *   61.76.112.4: 129
    *   167.250.224.25: 120
    *   68.183.149.135: 100
    *   77.83.207.203: 104
    *   198.23.238.154: 96
    *   68.183.207.213: 93

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 2720
    *   22: 1361
    *   5060: 446
    *   5903: 225
    *   445: 231
    *   5901: 113
    *   TCP/22: 57
    *   8333: 94
    *   5905: 75
    *   5904: 75
    *   UDP/5060: 55
    *   6379: 36
    *   TCP/80: 68
    *   80: 21
    *   443: 29

*   **Most Common CVEs:**
    *   CVE-2019-11500: 8
    *   CVE-2021-3449: 7
    *   CVE-2002-0013 CVE-2002-0012: 2
    *   CVE-2005-4050: 1

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh: 10
    *   lockr -ia .ssh: 10
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 10
    *   cat /proc/cpuinfo | grep name | wc -l: 9
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 9
    *   free -m | grep Mem | awk ...: 8
    *   ls -lh $(which ls): 9
    *   which ls: 9
    *   crontab -l: 9
    *   w: 9
    *   uname -m: 9
    *   cat /proc/cpuinfo | grep model | grep name | wc -l: 9
    *   top: 8
    *   uname: 8
    *   uname -a: 8
    *   whoami: 8
    *   lscpu | grep Model: 8
    *   df -h | head -n 2 | awk ...: 9
    *   uname -s -v -n -r -m: 10

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2714
    *   2024766: 2714
    *   ET DROP Dshield Block Listed Source group 1: 252
    *   2402000: 252
    *   ET SCAN NMAP -sS window 1024: 179
    *   2009582: 179
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 180
    *   2023753: 180
    *   ET HUNTING RDP Authentication Bypass Attempt: 63
    *   2034857: 63
    *   ET INFO Reserved Internal IP Traffic: 58
    *   2002752: 58
    *   ET SCAN Potential SSH Scan: 54
    *   2001219: 54

*   **Users / Login Attempts:**
    *   root/anmol123: 4
    *   root/ant00: 4
    *   root/Anwhelm9: 4
    *   root/aol123: 4
    *   root/Aotei3sh: 4
    *   root/AP201305: 4
    *   345gs5662d34/345gs5662d34: 7
    *   root/!Q2w3e4r: 5
    *   pi/raspberry: 4
    *   testuser/testuser: 3

*   **Files Uploaded/Downloaded:**
    *   wget.sh;: 16
    *   w.sh;: 4
    *   c.sh;: 4

**Key Observations and Anomalies:**
- The high number of events associated with the "DoublePulsar Backdoor" signature suggests a targeted campaign exploiting the SMB vulnerability.
- The commands executed by attackers indicate a clear pattern of reconnaissance (e.g., `uname -a`, `lscpu`) followed by attempts to establish persistence (e.g., modifying `.ssh/authorized_keys`).
- The IP address `72.146.232.13` was consistently active across all three log files, suggesting a persistent actor.
