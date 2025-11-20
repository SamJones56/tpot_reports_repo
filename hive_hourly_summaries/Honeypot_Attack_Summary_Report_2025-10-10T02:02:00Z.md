**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-10T02:01:39Z
**Timeframe:** 2025-10-10T01:20:02Z to 2025-10-10T02:00:01Z
**Files Used:**
- agg_log_20251010T012002Z.json
- agg_log_20251010T014001Z.json
- agg_log_20251010T020001Z.json

**Executive Summary**
This report summarizes 24,035 events recorded across the honeypot network. The majority of activity was captured by the Cowrie honeypot, indicating a high volume of SSH and telnet-based attacks. A significant number of events were also logged by Suricata, Dionaea, and Honeytrap. The most prominent attack vector appears to be SMB/CIFS, with port 445 being the most targeted. A large portion of this traffic is linked to the DoublePulsar backdoor, as evidenced by Suricata signatures. Brute-force login attempts and automated command execution upon successful entry remain prevalent tactics.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 9,934
    *   Suricata: 4,826
    *   Dionaea: 3,446
    *   Honeytrap: 3,311
    *   Ciscoasa: 1,814
    *   Sentrypeer: 365
    *   Tanner: 109
    *   ConPot: 58
    *   Mailoney: 45
    *   Honeyaml: 32
    *   Redishoneypot: 33
    *   Adbhoney: 23
    *   Dicompot: 13
    *   H0neytr4p: 17
    *   ElasticPot: 5
    *   Miniprint: 3
    *   Ipphoney: 1

*   **Top Attacking IPs:**
    *   180.180.217.239: 3,117
    *   103.28.161.199: 1,416
    *   167.250.224.25: 1,403
    *   118.96.95.30: 1,381
    *   45.91.193.63: 1,286
    *   134.209.54.142: 1,279
    *   64.227.125.115: 1,244

*   **Top Targeted Ports/Protocols:**
    *   445 (SMB): 3,162
    *   TCP/445 (SMB): 2,790
    *   22 (SSH): 1,636
    *   5060 (SIP): 365
    *   3306 (MySQL): 204
    *   8333 (Bitcoin): 143
    *   5903 (VNC): 207

*   **Most Common CVEs:**
    *   CVE-2024-4577 CVE-2024-4577: 4
    *   CVE-2024-4577 CVE-2002-0953: 4
    *   CVE-1999-0183: 2
    *   CVE-2002-0013 CVE-2002-0012: 2
    *   CVE-2019-11500 CVE-2019-11500: 2
    *   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 2
    *   CVE-2021-42013 CVE-2021-42013: 2

*   **Commands Attempted by Attackers:**
    *   `cd ~ && rm -rf .ssh && ...`: 28
    *   `lockr -ia .ssh`: 28
    *   System reconnaissance commands (`uname -a`, `whoami`, `w`, `top`): ~29 each
    *   `crontab -l`: 29
    *   `cat /proc/cpuinfo | ...`: 29

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,786
    *   ET DROP Dshield Block Listed Source group 1: 545
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 279
    *   ET SCAN NMAP -sS window 1024: 162
    *   ET HUNTING RDP Authentication Bypass Attempt: 120

*   **Users / Login Attempts:**
    *   root/: 202
    *   345gs5662d34/345gs5662d34: 26
    *   vpn/vpn: 7
    *   root/wsx.123: 7
    *   Multiple variations of `root` with common passwords.

*   **Files Uploaded/Downloaded:**
    *   sh: 196
    *   Multiple `.css`, `.js`, and image files related to web exploits.
    *   w.sh, c.sh, wget.sh: Multiple instances

*   **HTTP User-Agents:**
    *   No significant HTTP user-agent data was observed in this period.

*   **SSH Clients and Servers:**
    *   No specific SSH client or server version data was logged.

*   **Top Attacker AS Organizations:**
    *   No attacker AS organization data was available in the logs.

**Key Observations and Anomalies**
- The high number of hits on port 445, combined with the "DoublePulsar Backdoor" signature, indicates a sustained campaign to exploit the vulnerability patched by MS17-010.
- Attackers on Cowrie instances consistently attempt to deploy the same SSH public key, suggesting an automated script to maintain access to compromised hosts.
- A wide variety of system reconnaissance commands are executed post-breach, which is typical of automated bots cataloging the specifications of the compromised machine for potential use in botnets.
