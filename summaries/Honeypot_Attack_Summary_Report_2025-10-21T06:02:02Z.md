Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T06:01:23Z
**Timeframe:** 2025-10-21T05:20:01Z to 2025-10-21T06:00:01Z
**Log Files:**
- agg_log_20251021T052001Z.json
- agg_log_20251021T054001Z.json
- agg_log_20251021T060001Z.json

**Executive Summary:**
This report summarizes 7,798 malicious events recorded across the honeypot network. The majority of attacks were SSH brute-force attempts captured by the Cowrie honeypot. A significant amount of scanning activity was also observed, particularly targeting ports 22 (SSH) and 5060 (SIP). Attackers were observed attempting to download and execute malware, and several CVEs were targeted.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 5264
    *   Honeytrap: 1381
    *   Suricata: 712
    *   Sentrypeer: 194
    *   Dionaea: 88
    *   Redishoneypot: 31
    *   Mailoney: 44
    *   H0neytr4p: 19
    *   Tanner: 19
    *   Miniprint: 13
    *   ConPot: 8
    *   Ciscoasa: 11
    *   Adbhoney: 7
    *   ElasticPot: 3
    *   Honeyaml: 3
    *   Ipphoney: 1

*   **Top 10 Attacking IPs:**
    *   72.146.232.13: 606
    *   43.153.109.70: 490
    *   138.68.171.6: 426
    *   103.20.223.95: 416
    *   128.1.44.115: 431
    *   103.217.145.144: 337
    *   36.50.176.39: 366
    *   159.89.98.186: 325
    *   217.112.80.175: 247
    *   194.226.49.149: 222

*   **Top 10 Targeted Ports/Protocols:**
    *   22: 729
    *   5060: 194
    *   8333: 73
    *   5904: 78
    *   5905: 76
    *   445: 44
    *   25: 44
    *   6379: 28
    *   5901: 43
    *   5902: 39

*   **Most Common CVEs:**
    *   CVE-2024-3721: 3
    *   CVE-2021-3449: 1
    *   CVE-2002-0013, CVE-2002-0012: 1

*   **Top 10 Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh: 36
    *   lockr -ia .ssh: 36
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 36
    *   cat /proc/cpuinfo | grep name | wc -l: 35
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 35
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 35
    *   ls -lh $(which ls): 35
    *   which ls: 35
    *   crontab -l: 35
    *   w: 35

*   **Top 5 Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1: 223
    *   2402000: 223
    *   ET SCAN NMAP -sS window 1024: 86
    *   2009582: 86
    *   ET INFO Reserved Internal IP Traffic: 41

*   **Top 5 Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 32
    *   user01/Password01: 12
    *   deploy/123123: 7
    *   root/Password@2024: 5
    *   staging/staging: 6

*   **Files Uploaded/Downloaded:**
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

*   **HTTP User-Agents:**
    *   None observed.

*   **SSH Clients:**
    *   None observed.

*   **SSH Servers:**
    *   None observed.

*   **Top Attacker AS Organizations:**
    *   None observed.

**Key Observations and Anomalies:**
- The command `cd ~ && rm -rf .ssh && ...` is a common technique used to install a persistent SSH key on a compromised machine.
- The `urbotnetisass` files downloaded suggest an attempt to install a botnet client on the honeypot.
- The high number of scans on port 22 and the high volume of Cowrie events indicate a large-scale, automated SSH brute-force campaign.
- The presence of CVEs from various years, including recent ones like CVE-2024-3721 and much older ones like CVE-2002-0013, shows that attackers use a wide range of exploits to target systems.
