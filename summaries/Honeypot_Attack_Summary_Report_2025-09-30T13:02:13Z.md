Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T13:01:35Z
**Timeframe:** 2025-09-30T12:20:01Z to 2025-09-30T13:00:01Z

**Files Used:**
- agg_log_20250930T122001Z.json
- agg_log_20250930T124001Z.json
- agg_log_20250930T130001Z.json

**Executive Summary:**
This report summarizes 11,460 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. Attackers were observed attempting to gain access via SSH and other common ports, deploy malware, and add SSH keys for persistent access.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 5541
    *   Honeytrap: 2040
    *   Ciscoasa: 1466
    *   Suricata: 1180
    *   Mailoney: 851
    *   Heralding: 106
    *   H0neytr4p: 75
    *   Adbhoney: 64
    *   Sentrypeer: 47
    *   Dionaea: 27
    *   ConPot: 24
    *   Tanner: 24
    *   Redishoneypot: 9
    *   Dicompot: 3
    *   Ipphoney: 2
    *   Honeyaml: 1

*   **Top Attacking IPs:**
    *   86.54.42.238
    *   202.157.177.161
    *   118.194.230.250
    *   96.92.63.243
    *   103.103.245.61
    *   141.147.48.126
    *   158.174.210.161
    *   110.159.172.76
    *   34.80.109.90
    *   103.139.192.17
    *   67.217.243.120

*   **Top Targeted Ports/Protocols:**
    *   25
    *   22
    *   TCP/1080
    *   8333
    *   6001
    *   443
    *   27018

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
    *   CVE-2019-11500 CVE-2019-11500

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   cat /proc/cpuinfo | grep name | wc -l
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    *   uname -a
    *   crontab -l
    *   w
    *   uname -m

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   GPL INFO SOCKS Proxy attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET INFO CURL User Agent

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/3245gs5662d34
    *   root/nPSpP4PBW0
    *   work/workwork
    *   root/LeitboGi0ro
    *   titu/Ahgf3487@rtjhskl854hd47893@#a4nC

*   **Files Uploaded/Downloaded:**
    *   arm.urbotnetisass
    *   arm5.urbotnetisass
    *   arm6.urbotnetisass
    *   arm7.urbotnetisass
    *   x86_32.urbotnetisass
    *   mips.urbotnetisass
    *   mipsel.urbotnetisass
    *   wget.sh;
    *   w.sh;
    *   c.sh;

*   **HTTP User-Agents:**
    *   Not observed in this period.

*   **SSH Clients:**
    *   Not observed in this period.

*   **SSH Servers:**
    *   Not observed in this period.

*   **Top Attacker AS Organizations:**
    *   Not observed in this period.

**Key Observations and Anomalies:**
- A significant number of commands are related to reconnaissance of the system (e.g., `uname -a`, `cat /proc/cpuinfo`).
- Attackers are consistently attempting to add their own SSH key to the `authorized_keys` file for persistent access. The key is associated with the user "mdrfckr".
- Multiple attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from the IP `161.97.149.138`.
- Multiple attempts to download and execute various `urbotnetisass` malware variants for different architectures from the IP `94.154.35.154`.
- The high number of events from the Mailoney honeypot suggests a large amount of SMTP-based scanning or attack activity.
- The most common signatures triggered are related to blocklisted IPs and port scanning, indicating a high volume of automated attacks.
