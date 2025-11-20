# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T01:01:44Z
**Timeframe of Analysis:** 2025-10-04T00:20:01Z to 2025-10-04T01:00:02Z
**Log Files Used:**
- agg_log_20251004T002001Z.json
- agg_log_20251004T004001Z.json
- agg_log_20251004T010002Z.json

---

### Executive Summary

This report summarizes a total of 7,777 attacks recorded by the honeypot network during the analysis period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks were also observed on Cisco ASA (Ciscoasa) and mail (Mailoney) honeypots. Top attacking IPs originate from various geolocations, and attackers frequently targeted ports 25 (SMTP) and 22 (SSH). Several CVEs were exploited, and a variety of shell commands were executed, indicating attempts to establish persistence, gather system information, and download additional malware.

---

### Detailed Analysis

**Attacks by Honeypot:**
*   **Cowrie:** 3,026
*   **Ciscoasa:** 1,838
*   **Suricata:** 1,290
*   **Mailoney:** 841
*   **Sentrypeer:** 218
*   **Honeytrap:** 210
*   **Dionaea:** 139
*   **H0neytr4p:** 68
*   **Adbhoney:** 52
*   **Tanner:** 28
*   **ssh-rsa:** 30
*   **ConPot:** 11
*   **Miniprint:** 9
*   **Redishoneypot:** 12
*   **Wordpot:** 1
*   **Ipphoney:** 1
*   **Heralding:** 3

**Top Attacking IPs:**
*   176.65.141.117: 820
*   185.156.73.166: 219
*   170.233.151.14: 217
*   58.56.23.210: 183
*   139.150.83.88: 182
*   138.99.80.102: 234
*   171.244.61.82: 202
*   46.105.87.113: 180
*   178.62.19.223: 150
*   118.186.3.158: 129
*   165.154.36.71: 168

**Top Targeted Ports/Protocols:**
*   25: 841
*   22: 444
*   5060: 218
*   3306: 79
*   443: 68
*   80: 33
*   TCP/80: 28
*   TCP/22: 28
*   23: 21
*   UDP/161: 30
*   81: 32

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 20
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
*   CVE-2021-35394 CVE-2021-35394: 3
*   CVE-2005-4050: 2
*   CVE-2024-3721 CVE-2024-3721: 1
*   CVE-2023-26801 CVE-2023-26801: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
*   `lockr -ia .ssh`: 15
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 15
*   `cat /proc/cpuinfo | grep name | wc -l`: 15
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 14
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 14
*   `ls -lh $(which ls)`: 14
*   `which ls`: 14
*   `crontab -l`: 14
*   `w`: 14
*   `uname -m`: 14
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 14
*   `top`: 14
*   `uname`: 14
*   `uname -a`: 14
*   `whoami`: 14
*   `lscpu | grep Model`: 14
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 14
*   `Enter new UNIX password: `: 8
*   `Enter new UNIX password:`: 8

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1: 370
*   2402000: 370
*   ET SCAN NMAP -sS window 1024: 170
*   2009582: 170
*   ET INFO Reserved Internal IP Traffic: 58
*   2002752: 58
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 27
*   2403347: 27
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 27
*   2400031: 27
*   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
*   2403344: 22
*   ET CINS Active Threat Intelligence Poor Reputation IP group 51: 19
*   2403350: 19
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 24
*   2023753: 24

**Users / Login Attempts:**
*   a2billinguser/: 78
*   root/: 30
*   345gs5662d34/345gs5662d34: 13
*   root/nPSpP4PBW0: 9
*   root/2glehe5t24th1issZs: 6
*   superadmin/admin123: 5
*   test/zhbjETuyMffoL8F: 5
*   root/LeitboGi0ro: 5
*   root/Ahgf3487@rtjhskl854hd47893@#a4nC: 3
*   3245gs5662d34/3245gs5662d34: 3

**Files Uploaded/Downloaded:**
*   wget.sh;: 8
*   UnHAnaAW.mpsl;: 8
*   11: 7
*   fonts.gstatic.com: 7
*   css?family=Libre+Franklin...: 7
*   ie8.css?ver=1.0: 7
*   html5.js?ver=3.7.3: 7
*   UnHAnaAW.arm;: 4
*   UnHAnaAW.arm5;: 4
*   UnHAnaAW.arm6;: 4
*   UnHAnaAW.arm7;: 4
*   UnHAnaAW.m68k;: 4
*   UnHAnaAW.mips;: 4
*   UnHAnaAW.ppc;: 4
*   UnHAnaAW.sh4;: 4
*   UnHAnaAW.spc;: 4
*   UnHAnaAW.x86;: 4
*   w.sh;: 2
*   c.sh;: 2
*   arm.urbotnetisass;: 2

**HTTP User-Agents:**
*   *No user agents recorded in this period.*

**SSH Clients:**
*   *No SSH clients recorded in this period.*

**SSH Servers:**
*   *No SSH servers recorded in this period.*

**Top Attacker AS Organizations:**
*   *No AS organizations recorded in this period.*

---

### Key Observations and Anomalies

*   **High Volume of Automated Scans:** The prevalence of reconnaissance commands like `uname -a`, `whoami`, and `lscpu` suggests widespread automated scanning and information gathering by attackers to tailor their exploits.
*   **Persistent Threat Actors:** The repeated use of commands to modify SSH authorized_keys (`cd ~ && rm -rf .ssh && ...`) indicates a consistent campaign by one or more actors to establish persistent access to compromised systems. The specific SSH key `AAAAB3NzaC1yc2EAAAABJQAAA...` was seen across all log files.
*   **Malware Delivery:** Attackers attempted to download and execute various shell scripts (`w.sh`, `c.sh`, `wget.sh`) and ELF binaries for different architectures (`UnHAnaAW.*`, `*.urbotnetisass`), suggesting the deployment of botnet malware. The domains `161.97.147.255` and `94.154.35.154` were used for malware hosting.
*   **Credential Stuffing:** The high number of login attempts with common and default credentials (e.g., `root`, `admin`, `a2billinguser`) across different honeypots highlights the continued effectiveness of brute-force and credential stuffing attacks.
