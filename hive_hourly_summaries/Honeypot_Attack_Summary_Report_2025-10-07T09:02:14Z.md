Here is the Honeypot Attack Summary Report.

### Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T09:01:38Z
**Timeframe:** 2025-10-07T08:20:01Z to 2025-10-07T09:00:01Z
**Files Used:**
* `agg_log_20251007T082001Z.json`
* `agg_log_20251007T084001Z.json`
* `agg_log_20251007T090001Z.json`

---

### Executive Summary

This report summarizes 15,343 observed events across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. A significant spike in activity targeting SMB (port 445) was detected, largely attributed to a single IP address (41.38.14.67) and associated with the DoublePulsar backdoor signature. Attackers persistently attempted to add their SSH keys to `authorized_keys` for persistence.

---

### Detailed Analysis

**Attacks by Honeypot:**
* **Cowrie:** 8175
* **Suricata:** 2833
* **Honeytrap:** 2747
* **Ciscoasa:** 671
* **Sentrypeer:** 444
* **Dionaea:** 229
* **Mailoney:** 57
* **H0neytr4p:** 41
* **ConPot:** 27
* **Redishoneypot:** 30
* **Tanner:** 38
* **Heralding:** 19
* **Honeyaml:** 20
* **Adbhoney:** 6
* **Ipphoney:** 4
* **ssh-rsa:** 2

**Top Attacking IPs:**
* **41.38.14.67:** 1338
* **172.86.95.98:** 429
* **51.195.138.37:** 193
* **103.103.20.246:** 278
* **185.81.97.150:** 233
* **62.3.42.68:** 288
* **103.220.207.174:** 288
* **27.71.230.3:** 233
* **190.0.63.226:** 223
* **1.9.107.43:** 184
* **172.174.5.146:** 233
* **123.58.209.224:** 202
* **46.101.124.247:** 137
* **218.78.132.164:** 135
* **40.160.9.156:** 142
* **223.240.116.60:** 147

**Top Targeted Ports/Protocols:**
* **TCP/445:** 1334
* **22 (SSH):** 1142
* **5060 (SIP):** 444
* **445 (SMB):** 112
* **5903 (VNC):** 104
* **8333 (Bitcoin):** 97
* **27017 (MongoDB):** 70
* **23 (Telnet):** 58
* **TCP/1433 (MSSQL):** 39
* **25 (SMTP):** 57
* **80 (HTTP):** 53
* **8088:** 32

**Most Common CVEs:**
* **CVE-2002-0013, CVE-2002-0012, CVE-1999-0517:** 14
* **CVE-2019-11500:** 6
* **CVE-2021-3449:** 3
* **CVE-1999-0265:** 2
* **CVE-2023-26801:** 1
* **CVE-2006-3602, CVE-2006-4458, CVE-2006-4542:** 1
* **CVE-1999-0183:** 1

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
* `Enter new UNIX password:`
* `cat /proc/cpuinfo | grep name | wc -l`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `uname -a`
* `whoami`
* `w`
* `crontab -l`
* `lscpu | grep Model`

**Signatures Triggered:**
* **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 1331
* **ET DROP Dshield Block Listed Source group 1:** 442
* **ET SCAN NMAP -sS window 1024:** 145
* **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 94
* **ET INFO Reserved Internal IP Traffic:** 58
* **ET SCAN Suspicious inbound to MSSQL port 1433:** 28
* **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 29

**Users / Login Attempts:**
* **345gs5662d34/345gs5662d34:** 48
* **ubuntu/3245gs5662d34:** 12
* **david/david!:** 6
* **postgres/postgres:** 2
* **root/P@ssw0rd:** 3
* **admin/(multiple passwords):** 8+
* **sysadmin/sysadmin:** 3

---

### Key Observations and Anomalies

*   **High-Volume SMB Scan:** A single IP address, **41.38.14.67**, was responsible for 1,338 events targeting TCP port 445. The associated Suricata signature, "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor," strongly suggests this is automated scanning for systems vulnerable to exploits leaked by the Shadow Brokers.
*   **SSH Key Persistence:** A recurring pattern observed in Cowrie logs is the attempt to delete the existing `.ssh` directory, create a new one, and inject a hardcoded RSA public key into the `authorized_keys` file. This is a common tactic to ensure persistent access to a compromised machine.
*   **System Reconnaissance:** Attackers consistently ran a series of commands (`uname -a`, `lscpu`, `free -m`, `w`) to gather information about the system's architecture, CPU, memory, and logged-in users. This is standard post-exploitation behavior to assess the environment.
*   **Credential Stuffing:** A wide variety of username and password combinations were attempted, from default credentials (e.g., `admin/admin`, `postgres/postgres`) to more complex but common passwords, indicating broad, automated brute-force campaigns.

This concludes the Honeypot Attack Summary Report.