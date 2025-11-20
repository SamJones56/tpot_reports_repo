Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T06:01:26Z
**Timeframe:** 2025-10-15T05:20:01Z to 2025-10-15T06:00:02Z
**Files Used:**
- `agg_log_20251015T052001Z.json`
- `agg_log_20251015T054001Z.json`
- `agg_log_20251015T060002Z.json`

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 20,823 events were recorded. The most active honeypots were Cowrie, Suricata, and Honeytrap. A significant portion of the attacks originated from IP addresses `197.167.29.138` and `110.136.3.178`. The most targeted ports were TCP/445 (SMB) and 25 (SMTP). Several CVEs were detected, and a variety of shell commands were attempted, indicating efforts to profile the systems and establish persistent access.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 5817
    *   Suricata: 4920
    *   Honeytrap: 4468
    *   Ciscoasa: 1835
    *   Mailoney: 1652
    *   Sentrypeer: 1695
    *   Dionaea: 256
    *   ConPot: 37
    *   Tanner: 41
    *   Miniprint: 33
    *   Redishoneypot: 24
    *   ElasticPot: 12
    *   H0neytr4p: 17
    *   Honeyaml: 3
    *   Adbhoney: 5
    *   Ipphoney: 5
    *   Dicompot: 3

*   **Top Attacking IPs:**
    *   197.167.29.138: 1317
    *   110.136.3.178: 1377
    *   206.191.154.180: 1356
    *   88.214.50.58: 706
    *   176.65.141.119: 785
    *   172.86.95.98: 454
    *   172.86.95.115: 451
    *   86.54.42.238: 822
    *   185.213.165.211: 365
    *   185.243.5.121: 343
    *   62.141.43.183: 323

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 2686
    *   25: 1653
    *   5060: 1695
    *   22: 707
    *   1433: 203
    *   5903: 189
    *   TCP/1433: 104
    *   23: 77
    *   8333: 122

*   **Most Common CVEs:**
    *   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
    *   CVE-2002-0013 CVE-2002-0012: 3
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 35
    *   `lockr -ia .ssh`: 35
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 35
    *   `cat /proc/cpuinfo | grep name | wc -l`: 35
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 35
    *   `uname -a`: 36
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 23
    *   `Enter new UNIX password: `: 9

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2681
    *   ET DROP Dshield Block Listed Source group 1: 539
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 358
    *   ET HUNTING RDP Authentication Bypass Attempt: 176
    *   ET SCAN NMAP -sS window 1024: 177
    *   GPL TELNET Bad Login: 61
    *   ET SCAN Suspicious inbound to MSSQL port 1433: 103

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34: 34
    *   root/3245gs5662d34: 22
    *   root/Qaz123qaz: 17
    *   root/Password@2025: 13
    *   sa/147369: 10
    *   config/777777: 6
    *   admin/admin2020: 6
    *   unknown/unknown2021: 6

*   **Files Uploaded/Downloaded:**
    *   Mozi.m: 4
    *   ): 1
    *   arm.urbotnetisass: 2
    *   arm5.urbotnetisass: 2
    *   arm6.urbotnetisass: 2
    *   arm7.urbotnetisass: 2
    *   x86_32.urbotnetisass: 2
    *   mips.urbotnetisass: 2
    *   mipsel.urbotnetisass: 2

*   **HTTP User-Agents:**
    *   None observed.

*   **SSH Clients and Servers:**
    *   None observed.

*   **Top Attacker AS Organizations:**
    *   None observed.

**Key Observations and Anomalies:**
- The high number of events related to the "DoublePulsar Backdoor" signature suggests targeted attacks against a known SMB vulnerability.
- The repeated execution of commands to gather system information (`uname`, `lscpu`, `free`) followed by attempts to modify SSH authorized keys is a common pattern for establishing persistence.
- The download of various `urbotnetisass` ELF files for different architectures indicates a malware campaign targeting IoT or embedded devices.
- A significant number of login attempts used common or default credentials, highlighting the continued effectiveness of brute-force attacks.
