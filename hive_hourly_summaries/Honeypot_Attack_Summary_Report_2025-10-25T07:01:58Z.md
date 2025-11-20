Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T07:01:34Z
**Timeframe:** 2025-10-25T06:20:01Z to 2025-10-25T07:00:01Z
**Log Files:** agg_log_20251025T062001Z.json, agg_log_20251025T064001Z.json, agg_log_20251025T070001Z.json

### Executive Summary

This report summarizes 14,914 attacks recorded across three honeypot log files. The most targeted services were Cowrie (SSH) and Honeytrap, indicating a high volume of automated SSH brute-force attempts and scans for various services. The most prominent attacking IP was 103.160.232.131, heavily targeting port 445 (SMB). A significant number of commands were executed, primarily focused on reconnaissance and establishing unauthorized SSH access.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 4190
*   Honeytrap: 4115
*   Suricata: 2171
*   Dionaea: 1924
*   Ciscoasa: 1858
*   Sentrypeer: 212
*   Mailoney: 187
*   Tanner: 79
*   Redishoneypot: 62
*   Adbhoney: 31
*   H0neytr4p: 17
*   Miniprint: 16
*   Heralding: 16
*   Honeyaml: 18
*   ConPot: 10
*   Dicompot: 3
*   ElasticPot: 3
*   ssh-rsa: 2

**Top Attacking IPs:**
*   103.160.232.131: 1714
*   80.94.95.238: 1450
*   46.32.178.190: 558
*   117.131.245.62: 312
*   185.76.32.44: 260
*   91.92.199.36: 176
*   107.170.36.5: 250
*   64.227.129.56: 238
*   103.72.147.99: 199
*   5.182.209.68: 202
*   72.167.52.254: 178

**Top Targeted Ports/Protocols:**
*   445: 1727
*   22: 572
*   25: 187
*   5060: 212
*   3306: 171
*   8333: 180
*   5903: 132
*   5901: 111
*   6379: 62
*   23: 65
*   80: 59

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 14
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
*   CVE-2021-3449 CVE-2021-3449: 3
*   CVE-2019-11500 CVE-2019-11500: 3
*   CVE-2005-4050: 1

**Commands Attempted by Attackers:**
*   Commands related to disabling security and adding SSH keys (e.g., `chattr -ia .ssh`, `echo "ssh-rsa..." >> .ssh/authorized_keys`): 20
*   System reconnaissance commands (`uname -a`, `whoami`, `cat /proc/cpuinfo`, `crontab -l`): 20 each
*   Password change attempts (`Enter new UNIX password:`): 19
*   Malware download and execution (`wget`, `curl`, `chmod +x`, `./<malware>`): 4
*   TFTP/Busybox commands: 1

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 733
*   ET DROP Dshield Block Listed Source group 1: 433
*   ET SCAN NMAP -sS window 1024: 179
*   ET INFO Reserved Internal IP Traffic: 58
*   ET HUNTING RDP Authentication Bypass Attempt: 43

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 17
*   root/[multiple passwords]: 16+
*   admin/[multiple passwords]: 6+
*   Various other users: adm, maint, system, pi, mysql, etc.

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass: 4
*   sh: 6
*   wget.sh: 4
*   w.sh: 1
*   c.sh: 1

**HTTP User-Agents:**
*   None recorded.

**SSH Clients and Servers:**
*   None recorded.

**Top Attacker AS Organizations:**
*   None recorded.

### Key Observations and Anomalies

*   **High Volume SMB Traffic:** The significant number of events targeting port 445 suggests widespread scanning for SMB vulnerabilities, likely related to exploits like EternalBlue.
*   **Persistent SSH Compromise Attempts:** Attackers consistently attempted to add their own SSH keys to the `authorized_keys` file, a common technique to maintain persistent access.
*   **Malware Deployment:** Multiple attempts to download and execute malware targeting various architectures (ARM, x86, MIPS) were observed, indicating automated infection campaigns.
*   **Credential Stuffing:** A wide variety of usernames and passwords were used in login attempts, characteristic of brute-force attacks using common or previously breached credentials.
