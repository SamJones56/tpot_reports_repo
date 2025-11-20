**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-10T12:01:40Z
**Timeframe:** 2025-10-10T11:20:01Z to 2025-10-10T12:00:01Z
**Files Used to Generate Report:**
- agg_log_20251010T112001Z.json
- agg_log_20251010T114001Z.json
- agg_log_20251010T120001Z.json

**Executive Summary**

This report summarizes 14,553 malicious events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. The most prolific attacking IP address was 167.250.224.25. Attackers primarily targeted port 22 (SSH), followed by port 445 (SMB) and port 80 (HTTP). A significant number of activities involved reconnaissance commands to identify system architecture and resource information. Multiple CVEs were detected, with a focus on older vulnerabilities. A recurring pattern observed was the attempt to add a specific public SSH key to the authorized_keys file for persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
*   Cowrie: 6014
*   Honeytrap: 2544
*   Suricata: 2270
*   Ciscoasa: 1749
*   Dionaea: 876
*   Tanner: 586
*   Sentrypeer: 359
*   H0neytr4p: 40
*   Miniprint: 37
*   Mailoney: 46

**Top Attacking IPs:**
*   167.250.224.25: 972
*   51.250.65.61: 789
*   1.53.140.58: 725
*   85.208.84.144: 507
*   85.208.84.142: 499
*   31.220.99.243: 533
*   152.52.15.214: 264
*   113.193.234.210: 268
*   45.134.26.3: 222
*   88.210.63.16: 232

**Top Targeted Ports/Protocols:**
*   22: 960
*   445: 733
*   80: 588
*   5060: 359
*   5903: 202
*   1433: 83
*   TCP/1433: 81
*   8333: 109
*   5901: 82
*   5908: 82
*   5909: 82

**Most Common CVEs:**
*   CVE-2002-1149
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2006-2369

**Commands Attempted by Attackers:**
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
*   cat /proc/cpuinfo | grep name | wc -l
*   free -m | grep Mem
*   crontab -l
*   uname -m

**Signatures Triggered:**
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET SCAN NMAP -sS window 1024
*   ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
*   ET SCAN Suspicious inbound to MSSQL port 1433
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan

**Users / Login Attempts (Username/Password):**
*   345gs5662d34/345gs5662d34
*   support/1234567899
*   support/support4
*   support/9
*   supervisor/supervisor44
*   root/XSW!123456
*   dockeruser/dockeruser!
*   guest/webadmin
*   ubnt/ubnt2022
*   default/asdfgh

**Files Uploaded/Downloaded:**
*   a>
*   Help:Contents
*   guide
*   sta
*   welcome.jpg)
*   writing.jpg)
*   tags.jpg)
*   rondo.qpu.sh||wget

**HTTP User-Agents:**
*   No HTTP User-Agent data was recorded in this period.

**SSH Clients and Servers:**
*   **Clients:** No SSH client data was recorded in this period.
*   **Servers:** No SSH server data was recorded in this period.

**Top Attacker AS Organizations:**
*   No Attacker AS Organization data was recorded in this period.

**Key Observations and Anomalies**

- **System Reconnaissance:** A significant portion of the command execution attempts are focused on system reconnaissance (e.g., `uname`, `lscpu`, `df`, `free`). This suggests attackers are performing initial enumeration to tailor subsequent attacks.
- **Persistent Access Attempts:** The command to remove the `.ssh` directory and add a new `authorized_keys` file with a hardcoded RSA key was observed frequently across all log files. This is a clear indicator of an automated script attempting to establish persistent access.
- **High RDP/MSSQL Scans:** The Suricata signatures show a high volume of scans for Microsoft Terminal Server (RDP) on non-standard ports and for MSSQL (1433). This indicates widespread, automated scanning for these services.
- **Lack of Specific Data:** There is a notable absence of data for HTTP User-Agents, SSH client/server versions, and ASN information. This may be due to the nature of the attacks or a configuration aspect of the honeypots.
