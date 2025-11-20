Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T15:01:48Z
**Timeframe of Analysis:** 2025-10-21T14:20:01Z to 2025-10-21T15:00:01Z
**Log Files Analyzed:**
- agg_log_20251021T142001Z.json
- agg_log_20251021T144001Z.json
- agg_log_20251021T150001Z.json

**Executive Summary**
This report summarizes 20,845 events captured by the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and shell command execution. A significant number of attacks also targeted SMB services (port 445), captured by the Dionaea honeypot. The top attacking IP, 187.251.242.70, was highly active, responsible for nearly 15% of all observed events. Attackers were observed attempting to gain system information and install SSH keys for persistent access. Several network scan and intrusion detection signatures were triggered, with a high prevalence of scanning for MS Terminal Server.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 10,100
    *   Dionaea: 4,879
    *   Honeytrap: 3,493
    *   Suricata: 1,481
    *   Sentrypeer: 319
    *   Dicompot: 160
    *   Tanner: 105
    *   Mailoney: 98
    *   Redishoneypot: 67
    *   H0neytr4p: 71

*   **Top Attacking IPs:**
    *   187.251.242.70
    *   186.167.186.171
    *   72.146.232.13
    *   8.213.80.73
    *   107.172.151.218
    *   217.154.201.75
    *   195.154.114.27
    *   40.82.214.8

*   **Top Targeted Ports/Protocols:**
    *   445 (SMB)
    *   22 (SSH)
    *   5060 (SIP)
    *   5903 (VNC)
    *   2012
    *   1337

*   **Most Common CVEs:**
    *   CVE-2019-11500
    *   CVE-2021-3449
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0517
    *   CVE-2003-0825
    *   CVE-2005-4050

*   **Commands Attempted by Attackers:**
    *   A consistent pattern of commands was observed to gather system information (`uname`, `lscpu`, `free`, `w`, `top`, `crontab -l`).
    *   Multiple attempts were made to modify SSH access by clearing `.ssh` directory contents and adding a new public key to `authorized_keys`.
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `Enter new UNIX password:`

*   **Signatures Triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   GPL INFO SOCKS Proxy attempt
    *   ET INFO Reserved Internal IP Traffic

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/3245gs5662d34
    *   odin/odin
    *   root/APHa1d2m3i4n5
    *   user01/Password01

*   **Files Uploaded/Downloaded:**
    *   sh

*   **HTTP User-Agents:**
    *   No significant HTTP user-agent data was observed in this period.

*   **SSH Clients and Servers:**
    *   SSH Clients: No specific client versions were identified in the logs.
    *   SSH Servers: No specific server versions were identified in the logs.

*   **Top Attacker AS Organizations:**
    *   No attacker AS organization data was present in the logs.

**Key Observations and Anomalies**
- The high volume of activity from a single IP (187.251.242.70) suggests a targeted or automated campaign.
- The consistent use of shell commands aimed at reconnaissance and establishing persistence via SSH keys indicates a common attack pattern, likely from a botnet.
- The prevalence of scans for MS Terminal Server on non-standard ports highlights ongoing attacker interest in exploiting RDP vulnerabilities.
- While multiple CVEs were identified, the activity did not seem to focus on a single vulnerability, indicating a broad-spectrum scanning approach.

This concludes the Honeypot Attack Summary Report.
