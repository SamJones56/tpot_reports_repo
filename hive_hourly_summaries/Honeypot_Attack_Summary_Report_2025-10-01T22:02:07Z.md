## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T22:01:36Z
**Timeframe:** 2025-10-01T21:20:01Z to 2025-10-01T22:00:01Z
**Files Used:**
- agg_log_20251001T212001Z.json
- agg_log_20251001T214001Z.json
- agg_log_20251001T220001Z.json

### Executive Summary

This report summarizes the threat intelligence data collected from the T-Pot honeypot network over a 40-minute period. A total of 17,243 attacks were recorded across various honeypots. The majority of attacks were targeted at the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. The most prolific attacking IP address was 103.130.215.15, responsible for 5,749 individual events. A significant number of attacks targeted port 22 (SSH), followed by port 445 (SMB). Attackers attempted to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most frequently targeted. A variety of commands were executed on the honeypots, including reconnaissance commands and attempts to download and execute malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 10100
*   Honeytrap: 2529
*   Suricata: 1630
*   Ciscoasa: 1453
*   Dionaea: 1020
*   H0neytr4p: 200
*   Tanner: 89
*   Redishoneypot: 49
*   Adbhoney: 45
*   Mailoney: 44
*   ConPot: 44
*   Sentrypeer: 30
*   Heralding: 3
*   Dicompot: 3
*   Wordpot: 2
*   ElasticPot: 1
*   Honeyaml: 1

**Top Attacking IPs:**
*   103.130.215.15
*   187.136.122.22
*   106.75.131.128
*   179.1.143.50
*   185.156.73.166
*   185.156.73.167
*   88.210.63.16
*   92.63.197.55
*   209.38.35.67
*   92.63.197.59

**Top Targeted Ports/Protocols:**
*   22
*   445
*   443
*   8333
*   80
*   5901
*   TCP/80
*   23
*   TCP/22
*   25

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2024-4577 CVE-2024-4577
*   CVE-2024-4577 CVE-2002-0953
*   CVE-2021-35394 CVE-2021-35394
*   CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
*   CVE-2021-42013 CVE-2021-42013
*   CVE-2023-26801 CVE-2023-26801
*   CVE-1999-0183
*   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
*   CVE-2017-7577 CVE-2017-7577
*   CVE-2005-4050

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `uname -a`
*   `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...`
*   `Enter new UNIX password:`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/nPSpP4PBW0
*   superadmin/admin123
*   foundry/foundry
*   test/zhbjETuyMffoL8F
*   seekcy/Joysuch@Locate2022
*   root/2glehe5t24th1issZs
*   root/LeitboGi0ro
*   dd/dd123
*   teamspeak/qwerty123

**Files Uploaded/Downloaded:**
*   sh
*   wget.sh;
*   w.sh;
*   c.sh;
*   arm.urbotnetisass;
*   arm.urbotnetisass
*   arm5.urbotnetisass;
*   arm5.urbotnetisass
*   arm6.urbotnetisass;
*   arm6.urbotnetisass
*   arm7.urbotnetisass;
*   arm7.urbotnetisass

**HTTP User-Agents:**
*   *No user agents recorded in this period.*

**SSH Clients and Servers:**
*   *No SSH clients or servers recorded in this period.*

**Top Attacker AS Organizations:**
*   *No attacker AS organizations recorded in this period.*

### Key Observations and Anomalies

*   **High Volume of Cowrie Attacks:** The Cowrie honeypot recorded the highest number of attacks, indicating a sustained interest in compromising SSH and Telnet services. The commands executed suggest that attackers are attempting to gain persistent access by adding their SSH keys to the `authorized_keys` file.
*   **Malware Download Attempts:** Several commands were observed attempting to download and execute shell scripts and ELF binaries (e.g., `w.sh`, `c.sh`, `arm.urbotnetisass`). This suggests that attackers are attempting to deploy malware on compromised systems.
*   **Reconnaissance Activity:** A significant number of commands were focused on gathering system information, such as `uname -a`, `cat /proc/cpuinfo`, and `free -m`. This is a common tactic used by attackers to understand the environment they have compromised.
*   **Exploitation of Older Vulnerabilities:** The presence of CVEs from as early as 1999 suggests that attackers are still scanning for and attempting to exploit legacy vulnerabilities.
*   **Dominance of a Single Attacker IP:** The IP address 103.130.215.15 was responsible for a disproportionately large number of attacks, suggesting a targeted or automated attack campaign from this source.

This report highlights the ongoing and automated nature of attacks targeting common services like SSH and SMB. The variety of commands and CVEs observed indicates a diverse range of attack vectors being employed by malicious actors. Continued monitoring of these activities is crucial for understanding the evolving threat landscape.
