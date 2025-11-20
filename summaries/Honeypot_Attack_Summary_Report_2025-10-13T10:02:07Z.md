Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T10:01:43Z
**Timeframe:** 2025-10-13T09:20:01Z to 2025-10-13T10:00:01Z
**Files Used:**
- agg_log_20251013T092001Z.json
- agg_log_20251013T094001Z.json
- agg_log_20251013T100001Z.json

### Executive Summary
This report summarizes data from three honeypot log files, totaling 25,570 observed events. The most active honeypots were Honeytrap and Cowrie, which together accounted for the vast majority of interactions. A single IP address, 45.234.176.18, was responsible for a significant portion of the attack volume. Attackers predominantly targeted SSH (port 22) and SIP (port 5060) services. A variety of CVEs were targeted, and attackers attempted to run reconnaissance and system manipulation commands, including efforts to install malicious SSH keys.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 10,294
- Cowrie: 10,144
- Ciscoasa: 1,810
- Suricata: 1,392
- Mailoney: 840
- Sentrypeer: 763
- Dionaea: 75
- H0neytr4p: 56
- Tanner: 49
- ConPot: 40
- Honeyaml: 37
- Adbhoney: 23
- ElasticPot: 16
- Dicompot: 15
- Redishoneypot: 18
- Wordpot: 2
- Heralding: 3
- Miniprint: 3

**Top Attacking IPs:**
- 45.234.176.18: 9,532
- 134.199.206.85: 991
- 86.54.42.238: 820
- 137.184.97.100: 327
- 179.63.5.23: 326
- 38.43.130.70: 437
- 185.141.132.26: 454
- 103.4.92.103: 361
- 119.53.130.199: 316
- 95.211.195.196: 213
- 45.61.187.30: 281
- 172.174.5.146: 283

**Top Targeted Ports/Protocols:**
- 22 (SSH): 1,194
- 25 (SMTP): 840
- 5060 (SIP): 763
- 2323: 100
- 443 (HTTPS): 52
- 80 (HTTP): 65
- 445 (SMB): 18
- 3306 (MySQL): 21

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2006-2369
- CVE-2018-10562
- CVE-2018-10561
- CVE-2013-7471
- CVE-1999-0183

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && ...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | ...`
- `uname -a`
- `whoami`
- `crontab -l`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP (various groups)
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Potential SSH Scan

**Users / Login Attempts (user/password):**
- 345gs5662d34/345gs5662d34
- debian/debian2000
- root/3245gs5662d34
- support/222222
- operator/operator2013
- vpn/vpnpass
- admin1234/admin1234
- ftpuser/ftppassword

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were recorded.

**Top Attacker AS Organizations:**
- No attacker AS organization data was recorded.

### Key Observations and Anomalies
- **High Volume from a Single IP:** The IP address 45.234.176.18 was exceptionally active, indicating a targeted or persistent campaign from a single source.
- **Credential Stuffing:** A wide variety of common and default credentials were used, typical of automated brute-force attacks. The username/password `345gs5662d34/345gs5662d34` was the most frequently attempted.
- **Automated Reconnaissance:** The commands executed post-login are consistent with automated scripts gathering basic system information (CPU, memory, OS version) before likely deploying further malware.
- **Malware Delivery:** The attempted downloads of files like `arm.urbotnetisass` point to attempts to deploy IoT botnet malware, designed for various architectures (ARM, MIPS, x86).
- **SSH Key Manipulation:** A common pattern observed was the attempt to delete the existing `.ssh` directory and install a new authorized key, a clear persistence mechanism.
