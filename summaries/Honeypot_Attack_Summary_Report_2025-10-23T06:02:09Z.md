Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T06:01:46Z
**Timeframe:** 2025-10-23T05:20:00Z to 2025-10-23T06:00:00Z
**Files Used:**
- agg_log_20251023T052001Z.json
- agg_log_20251023T054001Z.json
- agg_log_20251023T060001Z.json

**Executive Summary**
This report summarizes 24,211 events collected from the honeypot network. The majority of malicious traffic originated from a single IP address, 23.94.26.58, which was responsible for a large-scale SIP scanning campaign. Other significant activity includes SMB exploit attempts, SSH brute-forcing, and the execution of post-exploitation commands. The most frequently triggered signatures were related to SIP scanning and the DoublePulsar backdoor.

**Detailed Analysis**

**Attacks by Honeypot:**
- Suricata
- Sentrypeer
- Honeytrap
- Cowrie
- Ciscoasa
- Dionaea
- Mailoney
- H0neytr4p
- Tanner
- ConPot
- Honeyaml
- Redishoneypot
- Miniprint
- Ipphoney
- ElasticPot
- Adbhoney

**Top Attacking IPs:**
- 23.94.26.58
- 117.4.113.214
- 109.205.211.9
- 52.187.9.8
- 107.175.54.2
- 174.138.38.19
- 123.30.249.49
- 162.144.85.107
- 27.254.235.12
- 103.149.86.99

**Top Targeted Ports/Protocols:**
- 5060
- UDP/5060
- TCP/445
- 22
- 1081
- 1036
- 1090
- 1057
- 1071
- TCP/1080

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2018-10562
- CVE-2018-10561
- CVE-1999-0183

**Commands Attempted by Attackers:**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem
- uname -a
- whoami
- crontab -l
- Enter new UNIX password:

**Signatures Triggered:**
- ET SCAN Sipsak SIP scan
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- GPL INFO SOCKS Proxy attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake

**Users / Login Attempts (user/pass):**
- 345gs5662d34/345gs5662d34
- root/p@ssw0rd1234
- root/asd123.
- root/ccnp
- root/ccrcinf009
- root/cdi33172
- root/cdmi4231
- uploader/3245gs5662d34
- flame/flame
- kiara/kiara
- marta/marta123

**Files Uploaded/Downloaded:**
- gpon8080&ipv=0

**HTTP User-Agents:**
- (No user agents recorded in this period)

**SSH Clients and Servers:**
- (No specific SSH clients or servers recorded in this period)

**Top Attacker AS Organizations:**
- (No AS organizations recorded in this period)

**Key Observations and Anomalies**
- **High-Volume SIP Scanning:** A massive number of events (over 7,700) were attributed to the IP address 23.94.26.58, primarily targeting port 5060 for SIP scanning. This indicates a large-scale VoIP reconnaissance or attack campaign.
- **SMB Exploitation:** A significant number of alerts for "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" were triggered, suggesting attempts to exploit SMB vulnerabilities. This was mainly from the IP 117.4.113.214 targeting TCP port 445.
- **SSH Post-Exploitation:** Attackers were observed attempting to modify the `.ssh/authorized_keys` file to maintain persistent access to the compromised host. This is a common technique used to create a backdoor.
- **System Reconnaissance:** After gaining initial access, attackers frequently ran commands to gather information about the system, such as CPU details, memory usage, and user accounts.
