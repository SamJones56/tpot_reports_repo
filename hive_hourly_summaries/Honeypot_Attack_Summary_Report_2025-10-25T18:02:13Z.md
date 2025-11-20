Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T18:01:48Z
**Timeframe:** 2025-10-25T17:20:02Z to 2025-10-25T18:00:01Z
**Log Files:**
- agg_log_20251025T172002Z.json
- agg_log_20251025T174001Z.json
- agg_log_20251025T180001Z.json

### Executive Summary

This report summarizes 29,483 events recorded across the honeypot network. The majority of traffic originated from the Sentrypeer honeypot, indicating a high volume of reconnaissance and attacks targeting VOIP services, specifically on port 5060. The most prolific attacker IP was 107.174.226.42, responsible for over a third of all recorded events. A significant number of attacks were logged by the Cowrie honeypot, showing persistent attempts to compromise SSH servers using common usernames and passwords. Attackers were observed attempting to download and execute various malicious scripts and ELF binaries.

### Detailed Analysis

**Attacks by Honeypot:**
- Sentrypeer: 11,734
- Cowrie: 6,599
- Honeytrap: 4,607
- Suricata: 2,961
- Ciscoasa: 1,743
- Heralding: 1,416
- Dionaea: 130
- Mailoney: 102
- Adbhoney: 55
- Redishoneypot: 45
- ConPot: 29
- Tanner: 25
- H0neytr4p: 20
- Honeyaml: 10
- ElasticPot: 3
- Dicompot: 3
- Medpot: 1

**Top Attacking IPs:**
- 107.174.226.42: 11,569
- 80.94.95.238: 2,591
- 185.243.96.105: 1,410
- 20.2.136.52: 1,104
- 206.189.83.92: 686
- 167.71.65.227: 480
- 135.13.11.134: 258
- 79.116.78.241: 209
- 201.48.78.29: 266
- 156.236.75.209: 286
- 50.6.5.235: 288
- 193.24.211.28: 224
- 187.111.28.131: 233
- 117.50.55.96: 209

**Top Targeted Ports/Protocols:**
- 5060: 11,734
- 22: 1,045
- vnc/5900: 1,410
- 8333: 167
- 5903: 130
- 5901: 118
- 25: 102
- UDP/5060: 65
- TCP/22: 61
- 1433: 75
- 6379: 30

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2006-2369
- CVE-1999-0183
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2005-4050

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 25
- `lockr -ia .ssh`: 25
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 24
- `cat /proc/cpuinfo | grep name | wc -l`: 24
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 24
- `ls -lh $(which ls)`: 24
- `which ls`: 24
- `crontab -l`: 24
- `w`: 24
- `uname -m`: 24
- `top`: 24
- `uname`: 24
- `uname -a`: 24
- `whoami`: 24
- `lscpu | grep Model`: 24
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 24

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1380
- 2023753: 1380
- ET DROP Dshield Block Listed Source group 1: 391
- 2402000: 391
- ET SCAN NMAP -sS window 1024: 168
- 2009582: 168
- ET HUNTING RDP Authentication Bypass Attempt: 131
- 2034857: 131
- ET VOIP REGISTER Message Flood UDP: 58
- 2009699: 58
- ET INFO Reserved Internal IP Traffic: 55
- 2002752: 55

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`: 24
- `/1q2w3e4r`: 8
- `root/f7dvd`: 4
- `root/3245gs5662d34`: 7
- `root/f95HahCA0eAz84U7dV`: 4
- `/passw0rd`: 4
- `root/FA`: 4
- `root/fa5t3rvm`: 4
- `root/fairtone1`: 4

**Files Uploaded/Downloaded:**
- `wget.sh;`: 20
- `w.sh;`: 5
- `c.sh;`: 5
- `arm.urbotnetisass;`: 2
- `arm.urbotnetisass`: 2
- `arm5.urbotnetisass;`: 2
- `arm5.urbotnetisass`: 2
- `arm6.urbotnetisass;`: 2
- `arm6.urbotnetisass`: 2
- `arm7.urbotnetisass;`: 2
- `x86_32.urbotnetisass;`: 2
- `mips.urbotnetisass;`: 2
- `mipsel.urbotnetisass;`: 2

**HTTP User-Agents:**
- No HTTP user-agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were recorded.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies

- **VOIP Targeting:** The vast majority of observed events were directed at port 5060 (SIP), indicating widespread, automated scanning and exploitation attempts against VOIP infrastructure.
- **Automated SSH Attacks:** Commands executed on the Cowrie honeypot show a clear, automated sequence: attackers attempt to secure exclusive access by modifying SSH authorized_keys, conduct system reconnaissance (`uname`, `lscpu`), and then attempt to download further malware. The attempt to add a specific SSH key (`mdrfckr`) was seen repeatedly.
- **Malware Delivery:** Attackers consistently used `wget` and `curl` to download shell scripts (`w.sh`, `wget.sh`) and ELF binaries (`arm.urbotnetisass`, `mips.urbotnetisass`, etc.). This indicates attempts to deploy multi-architecture malware, likely for inclusion in a botnet.
- **Reconnaissance:** Suricata signatures for NMAP scans and RDP bypass attempts confirm that a significant portion of traffic is reconnaissance, with attackers probing for open ports and known vulnerabilities before launching targeted attacks.
