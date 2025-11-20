Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T02:01:29Z
**Timeframe:** 2025-10-13T01:20:01Z to 2025-10-13T02:00:01Z
**Files Used:**
- agg_log_20251013T012001Z.json
- agg_log_20251013T014002Z.json
- agg_log_20251013T020001Z.json

### Executive Summary
This report summarizes 17,069 attacks recorded by honeypots over a 40-minute period. The most targeted services were SSH (Cowrie), various TCP/UDP services (Honeytrap), and SMB/CIFS (Suricata). The majority of attacks originated from IPs in Vietnam, China, and the United States. A significant number of attacks attempted to exploit known vulnerabilities, with CVE-2005-4050 being the most common. A number of shell commands were attempted, indicating efforts to profile and take control of the compromised systems.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4831
- Suricata: 3414
- Honeytrap: 3192
- Ciscoasa: 1903
- Dionaea: 1743
- Sentrypeer: 849
- Mailoney: 886
- H0neytr4p: 86
- ConPot: 33
- Tanner: 33
- Redishoneypot: 31
- ElasticPot: 21
- Honeyaml: 21
- Adbhoney: 11
- Dicompot: 7
- Heralding: 6
- Ipphoney: 2

**Top Attacking IPs:**
- 171.227.117.204: 1439
- 203.78.147.68: 1188
- 223.100.22.69: 851
- 86.54.42.238: 821
- 218.31.7.24: 463
- 115.240.221.28: 336
- 196.251.88.103: 257
- 172.86.95.98: 392
- 51.178.24.221: 263
- 62.141.43.183: 326
- 103.97.177.230: 333
- 209.141.47.6: 215
- 147.78.100.99: 225
- 156.236.31.46: 150

**Top Targeted Ports/Protocols:**
- 445 (SMB/CIFS): 2326+
- 5060 (SIP): 849
- 25 (SMTP): 886
- 22 (SSH): 744
- 21 (FTP): 332
- 5903 (VNC): 190
- 8333 (Bitcoin): 104
- 7443 (HTTPS): 56
- 3306 (MySQL): 68
- 5909 (VNC): 83

**Most Common CVEs:**
- CVE-2005-4050: 27
- CVE-2002-0013 CVE-2002-0012: 15
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2009-2765: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 11
- `lockr -ia .ssh`: 11
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 11
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 11
- `ls -lh $(which ls)`: 10
- `which ls`: 10
- `crontab -l`: 10
- `w`: 10
- `uname -m`: 10
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 10
- `top`: 10
- `uname`: 10
- `uname -a`: 11
- `whoami`: 11
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 9
- `cat /proc/cpuinfo | grep name | wc -l`: 9

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766): 1562
- ET DROP Dshield Block Listed Source group 1 (2402000): 545
- ET SCAN NMAP -sS window 1024 (2009582): 141
- ET FTP FTP PWD command attempt without login (2010735): 112
- ET FTP FTP CWD command attempt without login (2010731): 112
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 102
- ET INFO Reserved Internal IP Traffic (2002752): 60
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system (2008953): 29

**Users / Login Attempts:**
- cron/: 64
- root/netillo123: 7
- root/vicidial: 7
- root/SangomaDefaultPassword: 6
- root/Pa$$word@123: 6
- root/ph0n3v0xn0v43r4: 6
- root/askozia: 6
- root/192168200248: 6
- root/906768700!@#: 6
- root/1qaz@WSX3edc: 6
- support/7: 6
- 345gs5662d34/345gs5662d34: 6

**Files Uploaded/Downloaded:**
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- json: 1
- mpsl;: 1
- Mozi.m: 1

**HTTP User-Agents:**
- None observed in this timeframe.

**SSH Clients and Servers:**
- No specific client or server versions were logged in this timeframe.

**Top Attacker AS Organizations:**
- No AS organization data was available in the logs.

### Key Observations and Anomalies
- The high number of scans for port 445, combined with DoublePulsar detection, suggests continued automated exploitation of SMB vulnerabilities.
- The variety of commands executed post-login indicates attackers are attempting to profile the system for further exploitation or to deploy additional malware.
- The appearance of `Mozi.m` suggests IoT botnet activity.
- The use of commands to add an SSH key to `authorized_keys` is a common persistence mechanism.

This concludes the Honeypot Attack Summary Report.