Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T18:01:31Z
**Timeframe:** 2025-10-10T17:20:01Z to 2025-10-10T18:00:01Z
**Log Files:**
- `agg_log_20251010T172001Z.json`
- `agg_log_20251010T174001Z.json`
- `agg_log_20251010T180001Z.json`

### Executive Summary

This report summarizes 21,813 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant portion of the activity originated from a small number of IP addresses, with a notable focus on ports 22 (SSH) and 25 (SMTP). Attackers attempted to gain unauthorized access using common and easily guessable credentials and executed post-breach commands to establish persistent access. Several security signatures were triggered, primarily related to scanning for MS Terminal Server, blocklisted IPs, and RDP authentication bypass attempts.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 12,954
- Honeytrap: 2,924
- Suricata: 2,168
- Ciscoasa: 1,768
- Mailoney: 850
- Dionaea: 457
- ElasticPot: 362
- Sentrypeer: 123
- Heralding: 64
- Tanner: 66
- ConPot: 19
- H0neytr4p: 20
- Adbhoney: 9
- Redishoneypot: 9
- Dicompot: 6
- Ipphoney: 8
- Honeyaml: 6

**Top Attacking IPs:**
- 46.32.178.62
- 176.65.141.117
- 167.250.224.25
- 85.172.189.189
- 188.164.195.81
- 103.176.78.149
- 154.83.15.123
- 27.112.79.123
- 1.238.106.229
- 103.250.11.235

**Top Targeted Ports/Protocols:**
- 22
- 25
- 9200
- 1111
- 5060
- 5903
- 8333
- 21
- 80
- vnc/5900

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2022-27255 CVE-2022-27255

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `which ls`
- `ls -lh $(which ls)`
- `crontab -l`

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET CINS Active Threat Intelligence Poor Reputation IP group 42

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/LeitboGi0ro
- root/nPSpP4PBW0
- nobody/pass
- admin/Abc123456
- git/gitpass
- dockeruser/3245gs5662d34
- test/Passw0rd
- test/Welcome1

**Files Uploaded/Downloaded:**
- w.sh;
- c.sh;

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No specific SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

### Key Observations and Anomalies

- **High-Volume SSH Attacks:** The dominance of the Cowrie honeypot highlights a significant and persistent threat from SSH-based attacks.
- **Credential Stuffing:** The variety of usernames and passwords suggests automated credential stuffing attacks are prevalent.
- **Post-Exploitation Activity:** The commands executed post-breach focus on establishing persistence by adding SSH keys to `authorized_keys`.
- **Targeted Scanning:** The triggered Suricata signatures indicate that attackers are actively scanning for vulnerable services, including RDP and MS Terminal Server, on non-standard ports.
- **Malware Delivery:** The downloaded files (`w.sh` and `c.sh`) are likely shell scripts intended to download and execute further malware payloads.
- **Concentrated Attack Sources:** A small number of IP addresses are responsible for a large percentage of the attack traffic, suggesting a coordinated campaign or a botnet.
