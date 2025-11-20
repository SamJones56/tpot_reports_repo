## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T19:01:47Z
**Timeframe Covered:** Data from 2025-10-03T18:20:01Z to 2025-10-03T19:00:01Z
**Files Used to Generate Report:**
- agg_log_20251003T182001Z.json
- agg_log_20251003T184001Z.json
- agg_log_20251003T190001Z.json

### Executive Summary
This report summarizes 13,189 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. Attackers were observed attempting to gain access using common default credentials and executing post-breach commands, including downloading malware and adding SSH keys for persistence. The most frequent attacks originated from IP address 176.65.141.117.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6873
- Ciscoasa: 1932
- Mailoney: 1640
- Suricata: 1178
- Dionaea: 967
- Sentrypeer: 278
- Honeytrap: 143
- H0neytr4p: 58
- Adbhoney: 51
- Redishoneypot: 17
- Tanner: 19
- ConPot: 10
- Honeyaml: 12
- Dicompot: 4
- Miniprint: 3
- ElasticPot: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 176.65.141.117
- 213.149.166.133
- 207.180.229.239
- 185.121.0.25
- 122.147.148.236
- 192.227.128.4
- 138.248.168.20
- 200.195.181.178
- 103.189.234.198
- 103.253.21.190

**Top Targeted Ports/Protocols:**
- 25
- 445
- 22
- 5060
- 443
- 23
- 27017
- 6379
- 81
- 80

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 50

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/2glehe5t24th1issZs
- root/nPSpP4PBW0
- superadmin/admin123
- root/LeitboGi0ro
- test/zhbjETuyMffoL8F
- root/blackbird
- gits/gits
- titu/Ahgf3487@rtjhskl854hd47893@#a4nC

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations recorded in this period.

### Key Observations and Anomalies
- A significant number of commands are focused on reconnaissance within the compromised system (e.g., `uname -a`, `lscpu`, `cat /proc/cpuinfo`).
- A recurring pattern involves attackers attempting to add their own SSH public key to the `authorized_keys` file for persistent access.
- Attackers were observed downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`) and what appears to be the `urbotnetisass` malware for various architectures.
- There is a high volume of traffic from IPs on Dshield and Spamhaus blocklists, indicating that known malicious actors are actively scanning and attacking.
