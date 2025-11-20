
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T21:01:24Z
**Timeframe:** 2025-10-07T20:20:00Z to 2025-10-07T21:01:00Z
**Files Used:**
- agg_log_20251007T202001Z.json
- agg_log_20251007T204001Z.json
- agg_log_20251007T210001Z.json

## Executive Summary

This report summarizes 23,738 events collected from the honeypot network. The majority of attacks were detected by the Sentrypeer and Cowrie honeypots. A significant portion of the traffic originated from a small number of IP addresses, with a primary focus on ports related to VoIP (5060), SMB (445), and SSH (22). Several CVEs were targeted, most notably CVE-2021-44228 (Log4j). A large number of automated commands were executed, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Sentrypeer: 10166
- Cowrie: 6884
- Suricata: 2310
- Honeytrap: 1827
- Ciscoasa: 1152
- Mailoney: 877
- Dionaea: 207
- Tanner: 156
- Redishoneypot: 46
- ElasticPot: 43
- H0neytr4p: 29
- Dicompot: 16
- ConPot: 12
- Adbhoney: 9
- ssh-rsa: 2
- Honeyaml: 1
- Ipphoney: 1

### Top Attacking IPs
- 2.57.121.61
- 200.58.166.84
- 45.78.192.92
- 176.65.141.117
- 71.41.130.50
- 185.255.126.223
- 93.115.79.198
- 27.128.174.164
- 141.138.146.167
- 77.50.63.250

### Top Targeted Ports/Protocols
- 5060
- TCP/445
- 22
- 25
- 80
- 5910
- 8333
- 3306
- 3388
- 6379

### Most Common CVEs
- CVE-2021-44228 CVE-2021-44228
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0183

### Commands Attempted by Attackers
- uname -a
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET SCAN Suspicious inbound to MSSQL port 1433

### Users / Login Attempts
- appuser/
- 345gs5662d34/345gs5662d34
- sysadmin/sysadmin@1
- root/Qq123456
- admin/Admin@1234
- pi/pi
- operator/operator
- sysadmin/3245gs5662d34
- ubuntu/3245gs5662d34
- wordpress/123

### Files Uploaded/Downloaded
- sh
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- wget.sh;
- ns#
- sign_in
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png
- 172.20.254.127
- w.sh;
- c.sh;

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- **High Volume of Sentrypeer Events:** A large number of events were logged by the Sentrypeer honeypot, indicating widespread scanning activity related to VoIP services.
- **Repetitive Automated Commands:** The commands executed by attackers are highly repetitive and indicative of automated scripts. These scripts are primarily focused on reconnaissance and installing SSH keys for persistence.
- **DoublePulsar Backdoor:** The signature for the DoublePulsar backdoor was triggered a significant number of times, suggesting that attackers are still attempting to exploit this vulnerability.
- **Targeting of Common Services:** The most targeted ports (5060, 445, 22, 25, 80) are all well-known services that are commonly exposed to the internet, indicating that attackers are casting a wide net for vulnerable systems.
