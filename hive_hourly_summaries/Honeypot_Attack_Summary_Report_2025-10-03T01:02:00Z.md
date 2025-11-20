# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T01:01:33Z
**Timeframe:** 2025-10-03T00:20:01Z to 2025-10-03T01:00:01Z
**Files Used:**
- agg_log_20251003T002001Z.json
- agg_log_20251003T004001Z.json
- agg_log_20251003T010001Z.json

## Executive Summary
This report summarizes a total of 11,206 events captured by the honeypot network. The majority of attacks were detected by the Cowrie honeypot, with significant activity also observed on Ciscoasa, Mailoney, and Sentrypeer. The most frequent attacks originated from IP address 176.65.141.117. The primary targets were ports 25 (SMTP), 5060 (SIP), and 22 (SSH). A notable number of brute-force attempts and command injections were recorded, with attackers attempting to gain control of the system and establish persistent access by adding SSH keys.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 3651
- **Ciscoasa:** 2649
- **Mailoney:** 1668
- **Sentrypeer:** 1580
- **Suricata:** 1223
- **Honeytrap:** 202
- **Dionaea:** 67
- **H0neytr4p:** 48
- **Tanner:** 38
- **Redishoneypot:** 26
- **Heralding:** 19
- **Adbhoney:** 10
- **Honeyaml:** 9
- **ConPot:** 6
- **Dicompot:** 4
- **Miniprint:** 3
- **ElasticPot:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- 176.65.141.117
- 23.175.48.211
- 92.63.197.55
- 185.156.73.166
- 92.63.197.59
- 81.192.46.45
- 193.32.162.157
- 197.5.145.73
- 150.95.155.240
- 91.237.163.110
- 180.184.141.117
- 106.75.162.123
- 50.232.189.209
- 37.59.110.4
- 46.105.87.113
- 79.117.123.72
- 197.225.146.23
- 36.99.192.221
- 103.49.238.99

### Top Targeted Ports/Protocols
- 25
- 5060
- 22
- TCP/22
- 443
- 80
- TCP/1080
- 6379
- 1433
- postgresql/5432
- TCP/1433

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Potential SSH Scan
- 2001219

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`
- `root/nPSpP4PBW0`
- `test/zhbjETuyMffoL8F`
- `root/3245gs5662d34`
- `superadmin/admin123`

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents
- No user agents recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in the logs for this period.

### Top Attacker AS Organizations
- No attacker AS organizations were identified in the logs for this period.

## Key Observations and Anomalies
- A significant number of attacks are focused on compromising SSH servers, with attackers attempting to add their own SSH keys for persistent access.
- The high volume of traffic on ports 25 and 5060 indicates a focus on exploiting email and VoIP services.
- The presence of Nmap scans suggests that attackers are actively probing the network for open ports and services.
- The commands executed by attackers indicate an attempt to gather system information and disable security measures.
- CVEs related to older vulnerabilities are still being exploited, highlighting the importance of patching and updating systems.
