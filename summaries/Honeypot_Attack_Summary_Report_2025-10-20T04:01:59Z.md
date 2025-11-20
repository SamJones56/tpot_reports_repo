Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T04:01:32Z
**Timeframe:** 2025-10-20T03:20:02Z to 2025-10-20T04:00:02Z
**Files Analyzed:**
- agg_log_20251020T032002Z.json
- agg_log_20251020T034001Z.json
- agg_log_20251020T040002Z.json

### Executive Summary
This report summarizes 9,722 events captured by the honeypot network. The majority of the activity was related to SSH brute force attempts and exploitation of SMB vulnerabilities. The most active honeypot was Cowrie, which recorded 4,983 events. A significant portion of the attacks originated from the IP address 103.179.214.3, which was responsible for 1,579 events, primarily targeting TCP port 445. Several CVEs were detected, with the most frequent being related to older vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4983
- Suricata: 2214
- Honeytrap: 1678
- Ciscoasa: 499
- Sentrypeer: 113
- Dionaea: 61
- H0neytr4p: 49
- ConPot: 32
- Tanner: 30
- Redishoneypot: 20
- Honeyaml: 20
- Mailoney: 9
- ElasticPot: 5
- Miniprint: 3
- ssh-rsa: 2
- Adbhoney: 2
- Ipphoney: 2

**Top Attacking IPs:**
- 103.179.214.3
- 72.146.232.13
- 46.238.32.247
- 165.232.88.113
- 205.185.126.121
- 45.61.187.220
- 64.227.174.243
- 160.25.81.58
- 197.44.15.210
- 138.204.127.54

**Top Targeted Ports/Protocols:**
- TCP/445
- 22
- 5060
- 8333
- 5904
- 5905
- TCP/22
- UDP/161
- TCP/1433

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2019-11500
- CVE-2021-35394
- CVE-2001-0414
- CVE-1999-0183

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- uname -a
- whoami

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- user01/Password01
- user01/3245gs5662d34
- deploy/123123
- admin/
- ansible/Password@123
- luke/luke123
- root/9e47snnLUBAl

**Files Uploaded/Downloaded:**
- all.sh
- ?format=json

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- The high number of events targeting TCP port 445 from a single IP address (103.179.214.3) suggests a targeted campaign to exploit the SMB vulnerability. The triggered signature "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" confirms this.
- The most common commands executed by attackers are reconnaissance commands to understand the system's architecture, along with attempts to add a malicious SSH key to the `authorized_keys` file for persistence.
- A wide variety of credentials were used in brute-force attacks, indicating the use of automated tools and common credential lists.
- The CVEs detected are relatively old, suggesting that attackers are targeting unpatched or legacy systems.
