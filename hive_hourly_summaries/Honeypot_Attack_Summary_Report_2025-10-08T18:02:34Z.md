Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T18:01:39Z
**Timeframe:** 2025-10-08T17:20:01Z to 2025-10-08T18:00:01Z
**Files Used:**
- agg_log_20251008T172001Z.json
- agg_log_20251008T174001Z.json
- agg_log_20251008T180001Z.json

### Executive Summary

This report summarizes 25,051 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Suricata, Cowrie, and Honeytrap honeypots. The most targeted services were SSH (port 22), SIP (port 5060), and SMB (port 445). A significant number of attacks originated from the IP address `116.205.121.146`, primarily targeting SOCKS proxies on TCP port 1080. Attackers were observed attempting to install SSH keys for persistence, download and execute malicious scripts, and exploit several vulnerabilities, with CVE-2022-27255 being the most common.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 8787
- Cowrie: 8983
- Honeytrap: 2275
- Dionaea: 1571
- Sentrypeer: 1227
- Ciscoasa: 1283
- H0neytr4p: 55
- Mailoney: 47
- Redishoneypot: 31
- ConPot: 23
- Adbhoney: 20
- ElasticPot: 20
- Tanner: 24
- Miniprint: 12
- Heralding: 27
- Ipphoney: 1

**Top Attacking IPs:**
- 116.205.121.146: 7725
- 23.94.26.58: 1694
- 103.75.54.141: 1529
- 165.232.105.167: 1027
- 178.128.41.154: 503
- 82.115.43.135: 243
- 180.76.96.235: 209
- 147.93.189.166: 337
- 103.27.36.4: 307
- 64.227.133.234: 253
- 197.243.14.52: 243
- 203.83.231.93: 302
- 146.190.93.207: 174
- 181.49.50.6: 114
- 159.223.183.233: 139
- 118.195.150.246: 134
- 3.144.44.57: 129
- 103.146.52.252: 149
- 103.189.235.134: 119
- 171.244.141.177: 114

**Top Targeted Ports/Protocols:**
- TCP/1080: 7729
- 445: 1530
- 5060: 1227
- 22: 1322
- UDP/5060: 588
- 5903: 165
- TCP/5900: 146
- 8333: 117
- 5901: 65
- TCP/22: 86
- 25: 49
- 6379: 28
- 10001: 22
- 5908: 41
- 5907: 33
- 5909: 33
- 9200: 20
- 443: 40
- 23: 21
- 8888: 13

**Most Common CVEs:**
- CVE-2022-27255: 42
- CVE-2002-0013, CVE-2002-0012: 8
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 3
- CVE-2021-44228: 2
- CVE-2024-40891: 1
- CVE-2019-11500: 1
- CVE-2021-3449: 1
- CVE-2016-20016: 1
- CVE-2023-26801: 1
- CVE-2005-4050: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 46
- `lockr -ia .ssh`: 46
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 46
- `cat /proc/cpuinfo | grep name | wc -l`: 43
- `Enter new UNIX password: `: 43
- `Enter new UNIX password:`: 43
- `crontab -l`: 44
- `w`: 44
- `uname -m`: 44
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 44
- `top`: 44
- `uname`: 44
- `uname -a`: 44
- `whoami`: 44
- `lscpu | grep Model`: 44
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 44
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 43
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 43
- `ls -lh $(which ls)`: 43
- `which ls`: 43

**Signatures Triggered:**
- GPL INFO SOCKS Proxy attempt (2100615): 3872
- ET INFO Python aiohttp User-Agent Observed Inbound (2064326): 3857
- ET SCAN Sipsak SIP scan (2008598): 537
- ET DROP Dshield Block Listed Source group 1 (2402000): 199
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41 (2400040): 148
- ET SCAN NMAP -sS window 1024 (2009582): 115
- ET SCAN Potential SSH Scan (2001219): 71
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255) (2038669): 42
- ET INFO Reserved Internal IP Traffic (2002752): 46
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 43
- ET INFO VNC Authentication Failure (2002920): 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 44 (2403343): 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 43 (2403342): 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 42 (2403341): 10
- ET INFO CURL User Agent (2002824): 9

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`: 42
- `vpn/vpn!`: 7
- `newuser/newuser`: 8
- `admin/admin!`: 7
- `support/aaaaaa`: 6
- `user2/user2!`: 5
- `supervisor/supervisor4`: 4
- `unknown/unknown3`: 4
- `user/userpass`: 4
- `pi/1234`: 4
- `root/R00T`: 6
- `root/590426`: 4
- `user2/123456789`: 4
- `elasticsearch/elasticsearch321`: 3
- `guest/guest21`: 3
- `amir/amir123123`: 3
- `soporte/123`: 3
- `jenkins/jenkins@2025`: 3
- `me/P@ssw0rd1`: 3
- `ftptest/P@ssw0rd@123`: 3
- `ftptest/3245gs5662d34`: 3
- `newuser/password@123`: 3
- `root/password1`: 3
- `user2/user2123`: 3
- `rustserver/P@ssw0rd1`: 3
- `david/daviddavid`: 3
- `/checkers`: 3
- `github/123`: 3
- `userbot/userbot`: 3
- `ubuntu/3245gs5662d34`: 3
- `github/1`: 3
- `test/test1234`: 3
- `daniel/daniel!`: 3
- `charan/charan123`: 3
- `vpn/vpn!@#`: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies

- **High Volume SOCKS Proxy Scan:** The IP address `116.205.121.146` was responsible for a large number of events targeting TCP port 1080, indicating a widespread scan for open SOCKS proxies.
- **Malware Download Attempts:** Attackers were observed using `wget` and `curl` to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from the IP `213.209.143.62`. This suggests an attempt to install malware on compromised systems.
- **SSH Key Persistence:** A common tactic observed was the attempt to add a new SSH public key to the `authorized_keys` file. This is a well-known technique for maintaining persistent access to a compromised machine.
- **System Information Gathering:** Attackers frequently ran commands to gather information about the system, such as CPU, memory, and disk space. This is often a precursor to more targeted attacks.
- **Exploitation of CVE-2022-27255:** This vulnerability in Realtek eCos RSDK/MSDK was the most frequently targeted CVE, indicating that it is still being actively exploited in the wild.

This concludes the Honeypot Attack Summary Report. Further analysis of the downloaded malicious files is recommended to understand the full scope of the threat.