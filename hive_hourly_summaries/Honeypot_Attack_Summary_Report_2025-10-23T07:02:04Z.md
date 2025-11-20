
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T07:01:34Z
**Timeframe:** 2025-10-23T06:20:02Z to 2025-10-23T07:00:01Z
**Files Used:**
- agg_log_20251023T062002Z.json
- agg_log_20251023T064001Z.json
- agg_log_20251023T070001Z.json

## Executive Summary

This report summarizes honeypot activity over the last hour, based on logs from three separate intervals. A total of 22,061 attacks were recorded across various honeypots. The most targeted services were SMB (port 445) and SIP (port 5060). The majority of attacks were detected by the Suricata, Honeytrap, and Cowrie honeypots. A significant number of commands were attempted, primarily focused on reconnaissance and establishing persistent access. Multiple CVEs were targeted, with a focus on older vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot
- **Suricata:** 6957
- **Honeytrap:** 7132
- **Cowrie:** 3127
- **Dionaea:** 1838
- **Ciscoasa:** 1812
- **Sentrypeer:** 954
- **Tanner:** 84
- **Mailoney:** 52
- **Redishoneypot:** 51
- **Adbhoney:** 13
- **H0neytr4p:** 17
- **ConPot:** 10
- **Miniprint:** 6
- **Honeyaml:** 3
- **ElasticPot:** 2
- **Wordpot:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- 109.205.211.9
- 103.25.138.161
- 181.219.226.65
- 180.246.121.46
- 203.82.41.210
- 185.68.247.151
- 27.79.44.6
- 116.110.150.189
- 196.251.69.141
- 103.187.147.214

### Top Targeted Ports/Protocols
- 445
- TCP/445
- 5060
- 22
- 80
- 23
- 1099
- 1120
- 1106
- 1133

### Most Common CVEs
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- system
- shell
- cat /proc/uptime 2 > /dev/null | cut -d. -f1
- export PATH=...
- echo "root:k0WZr4H5ZPt2"|chpasswd|bash
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET MALWARE J-magic (nfsiod) Backdoor Magic Packet Inbound Request M5
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

### Users / Login Attempts
- root/celu12
- root/cempbx1
- 345gs5662d34/345gs5662d34
- root/center5870
- root/Centos
- root/centralino
- root/CENTRALVET
- admin/12345
- namrata/namrata
- techadmin/techadmin

### Files Uploaded/Downloaded
- sh: 6

### HTTP User-Agents
- No user agents recorded in this timeframe.

### SSH Clients and Servers
- No SSH clients or servers recorded in this timeframe.

### Top Attacker AS Organizations
- No AS organizations recorded in this timeframe.

## Key Observations and Anomalies

- A large number of commands are focused on disabling security features (`chattr -ia .ssh`), reconnaissance (`uname -a`, `cat /proc/cpuinfo`), and establishing persistent access by adding SSH keys to `authorized_keys`.
- The `DoublePulsar Backdoor` signature was triggered a significant number of times, indicating attempts to exploit the EternalBlue vulnerability.
- The most common login attempts use default or simple credentials, such as `root/celu12`, `admin/12345`, and `test/test`.
- A file named `sh` was uploaded 6 times, likely a shell script for further exploitation.
- No HTTP user agents, SSH clients/servers, or AS organization data was present in the logs for this period. This could be a gap in logging or an indication of the attack vectors used.
