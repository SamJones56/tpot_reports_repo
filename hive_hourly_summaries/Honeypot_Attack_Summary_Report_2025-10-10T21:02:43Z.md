# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T21:01:29Z
**Timeframe:** 2025-10-10T20:20:01Z to 2025-10-10T21:00:01Z
**Files Used:**
- agg_log_20251010T202001Z.json
- agg_log_20251010T204001Z.json
- agg_log_20251010T210001Z.json

## Executive Summary

This report summarizes 19,485 attacks recorded by the T-Pot honeypot network over a 40-minute period. The majority of attacks were SSH brute-force attempts, with significant activity also observed on ports related to SMTP and SMB. A wide range of reconnaissance and exploitation techniques were observed, including the attempted download and execution of malicious scripts.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 9305
- **Honeytrap:** 3076
- **Suricata:** 2200
- **Ciscoasa:** 1750
- **Dionaea:** 1719
- **Mailoney:** 907
- **H0neytr4p:** 189
- **Sentrypeer:** 123
- **Heralding:** 78
- **Tanner:** 64
- **Honeyaml:** 22
- **Redishoneypot:** 15
- **ConPot:** 11
- **Dicompot:** 9
- **Adbhoney:** 9
- **ElasticPot:** 4
- **ssh-rsa:** 4

### Top Attacking IPs

1.  193.37.71.190
2.  50.6.225.98
3.  213.149.166.133
4.  176.65.141.117
5.  165.227.174.138
6.  167.250.224.25
7.  88.210.63.16
8.  52.226.128.119
9.  165.154.12.20
10. 104.168.56.59
11. 203.161.56.203
12. 154.198.162.75
13. 119.207.254.77
14. 23.227.147.163
15. 57.129.61.16
16. 197.199.224.52
17. 79.61.112.234
18. 190.181.27.27
19. 172.187.216.162
20. 195.178.110.199

### Top Targeted Ports/Protocols

1.  22
2.  25
3.  445
4.  TCP/21
5.  443
6.  5903
7.  21
8.  5060
9.  5908
10. 5909
11. vnc/5900
12. 5901
13. 80
14. TCP/22
15. 5907
16. UDP/5060
17. 27018
18. 5984
19. 2525
20. 51003

### Most Common CVEs

- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2021-35394 CVE-2021-35394
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2016-20016 CVE-2016-20016
- CVE-1999-0183

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`
- `uname -s -v -n -r -m`

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1** (2402000)
- **ET SCAN MS Terminal Server Traffic on Non-standard Port** (2023753)
- **ET SCAN NMAP -sS window 1024** (2009582)
- **ET HUNTING RDP Authentication Bypass Attempt** (2034857)
- **ET FTP FTP PWD command attempt without login** (2010735)
- **ET FTP FTP CWD command attempt without login** (2010731)
- **ET INFO VNC Authentication Failure** (2002920)
- **ET INFO Reserved Internal IP Traffic** (2002752)
- **ET VOIP MultiTech SIP UDP Overflow** (2003237)
- **ET SCAN Potential SSH Scan** (2001219)

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/LeitboGi0ro
- ali/ali!
- Test/P@ssw0rd
- admin/admin13
- botuser/123botuser
- User/1234
- support/123
- adm/adm
- root/welc0me
- lab/lab@
- debian/1234567
- debian/3245gs5662d34
- support/password321
- sh/cd /tmp...
- support/Support12
- myuser/myuser1234
- myuser/3245gs5662d34

### Files Uploaded/Downloaded

- sh
- mpsl;
- w.sh;
- c.sh;

### HTTP User-Agents

- None observed.

### SSH Clients and Servers

- None observed.

### Top Attacker AS Organizations

- None observed.

## Key Observations and Anomalies

- A significant number of commands are reconnaissance-focused, suggesting automated scripts are being used to gather system information before attempting further exploitation.
- One of the login attempts included a command to download and execute shell scripts from a remote server, indicating a malware infection attempt.
- Several commands attempted to add an SSH key to the `authorized_keys` file, a common technique for establishing persistence on a compromised system.
- The download of shell scripts such as `w.sh` and `c.sh` was observed, which are likely malicious payloads.
