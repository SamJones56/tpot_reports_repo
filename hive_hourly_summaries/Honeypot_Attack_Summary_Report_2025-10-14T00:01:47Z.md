
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T00:01:27Z
**Timeframe:** 2025-10-13 23:20:01Z to 2025-10-14 00:00:02Z
**Files Used:**
- agg_log_20251013T232001Z.json
- agg_log_20251013T234001Z.json
- agg_log_20251014T000002Z.json

## Executive Summary

This report summarizes 17,487 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Sentrypeer, Redishoneypot, and Dionaea. The most frequent attacks originated from IP address 8.222.207.98, and the most targeted port was 5060 (SIP). A variety of CVEs were observed, with CVE-2005-4050 being the most common. Attackers attempted numerous commands, many of which appear to be related to establishing remote access and gathering system information.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 8284
- **Sentrypeer:** 3176
- **Redishoneypot:** 2004
- **Dionaea:** 1543
- **Suricata:** 1338
- **Honeytrap:** 750
- **ssh-rsa:** 134
- **Adbhoney:** 68
- **Mailoney:** 67
- **Tanner:** 52
- **Miniprint:** 32
- **H0neytr4p:** 25
- **Honeyaml:** 6
- **ConPot:** 3
- **ElasticPot:** 3
- **Ciscoasa:** 2

### Top Attacking IPs

- 8.222.207.98: 2632
- 143.44.164.239: 1498
- 134.209.54.142: 1243
- 185.243.5.146: 1148
- 185.243.5.148: 731
- 45.236.188.4: 735
- 196.189.155.74: 587
- 172.86.95.115: 422
- 172.86.95.98: 395
- 172.245.92.249: 318
- 62.141.43.183: 322
- 112.66.129.180: 229

### Top Targeted Ports/Protocols

- 5060: 3176
- 6379: 2004
- 445: 1498
- 22: 1276
- 25: 67
- 5555: 37
- 80: 51
- 23: 38
- UDP/5060: 85
- TCP/22: 68
- UDP/161: 48
- 9100: 32
- 443: 25

### Most Common CVEs

- CVE-2005-4050: 58
- CVE-2002-0013 CVE-2002-0012: 35
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 20
- CVE-2006-0189: 5
- CVE-2022-27255 CVE-2022-27255: 5
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2002-1149: 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
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
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `Enter new UNIX password:`
- `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 364
- 2402000: 364
- ET SCAN NMAP -sS window 1024: 154
- 2009582: 154
- ET VOIP MultiTech SIP UDP Overflow: 58
- 2003237: 58
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 53
- 2001219: 53

### Users / Login Attempts

- root/: 134
- 345gs5662d34/345gs5662d34: 28
- root/Qaz123qaz: 14
- root/Password@2025: 16
- ubnt/8, ubnt/666666: 9

### Files Uploaded/Downloaded

- json: 3
- icanhazip.com: 2
- soap-envelope: 1
- addressing: 1
- discovery: 1
- devprof: 1
- soap:Envelope>: 1
- &currentsetting.htm=1: 1
- applebot): 1

### HTTP User-Agents
- No user agents were recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in the logs.

### Top Attacker AS Organizations
- No specific attacker AS organizations were identified in the logs.

## Key Observations and Anomalies

- **Repetitive SSH commands:** Attackers are consistently attempting to modify SSH authorized_keys to gain persistent access. The use of `chattr` and `lockr` suggests an attempt to make their modifications immutable.
- **Information Gathering:** A significant portion of the commands are focused on gathering system information, such as CPU, memory, and disk space.
- **Malware download attempts:** The "interesting" commands show numerous attempts to download and execute files from remote servers, a common tactic for deploying malware or botnet clients. The use of `nohup` and redirection indicates attempts to run these processes in the background and detached from the current session.
- **SIP and Redis Scanning:** The high number of events on ports 5060 (SIP) and 6379 (Redis) indicates widespread scanning for vulnerabilities in VoIP and database services.
