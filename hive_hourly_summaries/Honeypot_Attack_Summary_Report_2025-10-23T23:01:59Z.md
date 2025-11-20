# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T23:01:29Z
**Timeframe:** 2025-10-23T22:20:01Z to 2025-10-23T23:00:01Z
**Log Files:**
- `agg_log_20251023T222001Z.json`
- `agg_log_20251023T224002Z.json`
- `agg_log_20251023T230001Z.json`

## Executive Summary

This report summarizes 5,679 malicious activities recorded across multiple honeypots. The primary attack vectors observed were targeting Cisco ASA, generic TCP services (Honeytrap), and SSH (Cowrie). The most prominent attacker IP, `80.94.95.238`, was responsible for a significant portion of the traffic. A variety of reconnaissance, credential stuffing, and payload delivery commands were observed.

## Detailed Analysis

### Attacks by Honeypot

- **Ciscoasa:** 1826
- **Honeytrap:** 1552
- **Cowrie:** 1161
- **Suricata:** 813
- **Sentrypeer:** 201
- **ssh-rsa:** 30
- **Dionaea:** 20
- **Mailoney:** 17
- **Heralding:** 16
- **Redishoneypot:** 15
- **Tanner:** 12
- **H0neytr4p:** 8
- **Dicompot:** 3
- **Honeyaml:** 3
- **Medpot:** 2

### Top Attacking IPs

- 80.94.95.238
- 191.223.75.89
- 27.71.230.3
- 107.170.36.5
- 68.183.149.135
- 58.34.135.138
- 42.112.42.129
- 64.23.191.60
- 185.243.5.140
- 58.210.98.130

### Top Targeted Ports/Protocols

- 22
- 5060
- 2054
- 5905
- 5904
- 8333
- 5901
- 5902
- 5903
- TCP/80

### Most Common CVEs

- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500

### Commands Attempted by Attackers

- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `system`
- `shell`
- `q`
- `enable`
- `sh`
- `cat /proc/mounts; /bin/busybox LCUSW`
- `tftp; wget; /bin/busybox LCUSW`
- `rm .s; exit`

### Signatures Triggered

- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

### Users / Login Attempts

- undib/undib
- 345gs5662d34/345gs5662d34
- root/cvoice345
- root/00
- clipper/clipper
- root/reboot
- telecomadmin/admintelecom
- root/
- root/0000
- blas/blas123
- shogun/shogun
- postgres/postgres
- postgres/1234
- administrator/administrator
- manager/friend

### Files Uploaded/Downloaded

- None observed.

### HTTP User-Agents

- None observed.

### SSH Clients and Servers

- None observed.

### Top Attacker AS Organizations

- None observed.

## Key Observations and Anomalies

- A significant number of commands are focused on system enumeration (`uname`, `lscpu`, `df`) and attempting to establish persistent SSH access by modifying `authorized_keys`.
- The command sequence involving `tftp; wget; /bin/busybox LCUSW` suggests attempts to download and execute a payload from a remote server, a common tactic for malware infection.
- The variety of credentials used in brute-force attempts indicates automated attacks using common default or leaked password lists. The targeting of `postgres` accounts was noted in one of the log files.
- `80.94.95.238` is a highly active IP and warrants further investigation and potential blocking.
- The triggering of "ET SCAN MS Terminal Server Traffic on Non-standard Port" indicates widespread scanning for exposed RDP services on non-standard ports.
