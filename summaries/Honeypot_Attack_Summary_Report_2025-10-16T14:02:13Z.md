# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T14:01:29Z
**Timeframe:** 2025-10-16T13:20:01Z to 2025-10-16T14:01:29Z

**Log Files Used:**
- `agg_log_20251016T132001Z.json`
- `agg_log_20251016T134001Z.json`
- `agg_log_20251016T140001Z.json`

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing 28,686 events from three log files. The majority of attacks targeted the Cowrie, Heralding, and Suricata honeypots. The most prominent attacker IP was `45.134.26.47`, responsible for a significant portion of the traffic. VNC (port 5900) and SMB (port 445) were the most targeted services. Several CVEs were detected, with CVE-2005-4050 being the most frequent. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access by adding SSH keys.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7284
- Heralding: 5733
- Suricata: 5359
- Honeytrap: 3064
- Sentrypeer: 2377
- Dionaea: 2010
- Ciscoasa: 1439
- Mailoney: 868
- Wordpot: 230
- Tanner: 89
- Redishoneypot: 63
- Miniprint: 47
- ConPot: 51
- ElasticPot: 21
- Dicompot: 13
- H0neytr4p: 20
- Adbhoney: 8
- Ipphoney: 3
- Honeyaml: 7

### Top Attacking IPs
- 45.134.26.47: 5719
- 137.97.230.174: 1302
- 47.97.127.96: 1239
- 136.158.48.123: 941
- 45.171.150.123: 916
- 86.54.42.238: 822
- 177.44.221.148: 708
- 10.140.0.3: 1678
- 23.94.26.58: 727
- 107.155.93.174: 671
- 185.243.5.158: 441
- 172.86.95.115: 446
- 172.86.95.98: 420
- 43.160.204.100: 374
- 134.199.199.162: 431

### Top Targeted Ports/Protocols
- vnc/5900: 5733
- TCP/445: 2009
- 445: 1966
- 5060: 2377
- 22: 1123
- 25: 855
- 80: 309
- TCP/5900: 315
- 5903: 200
- 6379: 49
- 23: 79
- 9100: 47
- 5901: 98
- 8333: 86
- 5905: 67
- 5904: 66

### Most Common CVEs
- CVE-2021-3449 CVE-2021-3449: 8
- CVE-2002-1149: 5
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2001-0414: 1
- CVE-2005-4050: 43

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 30
- `lockr -ia .ssh`: 30
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 29
- `top`: 29
- `uname`: 29
- `uname -a`: 29
- `whoami`: 28
- `lscpu | grep Model`: 28
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 28
- `cat /proc/cpuinfo | grep name | wc -l`: 28
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 28
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 28
- `ls -lh $(which ls)`: 28
- `which ls`: 28
- `crontab -l`: 28
- `w`: 28
- `uname -m`: 28
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 28

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2003
- 2024766: 2003
- ET INFO VNC Authentication Failure: 1693
- 2002920: 1693
- ET DROP Dshield Block Listed Source group 1: 508
- 2402000: 508
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 183
- 2400041: 183
- ET SCAN NMAP -sS window 1024: 150
- 2009582: 150
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 131
- 2400040: 131

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 30
- root/Qaz123qaz: 18
- root/QWE123!@#qwe: 17
- root/3245gs5662d34: 15
- root/123@@@: 15
- ftpuser/ftppassword: 11
- nobody/123123123: 6
- centos/centos2015: 6
- default/default2006: 6
- test/9999: 6
- blank/blank2025: 6

### Files Uploaded/Downloaded
- None observed in the logs.

### HTTP User-Agents
- None observed in the logs.

### SSH Clients and Servers
- No specific SSH client or server software versions were logged.

### Top Attacker AS Organizations
- No AS organization data was available in the logs.

## Key Observations and Anomalies

- **High-Volume Scanners:** The IP address `45.134.26.47` was extremely active, consistently scanning for VNC servers across all three time windows. This indicates a targeted, large-scale scanning operation.
- **Persistent SSH Intrusion Attempts:** The repeated use of commands to add an SSH key to `authorized_keys` suggests a coordinated campaign to gain persistent access to compromised systems.
- **DoublePulsar Activity:** The frequent triggering of the "DoublePulsar Backdoor" signature indicates that attackers are still attempting to use exploits associated with the Shadow Brokers leak.
- **Credential Stuffing:** A wide variety of common and default credentials were attempted, showing that brute-force and credential stuffing remain popular attack vectors.
- **Reconnaissance Commands:** The prevalence of commands like `uname`, `lscpu`, and `free -m` are clear indicators of attackers performing reconnaissance to understand the environment of the systems they believe they have compromised.
