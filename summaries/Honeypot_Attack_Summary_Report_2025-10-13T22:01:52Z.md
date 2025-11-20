# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T22:01:30Z
**Timeframe:** 2025-10-13T21:20:01Z to 2025-10-13T22:00:02Z
**Files Used:**
- agg_log_20251013T212001Z.json
- agg_log_20251013T214001Z.json
- agg_log_20251013T220002Z.json

## Executive Summary

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 19,497 attacks were recorded. The most targeted services were Sentrypeer (SIP), Cowrie (SSH), and Mailoney (SMTP). The majority of attacks originated from a small number of IP addresses, with `2.57.121.61` being the most prolific. Attackers attempted to exploit several vulnerabilities, with a focus on older CVEs. A variety of shell commands were executed, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Sentrypeer: 10721
- Cowrie: 5382
- Suricata: 1056
- Dionaea: 810
- Mailoney: 808
- Honeytrap: 569
- Tanner: 59
- Redishoneypot: 33
- Adbhoney: 16
- H0neytr4p: 25
- ConPot: 8
- ElasticPot: 3
- Wordpot: 1
- Ciscoasa: 8
- Honeyaml: 8

### Top Attacking IPs
- 2.57.121.61: 8239
- 165.227.174.138: 1068
- 185.243.5.146: 962
- 45.236.188.4: 662
- 86.54.42.238: 767
- 185.243.5.148: 576
- 50.6.5.235: 232
- 172.86.95.98: 322
- 172.86.95.115: 320
- 81.17.103.128: 352
- 62.141.43.183: 256
- 143.198.71.38: 182
- 61.12.84.15: 198
- 180.76.144.122: 132
- 103.176.78.240: 50
- 62.60.131.157: 42
- 14.103.173.90: 69

### Top Targeted Ports/Protocols
- 5060: 10721
- 22: 838
- 25: 800
- 445: 787
- 80: 60
- 6379: 30
- UDP/5060: 59
- TCP/22: 42
- 443: 23
- 23: 26
- 5555: 8
- 8291: 7
- 39999: 6
- 53413: 9
- 1024: 10
- 9300: 4
- 50000: 4
- 16993: 4

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
- CVE-2006-0189: 20
- CVE-2022-27255 CVE-2022-27255: 20
- CVE-2005-4050: 14
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 19
- lockr -ia .ssh: 19
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 19
- cat /proc/cpuinfo | grep name | wc -l: 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- ls -lh $(which ls): 19
- which ls: 19
- crontab -l: 19
- w: 19
- uname -m: 19
- top: 19
- uname: 19
- uname -a: 19
- whoami: 19
- lscpu | grep Model: 19
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 19
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 7
- uname -s -v -n -r -m: 2
- Enter new UNIX password: : 7

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 292
- 2402000: 292
- ET SCAN NMAP -sS window 1024: 126
- 2009582: 126
- ET INFO Reserved Internal IP Traffic: 48
- 2002752: 48
- ET SCAN Potential SSH Scan: 32
- 2001219: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 27
- 2403349: 27
- GPL SNMP request udp: 9
- 2101417: 9
- GPL SNMP public access udp: 6
- 2101411: 6

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 18
- root/Qaz123qaz: 8
- test/test44: 4
- root/3245gs5662d34: 11
- support/administrator: 6
- unknown/6666: 6
- root/Password@2025: 5
- ubnt/55555: 6
- test/passw0rd: 4
- root/KZDH451*#*451DAVOSEC: 4
- root/123@@@: 4
- root/KZDH504*#*504DAVOSEC: 4
- test/test2005: 4
- blank/8: 4

### Files Uploaded/Downloaded
- json: 4
- ohshit.sh;: 2
- ): 1
- &currentsetting.htm=1: 1

### HTTP User-Agents
- None observed.

### SSH Clients and Servers
- **Clients:** None observed.
- **Servers:** None observed.

### Top Attacker AS Organizations
- None observed.

## Key Observations and Anomalies

- The overwhelming majority of attacks were directed at port 5060 (SIP), indicating a large-scale, automated campaign targeting VoIP services.
- A single IP address, `2.57.121.61`, was responsible for a significant portion of the total attack volume.
- The commands executed by attackers suggest a common playbook for establishing persistence and gathering system information. The use of `chattr` to lock SSH files is a notable technique.
- The presence of the `ohshit.sh` filename in downloaded files suggests a potentially malicious script, warranting further investigation.
- The CVEs targeted are relatively old, suggesting that attackers are targeting unpatched or legacy systems.

This concludes the Honeypot Attack Summary Report.
