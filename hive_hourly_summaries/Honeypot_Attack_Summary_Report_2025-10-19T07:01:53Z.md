
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T07:01:24Z
**Timeframe:** 2025-10-19T06:20:01Z to 2025-10-19T07:00:01Z

**Files Used:**
- agg_log_20251019T062001Z.json
- agg_log_20251019T064001Z.json
- agg_log_20251019T070001Z.json

## Executive Summary

This report summarizes 29,714 events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie, Suricata, and Heralding honeypots. The most prominent attack vector was scanning and exploitation of TCP/445 (SMB) and VNC services. A significant number of brute-force attempts were observed against SSH and VNC. The most common CVEs exploited were related to VoIP and older SMB vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 8465
- **Suricata:** 9028
- **Heralding:** 4380
- **Honeytrap:** 5113
- **Sentrypeer:** 1673
- **Ciscoasa:** 880
- **Dionaea:** 94
- **Tanner:** 80
- **ConPot:** 27
- **H0neytr4p:** 22
- **Mailoney:** 24
- **ElasticPot:** 5
- **Honeyaml:** 4
- **Miniprint:** 12
- **Redishoneypot:** 3
- **Wordpot:** 1
- **Dicompot:** 2
- **Adbhoney:** 1

### Top Attacking IPs

- 185.243.96.105: 4110
- 113.193.26.150: 1332
- 45.140.17.52: 1380
- 117.43.97.191: 1324
- 154.242.105.207: 1300
- 194.50.16.73: 1473
- 38.242.213.182: 1227
- 72.146.232.13: 990
- 198.23.190.58: 976
- 23.94.26.58: 948
- 213.230.91.251: 943
- 45.133.5.110: 652
- 66.116.196.243: 513
- 104.198.246.170: 544
- 198.12.68.114: 685
- 89.23.116.82: 386
- 45.249.245.22: 325
- 152.53.197.136: 365
- 161.132.48.14: 303
- 138.124.117.159: 277

### Top Targeted Ports/Protocols

- TCP/445: 4912
- vnc/5900: 4110
- 22: 1613
- 5060: 1673
- UDP/5060: 1124
- 7070: 938
- 5038: 941
- 5903: 182
- 80: 83
- TCP/22: 83
- 8333: 107
- 5901: 90
- TCP/1433: 30
- 445: 22
- 5904: 61
- 5905: 61
- 2323: 18
- TCP/443: 16
- 443: 14
- 25: 12

### Most Common CVEs

- CVE-2005-4050: 1117
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2001-0414: 1
- CVE-1999-0183: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2025-3987 CVE-2025-3987: 1

### Commands Attempted by Attackers

- uname -a: 32
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 31
- lockr -ia .ssh: 31
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 31
- cat /proc/cpuinfo | grep name | wc -l: 31
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 31
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 31
- ls -lh $(which ls): 31
- which ls: 31
- crontab -l: 30
- w: 30
- uname -m: 30
- cat /proc/cpuinfo | grep model | grep name | wc -l: 31
- top: 31
- uname: 31
- whoami: 31
- lscpu | grep Model: 31
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 31
- Enter new UNIX password: : 24
- Enter new UNIX password:": 21
- cat /proc/uptime 2 > /dev/null | cut -d. -f1: 6
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh: 1
- cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps\n: 1
- curl2: 1

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 4907
- 2024766: 4907
- ET VOIP MultiTech SIP UDP Overflow: 1117
- 2003237: 1117
- ET DROP Dshield Block Listed Source group 1: 344
- 2402000: 344
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1044
- 2023753: 1044
- ET SCAN NMAP -sS window 1024: 142
- 2009582: 142
- ET HUNTING RDP Authentication Bypass Attempt: 503
- 2034857: 503
- ET SCAN Potential SSH Scan: 75
- 2001219: 75
- ET INFO Reserved Internal IP Traffic: 50
- 2002752: 50
- ET SCAN Suspicious inbound to MSSQL port 1433: 15
- 2010935: 15
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 19
- 2403345: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 10
- 2403343: 10
- GPL INFO SOCKS Proxy attempt: 274
- 2100615: 274
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 16
- 2403342: 16

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 31
- /passw0rd: 18
- /Passw0rd: 17
- /1q2w3e4r: 16
- centos/7: 6
- /qwertyui: 8
- admin/admin2004: 4
- zone/123: 4
- zone/3245gs5662d34: 4
- ftpuser/ftppassword: 7
- root/4gbu2ine22: 4
- root/123@Robert: 8
- root/3245gs5662d34: 4
- debian/1111: 4
- dev/dev: 3
- lu/123: 3
- ftpuser/ftpuser123: 5
- root/abc@2023: 3
- devel/devel123: 5
- ubuntu/admin123: 3
- penis/123: 4
- root/4lc4ch14: 4
- gaurav/gaurav@123: 4
- nobody/55555: 4
- erpnext/123: 3
- /1234qwer: 6
- factorio/factorio: 3
- filippo/filippo: 3
- guest/guest1: 3
- root/Vv123456: 2
- /qwer1234: 2
- blank/123abc: 2
- blank/2: 6
- support/654321: 6
- nobody/nobody77: 6
- root/4M11F2014: 4
- root/1234: 4
- /1qaz2wsx: 3
- root/1234567890: 3
- /asdf1234: 3
- root/123: 3
- root/root123: 3
- root/4ng3l1c4: 3
- root/12345: 3
- root/123456789: 3
- integration/123: 2

### Files Uploaded/Downloaded

- gpon8080&ipv=0: 4
- sh: 90
- 129.212.146.61: 1
- wlwps.htm: 1

### HTTP User-Agents

- None Observed

### SSH Clients and Servers

- None Observed

### Top Attacker AS Organizations

- None Observed

## Key Observations and Anomalies

- A large number of commands executed by attackers are related to reconnaissance and establishing persistence, such as gathering system information and adding SSH keys.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was seen across all three log files, indicating a consistent and automated attack campaign.
- The presence of the "mdrfckr" comment in the SSH key is a notable signature of this particular attacker or botnet.
- The high volume of SMB traffic, specifically triggering the "DoublePulsar" signature, suggests ongoing attempts to exploit older Windows vulnerabilities.
- There is a diverse range of login attempts with various usernames and passwords, typical of brute-force attacks.
- The command `curl2` is anomalous and could indicate a custom or modified version of the `curl` tool.
- The filenames `gpon8080&ipv=0` and `wlwps.htm` suggest attacks targeting specific web vulnerabilities or router models.
