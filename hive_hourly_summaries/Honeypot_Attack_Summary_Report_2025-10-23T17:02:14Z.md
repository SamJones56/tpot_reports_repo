Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T17:01:50Z
**Timeframe:** Approximately 6 minutes of data.
**Files Used:**
- agg_log_20251023T162001Z.json
- agg_log_20251023T164001Z.json
- agg_log_20251023T170001Z.json

**Executive Summary**

This report summarizes 14,769 events collected from the honeypot network. The majority of the traffic consisted of automated scanning and exploitation attempts. The most prominent activities were SMB exploitation attempts detected by Suricata, brute-force attacks against VNC and SSH services, and reconnaissance activities. A significant number of attacks originated from a small number of IP addresses, suggesting targeted efforts from these sources.

**Detailed Analysis**

***Attacks by Honeypot***
- Suricata: 4837
- Cowrie: 2706
- Heralding: 2425
- Honeytrap: 2008
- Ciscoasa: 1745
- Sentrypeer: 722
- Miniprint: 77
- Tanner: 71
- Dionaea: 64
- H0neytr4p: 28
- ElasticPot: 23
- Mailoney: 22
- Redishoneypot: 17
- ConPot: 13
- Adbhoney: 5
- Ipphoney: 3
- Dicompot: 3

***Top Attacking IPs***
- 185.243.96.105: 2504
- 10.140.0.3: 2426
- 170.155.12.7: 1427
- 157.245.67.247: 350
- 118.219.239.122: 287
- 172.245.92.249: 282
- 107.170.36.5: 253
- 185.243.5.146: 198
- 164.128.136.184: 189
- 117.48.216.168: 185
- 163.172.99.31: 162
- 202.143.111.139: 149
- 68.183.149.135: 111
- 185.243.5.140: 106
- 43.142.67.84: 105
- 186.235.28.11: 103
- 68.183.207.213: 94
- 121.227.31.13: 84
- 103.153.110.189: 81
- 103.217.145.120: 79

***Top Targeted Ports/Protocols***
- vnc/5900: 2425
- TCP/445: 1423
- 5060: 722
- 22: 406
- 5903: 133
- 5901: 122
- 31337: 56
- 5905: 79
- 5904: 78
- 9100: 77
- 8333: 76
- 80: 61

***Most Common CVEs***
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2024-4577
- CVE-2002-0953
- CVE-2019-11500
- CVE-2021-3449
- CVE-2021-41773
- CVE-2021-42013

***Commands Attempted by Attacker***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:

***Signatures Triggered***
- ET INFO VNC Authentication Failure: 2424
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1420
- ET DROP Dshield Block Listed Source group 1: 275
- ET SCAN NMAP -sS window 1024: 142
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 105

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- /1q2w3e4r
- /1qaz2wsx
- /passw0rd
- root/3245gs5662d34
- root/Colombia2029
- root/comcenter
- root/Comercipol2014
- root/compiled2014

***Files Uploaded/Downloaded***
- sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

***HTTP User-Agents***
- No HTTP User-Agents were observed in the logs.

***SSH Clients and Servers***
- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***
- No attacker AS organizations were identified in the logs.

**Key Observations and Anomalies**

- **DoublePulsar Activity:** A large number of events were related to the DoublePulsar backdoor, indicating attempts to exploit the SMB vulnerability (likely MS17-010). This activity was primarily observed from the IP address 170.155.12.7.
- **VNC Brute-Force:** The honeypot logs show a high number of VNC authentication failures, suggesting widespread and automated brute-force attacks against this service.
- **Malware Downloads:** The `adb` honeypot captured attempts to download and execute several variants of the `urbotnetisass` malware, a known botnet.
- **Reconnaissance:** Attackers frequently ran commands to gather system information, such as `uname -a`, `whoami`, `cat /proc/cpuinfo`, and `free -m`, which is a common precursor to more targeted attacks.
