Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T10:01:29Z
**Timeframe:** 2025-10-18T09:20:01Z to 2025-10-18T10:00:01Z
**Files Used:**
- agg_log_20251018T092001Z.json
- agg_log_20251018T094001Z.json
- agg_log_20251018T100001Z.json

### Executive Summary

This report summarizes 11,091 suspicious events recorded by honeypots over a 40-minute period. The primary attack vectors were SSH and SIP, with Cowrie and Honeytrap being the most frequently engaged honeypots. A significant number of attacks originated from the IP address 72.146.232.13. Attackers attempted to gain unauthorized access using common and default credentials and executed various commands to gather system information and establish persistence. Several CVEs were targeted, and network intrusion detection systems triggered multiple signatures, primarily related to blocklisted sources and scanning activity.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4339
- Honeytrap: 2494
- Suricata: 1292
- Ciscoasa: 1290
- Sentrypeer: 983
- Dionaea: 446
- Mailoney: 90
- Tanner: 52
- H0neytr4p: 39
- Heralding: 36
- Adbhoney: 15
- Honeyaml: 5
- ConPot: 3
- Redishoneypot: 3
- ElasticPot: 2
- Ipphoney: 1
- Wordpot: 1

**Top Attacking IPs:**
- 72.146.232.13
- 31.58.144.28
- 107.189.16.66
- 172.86.95.115
- 103.163.113.38
- 88.210.63.16
- 107.170.36.5
- 202.79.29.108
- 103.249.84.18
- 92.191.96.171
- 183.88.232.183
- 125.21.59.218
- 118.36.136.12
- 40.83.182.122
- 45.232.73.84
- 125.75.110.72
- 154.92.19.175
- 218.78.46.81
- 89.248.165.108
- 194.102.104.59

**Top Targeted Ports/Protocols:**
- 5060
- 22
- 445
- 5903
- 2083
- 5901
- 25
- 5904
- 5905
- 80
- TCP/22
- vnc/5900
- 5908
- 5907
- 5909
- 5902
- TCP/80
- 1433
- TCP/1433

**Most Common CVEs:**
- CVE-2001-0414
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2018-10562
- CVE-2018-10561
- CVE-2022-27255

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- blank/654321
- debian/123123
- centos/centos2005
- root/220415zero0
- root/adminHW
- sysop/123
- unknown/0000000
- test/6666666
- support/88
- config/33333
- test/987654321

**Files Uploaded/Downloaded:**
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- wget.sh;
- ?format=json
- w.sh;
- c.sh;
- gpon8080&ipv=0
- gpon80&ipv=0
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies

- The high volume of attacks in a short period suggests automated scanning and exploitation attempts.
- The commands executed indicate a focus on reconnaissance and establishing persistent access through SSH keys.
- The variety of honeypots triggered shows a broad spectrum of protocols and services being targeted.
- The repeated attempts to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`) and binaries (`.urbotnetisass`) from various IP addresses highlight the use of malware droppers.
- The targeting of CVEs, including older vulnerabilities, indicates that attackers are still attempting to exploit unpatched systems.
- The absence of HTTP User-Agents, SSH clients, and server software details suggests that these fields were not populated in the logs or that the attacks did not involve these vectors in a way that was logged.
- The IP address `72.146.232.13` was consistently active across all three log files, indicating a persistent attacker.

This concludes the Honeypot Attack Summary Report. Further analysis of the attacker IPs and the downloaded files is recommended.