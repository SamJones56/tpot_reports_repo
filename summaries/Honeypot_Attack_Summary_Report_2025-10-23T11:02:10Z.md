Honeypot Attack Summary Report

Report generated on 2025-10-23T11:01:40Z, summarizing data from the last hour.
Files used to generate this report:
- agg_log_20251023T102001Z.json
- agg_log_20251023T104001Z.json
- agg_log_20251023T110001Z.json

Executive Summary
This report summarizes 19,743 events collected from the honeypot network. The majority of attacks were captured by the Honeytrap, Cowrie, and Suricata honeypots. A significant number of attacks originated from the IP address 109.205.211.9. The most targeted ports were 445, 5060, and 22. Multiple CVEs were detected, with CVE-2002-0013, CVE-2002-0012, and CVE-2001-0414 being the most common. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access.

Detailed Analysis

Attacks by honeypot:
- Honeytrap: 7150
- Cowrie: 5038
- Suricata: 3655
- Ciscoasa: 1729
- Dionaea: 1000
- Sentrypeer: 842
- Tanner: 126
- Redishoneypot: 57
- Mailoney: 40
- ElasticPot: 39
- H0neytr4p: 23
- Miniprint: 15
- ConPot: 10
- Adbhoney: 9
- Honeyaml: 8
- ssh-rsa: 2

Top attacking IPs:
- 109.205.211.9: 2345
- 5.39.250.130: 975
- 103.160.232.131: 941
- 157.245.67.217: 475
- 128.199.168.119: 346
- 103.124.100.181: 321
- 46.188.119.26: 302
- 107.170.36.5: 250
- 185.243.5.146: 248
- 45.227.254.6: 160
- 201.249.192.30: 110

Top targeted ports/protocols:
- 445: 943
- 5060: 842
- 22: 815
- 2051: 142
- 5903: 131
- 80: 119
- 5901: 114

Most common CVEs:
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2001-0414: 6
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

Commands attempted by attackers:
- uname -a: 20
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 18
- lockr -ia .ssh: 18
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 18
- cat /proc/cpuinfo | grep name | wc -l: 18
- Enter new UNIX password: : 13
- Enter new UNIX password:: 13
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 18
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 18
- ls -lh $(which ls): 18
- which ls: 18
- crontab -l: 18
- w: 18
- uname -m: 18
- top: 18
- whoami: 18
- lscpu | grep Model: 18

Signatures triggered:
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1620
- 2023753: 1620
- ET HUNTING RDP Authentication Bypass Attempt: 784
- 2034857: 784
- ET DROP Dshield Block Listed Source group 1: 424
- 2402000: 424
- ET SCAN NMAP -sS window 1024: 159
- 2009582: 159
- ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake: 57
- 2010908: 57
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58

Users / login attempts:
- 345gs5662d34/345gs5662d34: 16
- root/Chino9999: 4
- root/choo3ieT: 4
- root/christin: 4
- root/christinAAA5: 4
- root/cicpkdx0: 4
- root/cin2mas4229..: 4
- root/3245gs5662d34: 3
- nmt/1234: 3
- nmt/3245gs5662d34: 3
- root/servidor: 3
- root/chpto325: 3
- root/fan123456: 3
- root/43211234: 3
- root/Cinda111...: 3

Files uploaded/downloaded:
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass;: 2
- mipsel.urbotnetisass: 2

HTTP User-Agents:
- No user agents were logged in this period.

SSH clients and servers:
- No specific SSH clients or servers were logged in this period.

Top attacker AS organizations:
- No AS organizations were logged in this period.

Key Observations and Anomalies
- The attacker at 109.205.211.9 was particularly persistent, generating a large volume of traffic across multiple honeypots and protocols.
- A series of commands were consistently executed in sequence, suggesting automated scripting. These scripts attempted to gather system information and install a persistent SSH key.
- The `urbotnetisass` malware was downloaded multiple times, indicating a coordinated campaign targeting IoT devices.
- The high number of scans for MS Terminal Server on non-standard ports, along with RDP authentication bypass attempts, suggests that attackers are actively searching for exposed remote desktop services.
- There is a notable amount of activity on port 445, which is associated with SMB. This could indicate attempts to exploit vulnerabilities like EternalBlue.