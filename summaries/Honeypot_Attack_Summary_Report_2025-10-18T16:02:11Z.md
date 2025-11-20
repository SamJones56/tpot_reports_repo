Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T16:01:28Z
**Timeframe:** 2025-10-18T15:20:01Z to 2025-10-18T16:00:01Z
**Files Used:**
* agg_log_20251018T152001Z.json
* agg_log_20251018T154001Z.json
* agg_log_20251018T160001Z.json

**Executive Summary**

This report summarizes 23,694 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie and Mailoney honeypots. The most targeted ports were 25 (SMTP) and 22 (SSH). A significant amount of activity was observed from the IP address 172.245.214.35, which was responsible for over a quarter of all observed events. The most common attack signature detected was related to the DoublePulsar backdoor.

**Detailed Analysis**

**Attacks by Honeypot**
* Cowrie: 9579
* Mailoney: 6587
* Suricata: 3309
* Honeytrap: 2319
* Ciscoasa: 1233
* Tanner: 328
* Sentrypeer: 154
* Dionaea: 91
* Adbhoney: 50
* H0neytr4p: 14
* Dicompot: 13
* ElasticPot: 13
* Honeyaml: 2
* ConPot: 2

**Top Attacking IPs**
* 172.245.214.35: 6577
* 194.50.16.73: 1646
* 167.250.66.24: 1484
* 176.9.111.156: 975
* 72.146.232.13: 903
* 161.132.48.14: 807
* 105.120.136.201: 541
* 89.117.150.149: 340
* 88.210.63.16: 321
* 103.189.235.176: 226

**Top Targeted Ports/Protocols**
* 25: 6587
* 22: 2057
* TCP/445: 2019
* 80: 323
* 5903: 223
* TCP/5900: 174
* 1975: 156
* 5060: 154
* 5901: 127
* 8333: 122

**Most Common CVEs**
* CVE-2022-27255
* CVE-2002-1149
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2024-3721
* CVE-2001-0414

**Commands Attempted by Attackers**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
* `cat /proc/cpuinfo | grep name | wc -l`
* `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `ls -lh $(which ls)`
* `which ls`
* `crontab -l`
* `w`
* `uname -m`
* `uname -a`
* `top`
* `uname`

**Signatures Triggered**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
* ET DROP Dshield Block Listed Source group 1
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET SCAN NMAP -sS window 1024
* ET HUNTING RDP Authentication Bypass Attempt
* ET SCAN Potential SSH Scan
* ET WEB_SERVER WEB-PHP phpinfo access
* ET INFO Reserved Internal IP Traffic
* ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28

**Users / Login Attempts**
* 345gs5662d34/345gs5662d34
* ftpuser/ftppassword
* root/123@Robert
* config/config2011
* root/3245gs5662d34
* ansible/Password1!
* root/!Q2w3e4r
* root/ubuntu@123
* root/277131821
* proxyuser/1111

**Files Uploaded/Downloaded**
* wget.sh;
* bot.html)
* w.sh;
* c.sh;
* get?src=cl1ckh0use
* k.php?a=x86_64,H8Q1E7OZO91FB11YH
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
* ie8.css?ver=1.0

**HTTP User-Agents**
* None observed.

**SSH Clients**
* None observed.

**SSH Servers**
* None observed.

**Top Attacker AS Organizations**
* None observed.

**Key Observations and Anomalies**

* A large number of attacks are targeting port 25, suggesting a focus on exploiting email servers.
* The IP address 172.245.214.35 is a significant source of attack traffic, and warrants further investigation.
* The high number of "DoublePulsar Backdoor" signatures suggests that attackers are attempting to exploit systems with this known vulnerability.
* A variety of shell scripts were downloaded and executed, indicating attempts to install malware or establish persistence on the honeypots.
