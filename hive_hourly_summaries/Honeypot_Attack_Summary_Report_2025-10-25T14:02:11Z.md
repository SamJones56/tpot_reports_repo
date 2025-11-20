Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T14:01:44Z
**Timeframe:** 2025-10-25T13:20:01Z to 2025-10-25T14:00:01Z
**Files Used:** agg_log_20251025T132001Z.json, agg_log_20251025T134001Z.json, agg_log_20251025T140001Z.json

**Executive Summary**

This report summarizes 18,322 attacks recorded by honeypots over a 40-minute interval. The most targeted services were VNC (port 5900), SMB (port 445), and SSH (port 22). A significant portion of attacks originated from the IP address 185.243.96.105. Attackers attempted to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most frequently targeted. The commands executed by attackers primarily focused on system reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
* Heralding: 4233
* Suricata: 3854
* Honeytrap: 3389
* Cowrie: 3304
* Ciscoasa: 1747
* Dionaea: 1006
* Sentrypeer: 400
* Mailoney: 114
* Tanner: 96
* Adbhoney: 64
* Miniprint: 45
* Redishoneypot: 23
* Dicompot: 15
* Honeyaml: 13
* H0neytr4p: 10
* ConPot: 5
* ElasticPot: 4

**Top Attacking IPs:**
* 185.243.96.105: 4230
* 109.205.211.9: 2532
* 114.37.149.144: 874
* 134.209.202.50: 524
* 198.23.190.58: 252
* 80.94.95.238: 224
* 36.103.243.179: 144
* 85.192.29.247: 130
* 203.189.221.17: 122
* 179.127.6.104: 109

**Top Targeted Ports/Protocols:**
* vnc/5900: 4230
* 445: 885
* 22: 543
* 5060: 400
* 8333: 168
* 5903: 131
* 5901: 109
* TCP/80: 109
* TCP/445: 79
* 25: 114

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2024-4577 CVE-2002-0953
* CVE-2024-4577 CVE-2024-4577
* CVE-2019-11500 CVE-2019-11500
* CVE-2021-41773
* CVE-2021-42013
* CVE-2006-2369
* CVE-2025-34036
* CVE-1999-0517
* CVE-2002-1149

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
* `cat /proc/cpuinfo | grep name | wc -l`
* `Enter new UNIX password:`
* `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
* `ls -lh $(which ls)`
* `which ls`
* `crontab -l`

**Signatures Triggered:**
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 1523
* 2023753: 1523
* ET HUNTING RDP Authentication Bypass Attempt: 702
* 2034857: 702
* ET DROP Dshield Block Listed Source group 1: 546
* 2402000: 546
* ET SCAN NMAP -sS window 1024: 184
* 2009582: 184
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 75
* 2024766: 75

**Users / Login Attempts:**
* /Passw0rd: 17
* /passw0rd: 16
* /1q2w3e4r: 15
* 345gs5662d34/345gs5662d34: 8
* root/euro: 4
* root/evox7410: 4
* root/ew2633: 4
* root/eurekaTLM: 3
* root/ewqiop321: 3
* /1234qwer: 3

**Files Uploaded/Downloaded:**
* sh: 98
* wget.sh;: 23
* w.sh;: 8
* c.sh;: 4
* arm.urbotnetisass;: 1
* arm.urbotnetisass: 1
* arm5.urbotnetisass;: 1
* arm5.urbotnetisass: 1
* arm6.urbotnetisass;: 1
* arm6.urbotnetisass: 1

**HTTP User-Agents:**
* (No data in logs)

**SSH Clients:**
* (No data in logs)

**SSH Servers:**
* (No data in logs)

**Top Attacker AS Organizations:**
* (No data in logs)

**Key Observations and Anomalies**

* The concentration of attacks from a single IP address (185.243.96.105) could indicate a targeted campaign or a single, highly active botnet.
* The commands attempted by attackers show a clear pattern of disabling security measures (`chattr -ia .ssh`), establishing persistence via SSH authorized keys, and performing system reconnaissance.
* The high number of VNC and RDP related signatures and port scans suggests that attackers are actively searching for and attempting to exploit remote desktop services.
* The variety of credentials used in login attempts indicates that attackers are using common and default password lists.
