Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T03:01:36Z
**Timeframe:** 2025-10-28T02:20:02Z to 2025-10-28T03:00:01Z
**Files Used:**
- agg_log_20251028T022002Z.json
- agg_log_20251028T024001Z.json
- agg_log_20251028T030001Z.json

**Executive Summary**
This report summarizes the honeypot activity over a short period, revealing a total of 16,746 malicious events. The majority of these attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. The most targeted ports were 445 (SMB) and 5060 (SIP). A variety of CVEs were targeted, with CVE-2021-3449 and CVE-2002-0012/13 being the most frequent. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

**Attacks by Honeypot:**
* Cowrie: 5580
* Honeytrap: 3065
* Suricata: 2020
* Ciscoasa: 2011
* Dionaea: 2091
* Sentrypeer: 1696
* Mailoney: 95
* Adbhoney: 63
* H0neytr4p: 30
* Tanner: 21
* Redishoneypot: 21
* Honeyaml: 16
* Miniprint: 16
* ElasticPot: 10
* Dicompot: 4
* Heralding: 3
* Ipphoney: 3
* ConPot: 1

**Top Attacking IPs:**
* 103.4.102.216: 1356
* 170.64.171.45: 1242
* 144.172.108.231: 1064
* 20.2.136.52: 889
* 167.71.11.218: 728
* 180.242.216.184: 379
* 163.172.99.31: 359
* 186.10.86.130: 335
* 69.63.77.146: 309
* 212.25.35.70: 212
* 115.240.221.26: 198
* 190.108.76.143: 198
* 88.210.63.16: 225
* 107.170.36.5: 253
* 185.243.5.121: 162
* 211.254.212.59: 162
* 167.250.224.25: 140
* 109.73.192.170: 124
* 103.189.235.93: 114
* 118.193.38.207: 114

**Top Targeted Ports/Protocols:**
* 445: 2051
* 5060: 1696
* 22: 907
* 5901: 213
* 5903: 132
* TCP/22: 120
* 25: 95
* 11434: 66
* 5904: 78
* 5905: 79
* 5907: 52
* 5908: 50
* 5909: 50
* 5902: 39
* 3395: 13
* TCP/80: 28
* 8333: 16
* 9100: 16

**Most Common CVEs:**
* CVE-2021-44228
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2025-22457
* CVE-2019-12263
* CVE-2019-12261
* CVE-2019-12260
* CVE-2019-12255
* CVE-2006-3602
* CVE-2006-4458
* CVE-2006-4542
* CVE-1999-0183
* CVE-2019-11500
* CVE-2021-3449

**Commands Attempted by Attackers:**
* cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 19
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 19
* lockr -ia .ssh: 19
* uname -a: 18
* cat /proc/cpuinfo | grep name | wc -l: 18
* whoami: 14
* crontab -l: 18
* w: 18
* uname -m: 18
* top: 17
* uname: 17
* ls -lh $(which ls): 17
* which ls: 17
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 17
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 17
* cat /proc/cpuinfo | grep model | grep name | wc -l: 17
* lscpu | grep Model: 14
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 14
* Enter new UNIX password: : 15
* Enter new UNIX password::: 15

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1: 504
* 2402000: 504
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 311
* 2023753: 311
* ET SCAN NMAP -sS window 1024: 190
* 2009582: 190
* ET HUNTING RDP Authentication Bypass Attempt: 116
* 2034857: 116
* ET SCAN Potential SSH Scan: 69
* 2001219: 69
* ET INFO Reserved Internal IP Traffic: 57
* 2002752: 57

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34: 18
* root/juli4n43!: 4
* root/julien: 4
* root/jungle: 4
* root/juliet4c4: 4
* root/Juno111: 4
* root/jw1=12--: 4
* rfarias/rfarias: 3
* root/junixti: 3
* user/xiao123456.: 3
* user/xiajc: 3
* user/xhliao: 3
* user/xhbai: 3
* user/www.y9idc.com: 3
* root/P@ssword2: 3

**Files Uploaded/Downloaded:**
* wget.sh;
* w.sh;
* c.sh;
* arm.uhavenobotsxd;
* arm.uhavenobotsxd
* arm5.uhavenobotsxd;
* arm5.uhavenobotsxd
* arm6.uhavenobotsxd;
* arm6.uhavenobotsxd
* arm7.uhavenobotsxd;
* arm7.uhavenobotsxd
* x86_32.uhavenobotsxd;
* x86_32.uhavenobotsxd
* mips.uhavenobotsxd;
* mips.uhavenobotsxd
* mipsel.uhavenobotsxd;
* mipsel.uhavenobotsxd
* arm.urbotnetisass;
* arm.urbotnetisass
* arm5.urbotnetisass;
* arm5.urbotnetisass
* arm6.urbotnetisass;
* arm6.urbotnetisass

**HTTP User-Agents:**
- No user agents were observed in the logs.

**SSH Clients:**
- No SSH clients were observed in the logs.

**SSH Servers:**
- No SSH servers were observed in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were observed in the logs.

**Key Observations and Anomalies**
- A significant number of commands are focused on disabling security measures (chattr, lockr) and establishing persistent access via SSH authorized_keys.
- The attackers are also performing detailed system reconnaissance, checking CPU info, memory, and disk space.
- Multiple attempts to download and execute malicious scripts from remote servers were observed.
- The login attempts use a mix of common default credentials and more complex passwords, indicating a broad and automated approach to brute-forcing.
- The presence of commands like "Enter new UNIX password:" suggests that some of the automated tools are not correctly handling the prompts from the honeypot, revealing their scripted nature.
- The filenames "uhavenobotsxd" and "urbotnetisass" suggest the attackers are deploying botnet clients.
