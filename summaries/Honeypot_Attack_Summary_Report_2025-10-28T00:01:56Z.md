Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T00:01:35Z
**Timeframe:** 2025-10-27T23:20:01Z to 2025-10-28T00:00:01Z
**Files Used:** agg_log_20251027T232001Z.json, agg_log_20251027T234001Z.json, agg_log_20251028T000001Z.json

**Executive Summary**

This report summarizes 20,565 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie (9,567 events), Suricata (3,363 events), and Honeytrap (3,182 events) honeypots. A significant number of attacks targeted SSH (port 22) and SMB (port 445). The most prominent attacking IP address was 87.245.148.38. Several CVEs were targeted, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing unauthorized access.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 9,567
*   Suricata: 3,363
*   Honeytrap: 3,182
*   Ciscoasa: 2,059
*   Sentrypeer: 1,657
*   Dionaea: 377
*   Mailoney: 103
*   ConPot: 59
*   Adbhoney: 42
*   H0neytr4p: 42
*   Redishoneypot: 34
*   ssh-rsa: 30
*   Tanner: 28
*   Honeyaml: 12
*   Dicompot: 7
*   Ipphoney: 3

***Top Attacking IPs***

*   87.245.148.38
*   45.132.75.33
*   144.172.108.231
*   152.32.206.160
*   154.219.113.236
*   103.241.43.23
*   189.36.132.232
*   194.107.115.65
*   41.59.229.33
*   190.184.222.63
*   77.83.240.70
*   38.248.12.102
*   87.19.175.188
*   117.247.111.70
*   135.181.251.183

***Top Targeted Ports/Protocols***

*   5060
*   22
*   445
*   TCP/445
*   5901
*   5903
*   23
*   25
*   6379
*   TCP/80
*   TCP/22
*   5904
*   5905

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2005-4050
*   CVE-2018-11776
*   CVE-2006-2369

***Commands Attempted by Attackers***

*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   cat /proc/cpuinfo | grep name | wc -l
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   cat /proc/cpuinfo | grep model | grep name | wc -l
*   top
*   uname
*   uname -a
*   whoami
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
*   Enter new UNIX password:

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET INFO Reserved Internal IP Traffic
*   ET SCAN Potential SSH Scan
*   ET INFO curl User-Agent Outbound
*   ET DYN_DNS DYNAMIC_DNS HTTP Request to a *.ddns .net Domain
*   ET CINS Active Threat Intelligence Poor Reputation IP group 45
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   root/000000
*   chenqun/chenqun
*   root/Zy@123456
*   root/q1w2e3r4!
*   admin/admin123456789
*   jifu/jifu
*   etienne/etienne
*   root/Asd@2023
*   etienne/3245gs5662d34
*   xiang/xiang
*   root/mainstreet
*   horse/horse

***Files Uploaded/Downloaded***

*   wget.sh;
*   arm.uhavenobotsxd;
*   arm.uhavenobotsxd
*   arm5.uhavenobotsxd;
*   arm5.uhavenobotsxd
*   arm6.uhavenobotsxd;
*   arm6.uhavenobotsxd
*   arm7.uhavenobotsxd;
*   arm7.uhavenobotsxd
*   x86_32.uhavenobotsxd;
*   x86_32.uhavenobotsxd
*   mips.uhavenobotsxd;
*   mips.uhavenobotsxd
*   mipsel.uhavenobotsxd;
*   mipsel.uhavenobotsxd
*   w.sh;
*   c.sh;

***HTTP User-Agents***

*   *No user agents recorded in this period.*

***SSH Clients and Servers***

*   *No specific SSH clients or servers recorded in this period.*

***Top Attacker AS Organizations***

*   *No attacker AS organizations recorded in this period.*

**Key Observations and Anomalies**

*   The high number of events from the IP address 87.245.148.38 is anomalous and suggests a targeted attack or a botnet.
*   The commands attempted by attackers indicate a clear pattern of reconnaissance, followed by attempts to establish persistent access by modifying SSH authorized_keys.
*   The DoublePulsar backdoor signature was triggered a significant number of times, indicating attempts to exploit the SMB vulnerability.
*   The variety of usernames and passwords used in login attempts suggests the use of common credential lists.

This concludes the Honeypot Attack Summary Report.