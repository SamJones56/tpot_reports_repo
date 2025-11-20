Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T20:01:34Z
**Timeframe:** 2025-10-19T19:20:01Z to 2025-10-19T20:00:01Z
**Log Files:**
- agg_log_20251019T192001Z.json
- agg_log_20251019T194001Z.json
- agg_log_20251019T200001Z.json

### Executive Summary
This report summarizes 17,100 attacks recorded over a 40-minute period. The most active honeypot was Cowrie, and the most frequent attacker IP was 198.23.238.154. The primary targets were ports associated with VoIP (5038, 5060) and SSH (22). Several CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7090
- Honeytrap: 5437
- Suricata: 2019
- Sentrypeer: 1567
- Ciscoasa: 642
- Mailoney: 77
- Dionaea: 73
- Tanner: 72
- Miniprint: 64
- ConPot: 15
- Redishoneypot: 15
- Adbhoney: 13
- H0neytr4p: 7
- Honeyaml: 4
- ElasticPot: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 198.23.238.154
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 198.12.68.114
- 164.92.146.119
- 104.248.196.40
- 85.239.237.99
- 194.107.115.11
- 107.170.36.5

**Top Targeted Ports/Protocols:**
- 5038
- 5060
- 22
- UDP/5060
- 5903
- 8333
- 9100
- TCP/80
- 80
- 5901

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2016-6563
- CVE-2023-25690
- CVE-2002-0013
- CVE-2021-3449
- CVE-2019-11500
- CVE-2001-0414
- CVE-2024-3721
- CVE-2023-52163
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2018-7600
- CVE-2023-26801

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

**Signatures Triggered:**
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET WEB_SERVER WGET Command Specifying Output in HTTP Headers
- 2019309
- ET WEB_SERVER WebShell Generic - wget http - POST
- 2016683
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- user01/Password01
- deploy/123123
- config/config2006
- unknown/66666
- deploy/1234
- debian/2
- admin/2222
- amal/amal
- root/7jdr3k8
- student2/student2123
- maxwell/3245gs5662d34
- data/data
- root/7k52Dx2dDd
- guest/guest2014
- elearning/123
- harry/123
- root/!Qaz2wsx
- root/7u8i9o!!!
- archana/archana123
- root/7y7c8DQN5!q

**Files Uploaded/Downloaded:**
- binary.sh
- `wget
- wget.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- `busybox
- w.sh;
- c.sh;
- json

**HTTP User-Agents:**
- None observed

**SSH Clients:**
- None observed

**SSH Servers:**
- None observed

**Top Attacker AS Organizations:**
- None observed

### Key Observations and Anomalies
- A significant number of commands are related to reconnaissance of the system's hardware and operating system.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install a persistent SSH key for backdoor access.
- The downloaded files `*.urbotnetisass` are likely malware payloads for different architectures (ARM, x86, MIPS).
- The high volume of traffic on ports 5038 and 5060 suggests a focus on exploiting VoIP systems.
- The Suricata signature "ET VOIP MultiTech SIP UDP Overflow" was triggered a large number of times, correlating with the high traffic on VoIP ports.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organizations suggests that the attacks are likely automated and may not be sophisticated enough to provide this information, or the honeypots did not capture it.
