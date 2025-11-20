Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T21:01:35Z
**Timeframe:** 2025-10-17T20:20:01Z to 2025-10-17T21:00:01Z
**Files Used:**
- agg_log_20251017T202001Z.json
- agg_log_20251017T204001Z.json
- agg_log_20251017T210001Z.json

**Executive Summary**

This report summarizes 12,202 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap and Suricata. The most frequent attacks originated from the IP address 72.146.232.13. The most targeted port was 5060, commonly used for SIP traffic. Several CVEs were detected, with CVE-2022-27255 being the most prevalent. A variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 3608
- Honeytrap: 2393
- Suricata: 1680
- Sentrypeer: 1435
- Ciscoasa: 1170
- Dionaea: 934
- ElasticPot: 782
- Tanner: 52
- H0neytr4p: 42
- Mailoney: 40
- ConPot: 28
- Redishoneypot: 17
- Honeyaml: 15
- Dicompot: 6

***Top Attacking IPs***

- 72.146.232.13
- 213.149.166.133
- 198.23.190.58
- 196.251.80.29
- 172.86.95.115
- 172.86.95.98
- 77.110.107.92
- 103.172.236.15
- 107.170.36.5
- 88.210.63.16

***Top Targeted Ports/Protocols***

- 5060
- 445
- 9200
- 22
- UDP/5060
- 8333
- 5903
- TCP/445
- 5904
- 5901

***Most Common CVEs***

- CVE-2022-27255
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2024-3721
- CVE-2001-0414
- CVE-2016-20016

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
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
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- echo "root:cX0nZn3NN4VU"|chpasswd|bash
- chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; mkdir -p ~/.ssh; chattr -ia ~/.ssh/authorized_keys; echo "ssh-rsa ... rsa-key-20230629" > ~/.ssh/authorized_keys; chattr +ai ~/.ssh/authorized_keys; uname -a
- tftp; wget; /bin/busybox KRHDA

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET HUNTING RDP Authentication Bypass Attempt
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- debian/7777777
- unknown/123123123
- support/33
- root/1938pyph
- centos/maintenance
- blank/techsupport
- test/000000
- debian/debian2019
- root/18mavi11
- root/18Setembro
- root/190634
- root/Zc123456
- supervisor/passw0rd
- ubnt/000000
- centos/123abc
- guest/4
- config/logon
- nobody/nobody2021
- naim/123

***Files Uploaded/Downloaded***

- None observed.

***HTTP User-Agents***

- None observed.

***SSH Clients***

- None observed.

***SSH Servers***

- None observed.

***Top Attacker AS Organizations***

- None observed.

**Key Observations and Anomalies**

- A significant number of commands are focused on manipulating SSH keys, suggesting a focus on maintaining persistent access.
- The high number of SIP-related attacks (port 5060) indicates a continued interest in exploiting VoIP systems.
- The prevalence of CVE-2022-27255, a buffer overflow vulnerability in Realtek's eCos SDK, suggests that many devices remain unpatched.
- The "mdrfckr" and "rsa-key-20230629" key comments in the attempted SSH commands are notable identifiers for specific threat actors or campaigns.
- No file uploads, downloads, or specific user agents were observed, which may indicate that the attacks are in an early reconnaissance phase.
