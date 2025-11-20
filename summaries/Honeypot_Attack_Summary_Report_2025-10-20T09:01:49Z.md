Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T09:01:24Z
**Timeframe:** 2025-10-20T08:20:01Z to 2025-10-20T09:00:01Z
**Files Used:**
- agg_log_20251020T082001Z.json
- agg_log_20251020T084001Z.json
- agg_log_20251020T090001Z.json

### Executive Summary

This report summarizes 6851 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the traffic was directed towards TCP port 445, likely related to SMB exploits, with SSH (port 22) and SIP (port 5060) also being major targets. The most prominent attacking IP address was 213.154.15.25. A number of CVEs were detected, with attackers attempting various commands to gain system information and establish persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 2573
- Suricata: 2401
- Honeytrap: 1328
- Sentrypeer: 338
- Dionaea: 86
- Adbhoney: 32
- Redishoneypot: 24
- Tanner: 16
- ConPot: 13
- Miniprint: 10
- Mailoney: 9
- H0neytr4p: 8
- ElasticPot: 7
- Ciscoasa: 4
- Honeyaml: 1
- Ipphoney: 1

**Top Attacking IPs:**
- 213.154.15.25
- 72.146.232.13
- 88.214.50.58
- 122.168.194.41
- 94.76.228.52
- 74.208.133.247
- 49.49.237.200
- 27.254.137.144
- 185.243.5.103
- 139.59.229.250
- 152.32.215.227
- 179.33.210.213
- 160.187.147.127
- 222.85.205.147

**Top Targeted Ports/Protocols:**
- TCP/445
- 22
- 5060
- 445
- 8333
- 5905
- 5904

**Most Common CVEs:**
- CVE-2025-30208
- CVE-2021-3449
- CVE-2019-11500
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2023-31983
- CVE-2020-10987
- CVE-2023-47565
- CVE-2014-6271
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2022-37056

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -a
- whoami
- top
- crontab -l

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- user01/Password01
- root/AAA250100yr
- irfan/123
- kafka/kafka123
- student1/student1123
- lena/lena
- ubuntu/XXXXX

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- server.cgi?func=server02_main_submit...
- rondo.qre.sh||busybox

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No AS organization data was available in the logs.

### Key Observations and Anomalies

- The high number of events targeting TCP port 445, combined with the "DoublePulsar Backdoor" signature, suggests a significant amount of SMB worm activity.
- Attackers are using a consistent set of commands to enumerate system information and attempt to install SSH keys for persistence.
- The `urbotnetisass` files suggest a campaign to install botnet clients on compromised devices of various architectures.
- There is a mix of targeted attacks and automated scanning, as evidenced by the variety of honeypots and triggered signatures.
