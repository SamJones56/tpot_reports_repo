Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T23:01:26Z
**Timeframe:** 2025-10-21T22:20:01Z to 2025-10-21T23:00:01Z
**Files Used:**
- agg_log_20251021T222001Z.json
- agg_log_20251021T224002Z.json
- agg_log_20251021T230001Z.json

**Executive Summary**

This report summarizes 7997 security events captured by the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Honeytrap, Ciscoasa, and Cowrie honeypots. The most frequent attacks originated from the IP address 72.146.232.13. The most targeted ports were 5060 (SIP) and 22 (SSH). Several CVEs were detected, with the most common being CVE-2022-27255. A variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- **Honeytrap:** 2528
- **Ciscoasa:** 1744
- **Cowrie:** 1576
- **Suricata:** 1387
- **Sentrypeer:** 466
- **Mailoney:** 75
- **Tanner:** 53
- **Dionaea:** 49
- **H0neytr4p:** 44
- **ConPot:** 39
- **Redishoneypot:** 10
- **Dicompot:** 9
- **ssh-rsa:** 8
- **ElasticPot:** 3
- **Heralding:** 3
- **Honeyaml:** 3

***Top Attacking IPs***

- **72.146.232.13:** 906
- **88.210.63.16:** 317
- **107.170.36.5:** 250
- **2.57.121.61:** 140
- **198.23.190.58:** 150
- **14.103.64.39:** 127
- **68.183.149.135:** 113
- **185.244.36.170:** 94
- **159.89.121.144:** 93
- **68.183.207.213:** 93
- **198.23.238.154:** 90
- **167.250.224.25:** 90
- **77.83.207.203:** 57
- **152.42.192.111:** 72
- **3.134.148.59:** 48
- **45.144.212.240:** 55
- **185.243.5.146:** 61
- **130.83.245.115:** 58

***Top Targeted Ports/Protocols***

- **5060:** 466
- **22:** 431
- **5903:** 224
- **5901:** 114
- **8333:** 86
- **25:** 75
- **5905:** 76
- **5904:** 79
- **UDP/5060:** 91
- **80:** 50
- **443:** 35
- **TCP/80:** 33

***Most Common CVEs***

- **CVE-2022-27255:** 14
- **CVE-2002-0013 CVE-2002-0012:** 9
- **CVE-2021-3449:** 7
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2019-11500:** 6
- **CVE-2024-3721:** 2
- **CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255:** 2
- **CVE-2006-2369:** 1
- **CVE-2002-1149:** 1

***Commands Attempted by Attackers***

- `uname -s -v -n -r -m`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `echo -e "batman\\nJU5vLTbTBZke\\nJU5vLTbTBZke"|passwd|bash`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`

***Signatures Triggered***

- **ET DROP Dshield Block Listed Source group 1:** 284
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 237
- **ET SCAN NMAP -sS window 1024:** 127
- **ET HUNTING RDP Authentication Bypass Attempt:** 98
- **ET SCAN Sipsak SIP scan:** 63
- **ET INFO Reserved Internal IP Traffic:** 50
- **ET HUNTING Mozilla User-Agent (Mozilla/5.0) Inbound Likely Fake:** 31
- **ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255):** 14
- **ET SCAN Sipvicious User-Agent Detected (friendly-scanner):** 12
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 20
- **GPL SNMP request udp:** 8

***Users / Login Attempts***

- A variety of usernames and passwords were attempted, with `root`, `admin`, `user`, and service names like `postgres`, `minecraft`, and `kafka` being common.
- Login attempts included default credentials, common passwords, and more complex variations.

***Files Uploaded/Downloaded***

- No files were uploaded or downloaded in this period.

***HTTP User-Agents***

- No HTTP user agents were recorded in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were recorded in this period.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- The high number of events in a short period indicates a high level of automated scanning and exploitation attempts.
- The commands attempted suggest that attackers are trying to gather information about the system, establish persistence through SSH keys, and change user passwords.
- The presence of commands to remove and modify the `.ssh` directory is a strong indicator of attempts to take over the system by adding the attacker's public key to the `authorized_keys` file.
- The variety of honeypots that were triggered indicates that attackers are using a wide range of techniques to probe for vulnerabilities.
- The triggered signatures from Suricata show that many of the attacking IPs are known bad actors and are part of blocklists like Dshield and Spamhaus.
