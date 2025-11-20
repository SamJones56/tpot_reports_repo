Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T06:01:37Z
**Timeframe:** 2025-10-16T05:20:01Z to 2025-10-16T06:00:01Z
**Log Files:**
- agg_log_20251016T052001Z.json
- agg_log_20251016T054001Z.json
- agg_log_20251016T060001Z.json

### Executive Summary
This report summarizes 15,064 attacks recorded by the honeypot network. The most targeted honeypot was Cowrie, a medium-interaction SSH and Telnet honeypot. The majority of attacks originated from the IP address 23.94.26.58. The most frequently targeted port was 5060 (SIP). A number of CVEs were detected, with the most common being related to older vulnerabilities. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control of the compromised system.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 4474
- **Honeytrap:** 3474
- **Sentrypeer:** 2983
- **Suricata:** 1972
- **Ciscoasa:** 1673
- **Dionaea:** 209
- **Adbhoney:** 39
- **ElasticPot:** 42
- **ConPot:** 51
- **Tanner:** 36
- **Mailoney:** 46
- **Miniprint:** 19
- **Redishoneypot:** 13
- **Honeyaml:** 13
- **H0neytr4p:** 16
- **Dicompot:** 4

**Top Attacking IPs:**
- **23.94.26.58:** 862
- **88.214.50.58:** 634
- **172.86.95.115:** 518
- **172.86.95.98:** 508
- **185.243.5.158:** 466
- **165.154.235.179:** 306
- **152.32.144.167:** 332
- **103.82.37.34:** 327
- **62.141.43.183:** 321
- **124.18.243.125:** 238
- **51.91.253.117:** 316
- **103.186.1.120:** 218
- **202.70.65.229:** 217
- **107.170.36.5:** 249
- **42.200.78.78:** 214
- **155.4.244.169:** 163
- **59.26.132.170:** 164
- **36.69.152.163:** 154
- **121.224.115.232:** 119
- **198.12.68.114:** 125

**Top Targeted Ports/Protocols:**
- **5060:** 2983
- **22:** 533
- **5903:** 227
- **8333:** 138
- **3306:** 134
- **5901:** 116
- **5905:** 76
- **5904:** 76
- **1025:** 40
- **9200:** 42
- **23:** 33
- **UDP/5060:** 38
- **25:** 46
- **5902:** 50
- **5909:** 49
- **5908:** 49
- **5907:** 50
- **80:** 28
- **1434:** 34
- **10250:** 51

**Most Common CVEs:**
- **CVE-2002-0013 CVE-2002-0012:** 14
- **CVE-2021-3449 CVE-2021-3449:** 6
- **CVE-2019-11500 CVE-2019-11500:** 5
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255:** 2
- **CVE-1999-0183:** 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `which ls`
- `ls -lh $(which ls)`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`
- `chmod 0755 /data/local/tmp/nohup`

**Signatures Triggered:**
- **ET DROP Dshield Block Listed Source group 1:** 525
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 364
- **ET HUNTING RDP Authentication Bypass Attempt:** 158
- **ET SCAN NMAP -sS window 1024:** 170
- **ET INFO Reserved Internal IP Traffic:** 61
- **ET SCAN Sipsak SIP scan:** 44
- **ET CINS Active Threat Intelligence Poor Reputation IP group 51:** 37
- **ET CINS Active Threat Intelligence Poor Reputation IP group 43:** 24
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 26
- **GPL SNMP request udp:** 8

**Users / Login Attempts:**
- **root/:** 132
- **345gs5662d34/345gs5662d34:** 28
- **root/Qaz123qaz:** 9
- **root/123@@@:** 7
- **guest/guest222:** 6
- **support/marketing:** 6
- **root/999999:** 5
- **root/88888:** 4
- **unknown/unknown2007:** 4
- **nobody/555:** 4
- **operator/operator2011:** 4
- **root/root2019:** 4
- **root/pass4312:** 4
- **nobody/2222:** 4
- **root/root66:** 6
- **debian/9:** 4
- **test/test2007:** 4
- **jafar/jafar:** 3
- **root/1225:** 3
- **root/pass2k2:** 3

**Files Uploaded/Downloaded:**
- Mozi.m;

**HTTP User-Agents:**
- None observed.

**SSH Clients:**
- None observed.

**SSH Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies
- The volume of attacks is high and consistent across the three time periods, indicating automated and widespread scanning campaigns.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear attempt to install a persistent SSH key for backdoor access. This was the most common malicious command observed.
- The file "Mozi.m" was observed in download attempts, which is associated with the Mozi botnet, a P2P botnet that primarily targets IoT devices.
- A significant number of brute-force attempts are still using common and default credentials like `root`, `admin`, `guest`, etc.
- The triggered Suricata signatures show a mix of reconnaissance scans (NMAP), traffic from known malicious IP addresses (Dshield, CINS), and some specific protocol scans (SIP, SNMP).