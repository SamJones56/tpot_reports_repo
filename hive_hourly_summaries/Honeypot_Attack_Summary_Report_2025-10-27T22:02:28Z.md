Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T22:01:47Z
**Timeframe:** 2025-10-27T21:20:02Z to 2025-10-27T22:00:01Z
**Log Files:**
- agg_log_20251027T212002Z.json
- agg_log_20251027T214001Z.json
- agg_log_20251027T220001Z.json

### Executive Summary
This report summarizes 18,003 attacks recorded by honeypots between 21:20 and 22:00 UTC on October 27, 2025. The majority of attacks targeted the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. Top attacking IPs originate from various global locations. Attackers primarily targeted ports 5060 (SIP) and 22 (SSH). Multiple CVEs were exploited, and a variety of malicious commands were executed, indicating attempts to perform reconnaissance and gain further access.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 9030
- **Honeytrap:** 3335
- **Ciscoasa:** 1984
- **Sentrypeer:** 1689
- **Suricata:** 1591
- **Adbhoney:** 62
- **Dionaea:** 77
- **Mailoney:** 97
- **Tanner:** 29
- **Redishoneypot:** 39
- **ConPot:** 21
- **H0neytr4p:** 18
- **ElasticPot:** 10
- **Dicompot:** 9
- **Honeyaml:** 7
- **ssh-rsa:** 2
- **Ipphoney:** 3

**Top Attacking IPs:**
- **8.217.77.179:** 1244
- **50.6.225.98:** 1242
- **144.172.108.231:** 1138
- **89.203.248.217:** 765
- **51.158.146.233:** 274
- **91.92.199.36:** 356
- **37.59.110.4:** 341
- **164.92.236.103:** 341
- **104.168.76.140:** 331
- **45.12.237.61:** 332
- **103.52.115.189:** 357
- **146.190.93.207:** 247
- **185.208.156.50:** 288
- **103.84.236.242:** 356
- **37.221.66.121:** 287
- **163.172.99.31:** 292
- **107.170.36.5:** 249
- **196.0.120.6:** 218
- **178.27.90.142:** 179
- **103.172.204.108:** 174

**Top Targeted Ports/Protocols:**
- **5060:** 1689
- **22:** 1393
- **5901:** 298
- **5903:** 139
- **8333:** 99
- **TCP/22:** 67
- **5904:** 77
- **5905:** 77
- **25:** 97
- **4369:** 111
- **TCP/80:** 40
- **5907:** 49
- **5908:** 50
- **5909:** 49
- **23:** 36
- **5902:** 45
- **80:** 27
- **443:** 15
- **10250:** 50
- **3306:** 14

**Most Common CVEs:**
- **CVE-2019-11500 CVE-2019-11500:** 6
- **CVE-1999-0265:** 5
- **CVE-2002-0013 CVE-2002-0012:** 4
- **CVE-2021-35394 CVE-2021-35394:** 2
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 2
- **CVE-2018-11776:** 1
- **CVE-2016-6563:** 1
- **CVE-1999-0183:** 1

**Commands Attempted by Attackers:**
- **cat /proc/cpuinfo | grep name | wc -l:** 37
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 37
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 37
- **ls -lh $(which ls):** 37
- **which ls:** 37
- **crontab -l:** 37
- **w:** 37
- **uname -m:** 37
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 37
- **top:** 37
- **uname -a:** 37
- **whoami:** 37
- **lscpu | grep Model:** 37
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 37
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 36
- **lockr -ia .ssh:** 36
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 36
- **Enter new UNIX password: :** 28
- **Enter new UNIX password::** 28
- **uname:** 36

**Signatures Triggered:**
- **ET DROP Dshield Block Listed Source group 1:** 355
- **2402000:** 355
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 227
- **2023753:** 227
- **ET SCAN NMAP -sS window 1024:** 194
- **2009582:** 194
- **ET HUNTING RDP Authentication Bypass Attempt:** 83
- **2034857:** 83
- **ET INFO Reserved Internal IP Traffic:** 61
- **2002752:** 61
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 21
- **2403347:** 21
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 14:** 19
- **2400013:** 19
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46:** 10
- **2403345:** 10
- **ET INFO CURL User Agent:** 10
- **2002824:** 10

**Users / Login Attempts:**
- **345gs5662d34/345gs5662d34:** 36
- **root/3245gs5662d34:** 6
- **root/asdf123.:** 5
- **root/jcastro123:** 4
- **root/jcaz2014:** 4
- **auxiliar/auxiliar:** 4
- **root/qaz123qaz:** 4
- **root/test101:** 4
- **root/Je0748329222:** 4
- **super/super:** 4
- **gmod/1234:** 4
- **root/jeff071185:** 4
- **root/Jelltom:** 4
- **root/Jeremy522:** 4

**Files Uploaded/Downloaded:**
- **wget.sh;**: 8
- **arm.uhavenobotsxd;**: 2
- **arm.uhavenobotsxd**: 2
- **arm5.uhavenobotsxd;**: 2
- **arm5.uhavenobotsxd**: 2
- **arm6.uhavenobotsxd;**: 2
- **arm6.uhavenobotsxd**: 2
- **arm7.uhavenobotsxd;**: 2
- **arm7.uhavenobotsxd**: 2
- **x86_32.uhavenobotsxd;**: 2
- **x86_32.uhavenobotsxd**: 2
- **mips.uhavenobotsxd;**: 2
- **mips.uhavenobotsxd**: 2
- **mipsel.uhavenobotsxd;**: 2
- **mipsel.uhavenobotsxd**: 2
- **lol.sh;**: 2
- **`cd**: 2
- **Mozi.m**: 2
- **XMLSchema-instance**: 2
- **XMLSchema**: 2

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients:**
- No SSH clients recorded in this period.

**SSH Servers:**
- No SSH servers recorded in this period.

**Top Attacker AS Organizations:**
- No AS organizations recorded in this period.

### Key Observations and Anomalies
- The high volume of attacks on Cowrie suggests a focus on SSH brute-forcing and command execution.
- A significant number of reconnaissance commands (`uname`, `lscpu`, `whoami`, etc.) were observed, indicating attackers are profiling the system after gaining initial access.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, suggesting an attempt to install a persistent SSH key for backdoor access.
- Attackers attempted to download and execute various malicious scripts (`wget.sh`, `arm.uhavenobotsxd`, `lol.sh`), indicating attempts to install malware or cryptominers.
- The targeting of port 5060 (SIP) remains high, indicating continued interest in exploiting VoIP systems.
- Despite the high volume of attacks, there is a lack of diversity in CVEs exploited, with only a few being repeatedly targeted.
- No HTTP user agents, SSH clients/servers, or AS organizations were recorded, which could indicate that the attacks were primarily from automated scripts that do not set these headers or that the honeypots did not capture this information.
