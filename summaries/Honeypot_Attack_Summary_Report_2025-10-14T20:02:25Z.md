Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T20:01:31Z
**Timeframe:** 2025-10-14T19:20:01Z to 2025-10-14T20:00:01Z
**Log Files:**
- agg_log_20251014T192001Z.json
- agg_log_20251014T194001Z.json
- agg_log_20251014T200001Z.json

**Executive Summary**

This report summarizes 18,297 attacks recorded by honeypots over a 40-minute period. The most targeted services were SSH (Cowrie), various network services (Honeytrap), and SIP (Sentrypeer). A significant portion of the attacks originated from IP addresses 206.191.154.180 and 185.243.5.146. Attackers attempted to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most common. A number of shell commands were executed, indicating attempts to establish persistence and gather system information.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 4871
- Honeytrap: 4310
- Sentrypeer: 3326
- Ciscoasa: 1800
- Suricata: 1737
- Mailoney: 1698
- Heralding: 219
- Dionaea: 141
- Redishoneypot: 54
- Tanner: 39
- H0neytr4p: 29
- ConPot: 27
- Miniprint: 17
- ElasticPot: 9
- Honeyaml: 9
- Ipphoney: 5
- Adbhoney: 3
- Dicompot: 3

***Top Attacking IPs***

- 206.191.154.180
- 185.243.5.146
- 5.39.250.130
- 176.65.141.119
- 86.54.42.238
- 95.170.68.246
- 88.210.63.16
- 172.86.95.98
- 172.86.95.115
- 185.243.5.148
- 185.243.5.121
- 62.141.43.183
- 5.223.45.31
- 61.220.127.240
- 41.111.162.34
- 23.95.128.167
- 59.97.205.137
- 89.117.54.101
- 165.22.211.63
- 138.68.171.6

***Top Targeted Ports/Protocols***

- 5060
- 25
- 22
- vnc/5900
- 5903
- 5908
- 5909
- 5901
- 27017
- 8333
- TCP/22
- 5907
- 80
- 3005
- TCP/80
- 5910
- 445
- 23
- 9100
- TCP/5432
- 1911
- 2000
- 9090
- 443
- 10001
- 22227
- TCP/1433
- 9001
- 2455
- 3377
- UDP/5060

***Most Common CVEs***

- CVE-1999-0517
- CVE-2002-0012
- CVE-2002-0013
- CVE-2016-20016
- CVE-2019-11500
- CVE-2025-57819

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
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
- Enter new UNIX password:
- uname -s -v -n -r -m
- echo -e "sg\\nzj82jmqiC8GR\\nzj82jmqiC8GR"|passwd|bash
- echo "sg\\nzj82jmqiC8GR\\nzj82jmqiC8GR\\n"|passwd

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Possible SSL Brute Force attack or Site Crawl
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET INFO CURL User Agent
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 49

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- root/Qaz123qaz
- root/3245gs5662d34
- ubnt/6666666
- supervisor/supervisor2016
- root/Password@2025
- nobody/111
- blank/blank2025
- root/vtGMthRo4v8Z
- centos/7777777
- ftpuser/ftppassword
- root/pbH7qwHBwmz7
- caja1/caja1123
- test/password12346
- minecraft/1234
- root/admin_888
- root/Aa000000
- thomas/thomas
- root/123@@@
- root/P@55w0rD
- user/222222
- default/default2007
- guest/guest666
- config/qwerty1
- blank/1111111
- silence/123
- root/98darmyeiN2y
- iksi/iksi
- zhaoyu/zhaoyu123
- root/1qaz@WSX!@#
- amar/amar@123
- root/factorio
- dani/dani
- kafka/kafka
- fin/fin123
- guest/guest22
- root/444444
- unknown/159753
- root/root2012
- root/CnM6CU9gVgKi
- blank/blank11
- root/QyUNxotCRD79
- elastic/elastic123
- user6/123
- jenkins/jenkins
- info/info
- admin/jc
- admin/Password@2021
- admin/a123456zzzz
- admin/adminnaja
- admin/12345Dou
- user/pass
- config/config2005

***Files Uploaded/Downloaded***

- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

***HTTP User-Agents***

- None Observed

***SSH Clients***

- None Observed

***SSH Servers***

- None Observed

***Top Attacker AS Organizations***

- None Observed

**Key Observations and Anomalies**

- A large number of commands were executed related to gathering system information and establishing persistence by adding an SSH key to `authorized_keys`.
- The file `arm.urbotnetisass` and its variants were downloaded, suggesting an attempt to install a botnet client.
- The most frequent signatures triggered were related to blocklisted IPs and scanning activity.
- A wide variety of usernames and passwords were attempted, indicating brute-force attacks.
