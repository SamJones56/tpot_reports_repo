
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T14:01:36Z
**Timeframe:** 2025-10-06T13:20:01Z to 2025-10-06T14:00:01Z
**Files Used:**
- agg_log_20251006T132001Z.json
- agg_log_20251006T134001Z.json
- agg_log_20251006T140001Z.json

## Executive Summary

This report summarizes 16,379 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. Attackers were observed attempting to gain access via SSH and other common ports, executing commands to download malicious files, and leveraging various CVEs. A significant number of attacks originated from a small number of IP addresses.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 9317
- **Mailoney:** 1697
- **Honeytrap:** 1816
- **Suricata:** 1277
- **Ciscoasa:** 1280
- **Dionaea:** 414
- **Sentrypeer:** 405
- **Adbhoney:** 20
- **Miniprint:** 41
- **Dicompot:** 18
- **H0neytr4p:** 27
- **Honeyaml:** 15
- **Tanner:** 13
- **ElasticPot:** 24
- **Redishoneypot:** 4
- **ConPot:** 9
- **Ipphoney:** 2

### Top Attacking IPs

- **176.65.141.117:** 1640
- **45.93.249.170:** 1255
- **170.64.159.245:** 968
- **172.86.95.98:** 387
- **103.82.92.209:** 258
- **103.98.176.164:** 232
- **54.38.52.18:** 209
- **194.163.157.112:** 198
- **14.103.116.87:** 220
- **50.84.211.204:** 169
- **137.184.145.163:** 174
- **167.86.127.135:** 149
- **157.180.74.71:** 159
- **115.94.44.14:** 89
- **195.250.72.168:** 149
- **27.79.6.160:** 318
- **116.99.175.49:** 237
- **112.17.139.236:** 147
- **194.190.153.226:** 134
- **189.190.223.246:** 129
- **185.227.152.155:** 124
- **115.94.44.12:** 104
- **64.227.102.57:** 94
- **167.71.204.253:** 84
- **116.138.186.211:** 69
- **185.76.34.16:** 65
- **14.103.115.233:** 54
- **85.185.112.6:** 390
- **117.72.205.36:** 136
- **103.189.235.176:** 124
- **192.40.58.3:** 124
- **182.61.149.98:** 122
- **178.177.19.25:** 114
- **103.10.45.57:** 204
- **103.136.106.101:** 94
- **196.12.203.185:** 94
- **185.186.26.225:** 73
- **145.249.109.167:** 70
- **42.51.42.196:** 114
- **129.226.4.89:** 109
- **8.219.235.147:** 94
- **106.13.114.161:** 94
- **43.231.129.254:** 60

### Top Targeted Ports/Protocols

- **25:** 1688
- **22:** 1538
- **5060:** 405
- **445:** 390
- **8333:** 110
- **5902:** 97
- **5903:** 95
- **23:** 99
- **9100:** 41
- **TCP/22:** 70
- **9200:** 22
- **443:** 19
- **5002:** 19
- **5431:** 21
- **80:** 10
- **81:** 8
- **TCP/8013:** 8
- **8729:** 8
- **1027:** 8
- **49155:** 7
- **8090:** 6
- **TCP/1521:** 23
- **2077:** 15
- **4190:** 15
- **1521:** 14
- **8585:** 10
- **TCP/5080:** 10
- **TCP/9100:** 10
- **8091:** 18
- **8389:** 9
- **2000:** 16
- **TCP/80:** 16
- **7443:** 15
- **UDP/161:** 15
- **55555:** 13
- **5908:** 11
- **5909:** 11
- **5907:** 10

### Most Common CVEs

- **CVE-2021-44228 CVE-2021-44228:** 25
- **CVE-2002-0013 CVE-2002-0012:** 11
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-1999-0517:** 3
- **CVE-2023-26801 CVE-2023-26801:** 1
- **CVE-2016-20016 CVE-2016-20016:** 1
- **CVE-2006-2369:** 1
- **CVE-2001-0414:** 1

### Commands Attempted by Attackers

- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 32
- **lockr -ia .ssh:** 32
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 32
- **cat /proc/cpuinfo | grep name | wc -l:** 32
- **Enter new UNIX password: :** 32
- **Enter new UNIX password:** 32
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 32
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 32
- **ls -lh $(which ls):** 32
- **which ls:** 32
- **crontab -l:** 32
- **w:** 32
- **uname -m:** 32
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 32
- **top:** 32
- **uname:** 32
- **uname -a:** 32
- **whoami:** 33
- **lscpu | grep Model:** 32
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 32

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1:** 557
- **2402000:** 557
- **ET SCAN NMAP -sS window 1024:** 125
- **2009582:** 125
- **ET SCAN Potential SSH Scan:** 52
- **2001219:** 52
- **ET INFO Reserved Internal IP Traffic:** 61
- **2002752:** 61
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 31
- **2023753:** 31
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 28
- **2400027:** 28
- **ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228):** 12
- **2034755:** 12
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 32:** 14
- **2400031:** 14
- **ET INFO CURL User Agent:** 19
- **2002824:** 19
- **ET SCAN Suspicious inbound to Oracle SQL port 1521:** 17
- **2010936:** 17
- **GPL TELNET Bad Login:** 6
- **2101251:** 6
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 49:** 5
- **2400048:** 5
- **ET CINS Active Threat Intelligence Poor Reputation IP group 68:** 9
- **2403367:** 9
- **ET CINS Active Threat Intelligence Poor Reputation IP group 13:** 7
- **2403312:** 7
- **ET HUNTING RDP Authentication Bypass Attempt:** 9
- **2034857:** 9
- **ET INFO curl User-Agent Outbound:** 6
- **2013028:** 6
- **ET HUNTING curl User-Agent to Dotted Quad:** 6
- **2034567:** 6

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 29
- **User-Agent: Mozilla/5.0...:** 6
- **Accept-Encoding: gzip/:** 6
- **frappe/frappe@11:** 3
- **basic/123:** 3
- **venus/venus123:** 3
- **dmdba/dmdba.:** 3
- **swearer/swearer:** 3
- **candi/candi@123:** 3
- **jenni/jenni123:** 3
- **root/1qaz2wsx:** 3
- **bigdata/bigdata:** 3
- **vps/3245gs5662d34:** 3
- **steam/steam:** 3
- **mongodb/mongodb:** 3
- **alex/alexPassword:** 3
- **teamspeak/teamspeak1234_:** 3
- **tammy/tammy@123:** 2
- **marty/marty123:** 2
- **root/Dharma@123:** 2
- **kermit/3245gs5662d34:** 2
- **root/root_!@#$%:** 2
- **ellen/ellen@123:** 2
- **ellen/3245gs5662d34:** 2
- **teamspeak/teamspeak_2024:** 2
- **user/Chinacache_2014:** 2
- **user/Chinacache_123:** 2
- **user/Chinacache_!@#:** 2
- **supported/supported@123:** 2
- **ftptest/ftptest123.123:** 2
- **crystal/crystal@123:** 2
- **shark/shark:** 2
- **rancher/rancher123:** 2
- **lynne/123:** 2
- **robotics/robotics:** 2
- **test/1234qwer:** 2
- **dieter/123:** 2
- **data/data:** 2
- **admin/121234:** 2
- **es/es:** 2
- **newuser/newuserP@ss0wrd:** 2
- **lamination/lamination:** 2
- **guest/guest123:** 2
- **vagrant/vagrant:** 2
- **mysql/mysql=123654:** 2
- **test1/test_123:** 2
- **dolphinscheduler/dolphinscheduler123:** 2
- **esadmin/esadmin:** 2
- **deploy/deploy123:** 2
- **root/toor:** 2
- **test1/test2024:** 2
- **oracle/123qwe:** 2
- **rabbitmq/rabbitmq:** 2
- **dmdba/dmdba_2025:** 2
- **ftp/ftp:** 2
- **developer/developer:** 2

### Files Uploaded/Downloaded

- **wget.sh;**: 8
- **w.sh;**: 2
- **c.sh;**: 2
- **11**: 1
- **fonts.gstatic.com**: 1
- **css?family=Libre+Franklin...**: 1
- **ie8.css?ver=1.0**: 1
- **html5.js?ver=3.7.3**: 1

### HTTP User-Agents

- No HTTP User-Agents were logged in this timeframe.

### SSH Clients and Servers

- No SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations

- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The vast majority of attacks are automated, focusing on well-known ports and vulnerabilities.
- The `Cowrie` honeypot continues to be the most targeted, indicating a high volume of SSH-based attacks.
- Attackers are consistently attempting to download and execute malicious scripts (`wget.sh`, `w.sh`, `c.sh`), suggesting attempts to enlist the honeypot in a botnet.
- The repeated use of commands to gather system information (`uname`, `lscpu`, `free`) is a common reconnaissance technique.
- A significant number of login attempts use common or default credentials, highlighting the ongoing threat of brute-force attacks.
- The presence of `CVE-2021-44228` (Log4j) indicates that this vulnerability is still actively being exploited.
