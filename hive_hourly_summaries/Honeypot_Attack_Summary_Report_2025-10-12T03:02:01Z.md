
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T03:01:35Z
**Timeframe:** 2025-10-12T02:20:01Z to 2025-10-12T03:00:01Z
**Files Used:**
- agg_log_20251012T022001Z.json
- agg_log_20251012T024001Z.json
- agg_log_20251012T030001Z.json

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, based on data from three log files. A total of 20,626 events were recorded across various honeypots. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap). A significant portion of the attacks originated from a small number of IP addresses, with a notable concentration of activity from `83.168.107.46` and `8.138.186.69`. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. Several CVEs were targeted, and a number of intrusion detection signatures were triggered.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 11,715
- **Honeytrap:** 4,337
- **Suricata:** 2,024
- **Ciscoasa:** 1,840
- **Sentrypeer:** 137
- **Tanner:** 146
- **Mailoney:** 125
- **ConPot:** 69
- **Dionaea:** 71
- **Miniprint:** 51
- **Dicompot:** 25
- **H0neytr4p:** 36
- **Redishoneypot:** 16
- **Honeyaml:** 15
- **Adbhoney:** 11
- **ElasticPot:** 6
- **Ipphoney:** 2

### Top Attacking IPs

- **83.168.107.46:** 1,264
- **8.138.186.69:** 1,014
- **118.194.250.47:** 925
- **45.128.199.212:** 746
- **71.168.162.91:** 438
- **162.240.156.34:** 446
- **81.177.101.45:** 421
- **147.45.112.157:** 451
- **217.160.201.135:** 376
- **103.86.180.10:** 337
- **46.32.178.186:** 322
- **1.238.106.229:** 303
- **78.39.48.166:** 277
- **103.176.20.115:** 268
- **64.227.139.157:** 288
- **103.189.208.13:** 232
- **103.148.195.173:** 277
- **14.29.129.250:** 200
- **79.46.155.110:** 214
- **204.44.127.231:** 209
- **200.1.218.25:** 179
- **103.72.147.99:** 169

### Top Targeted Ports/Protocols

- **22:** 1,709
- **5038:** 746
- **80:** 150
- **5903:** 201
- **25:** 125
- **5060:** 137
- **1521:** 66
- **23:** 44
- **445:** 33
- **TCP/22:** 54
- **TCP/80:** 39
- **TCP/1521:** 36

### Most Common CVEs

- **CVE-2002-1149:** 8
- **CVE-2002-0013 CVE-2002-0012:** 5
- **CVE-2019-11500 CVE-2019-11500:** 4
- **CVE-2016-20016 CVE-2016-20016:** 3
- **CVE-2021-3449 CVE-2021-3449:** 3
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 3
- **CVE-2023-49103 CVE-2023-49103:** 2
- **CVE-2005-4050:** 1
- **CVE-2022-27255 CVE-2022-27255:** 1

### Commands Attempted by Attackers

- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 57
- **lockr -ia .ssh:** 57
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 57
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 56
- **ls -lh $(which ls):** 56
- **which ls:** 56
- **crontab -l:** 56
- **w:** 56
- **uname -m:** 56
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 56
- **top:** 56
- **uname:** 56
- **uname -a:** 56
- **whoami:** 56
- **lscpu | grep Model:** 56
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 50
- **cat /proc/cpuinfo | grep name | wc -l:** 55
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 55
- **Enter new UNIX password: :** 52
- **Enter new UNIX password::** 52
- **uname -s -v -n -r -m:** 7

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1:** 697
- **2402000:** 697
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 264
- **2023753:** 264
- **ET SCAN NMAP -sS window 1024:** 158
- **2009582:** 158
- **ET HUNTING RDP Authentication Bypass Attempt:** 125
- **2034857:** 125
- **ET INFO Reserved Internal IP Traffic:** 56
- **2002752:** 56
- **ET SCAN Potential SSH Scan:** 41
- **2001219:** 41
- **ET SCAN Suspicious inbound to Oracle SQL port 1521:** 32
- **2010936:** 32
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46:** 16
- **2403345:** 16
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 23
- **2403347:** 23
- **ET CINS Active Threat Intelligence Poor Reputation IP group 42:** 28
- **2403341:** 28
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 20
- **2403343:** 20
- **ET INFO CURL User Agent:** 15
- **2002824:** 15

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 55
- **shane/shane:** 6
- **root/asdf1234:** 6
- **user/1:** 8
- **config/config2012:** 6
- **Test/test:** 6
- **admin/Iberia1234***: 6
- **ubnt/ubnt2008:** 5
- **rajesh/123:** 5
- **root/dc1f4h8:** 4
- **jona/jona:** 4
- **root/gaurav:** 4
- **root/Kumar@123:** 4
- **server/server123:** 4
- **root/dewsdews:** 4
- **scan/scan:** 4
- **mark/mark:** 4
- **zhangsan/3245gs5662d34:** 4
- **root/ABC-xmenx159:** 4
- **Admin/0000000:** 4
- **root/PassAdmin12346:** 4
- **root/OnlyUs1029:** 4

### Files Uploaded/Downloaded

- **Mozi.a+jaws:** 5
- **arm.urbotnetisass;**: 2
- **arm.urbotnetisass:** 2
- **arm5.urbotnetisass;**: 2
- **arm5.urbotnetisass:** 2
- **arm6.urbotnetisass;**: 2
- **arm6.urbotnetisass:** 2
- **arm7.urbotnetisass;**: 2
- **arm7.urbotnetisass:** 2
- **x86_32.urbotnetisass;**: 2
- **x86_32.urbotnetisass:** 2
- **mips.urbotnetisass;**: 2
- **mips.urbotnetisass:** 2
- **mipsel.urbotnetisass;**: 2
- **mipsel.urbotnetisass:** 2
- **&currentsetting.htm=1:** 1

### HTTP User-Agents

No HTTP user-agents were recorded in the logs.

### SSH Clients and Servers

No specific SSH client or server versions were recorded in the logs.

### Top Attacker AS Organizations

No attacker AS organization data was available in the logs.

## Key Observations and Anomalies

- **High Volume of Automated Attacks:** The sheer volume of events and the repetitive nature of commands and login attempts suggest that the majority of these attacks are automated, likely from botnets.
- **Focus on IoT/Embedded Devices:** The downloading of files with names like `arm.urbotnetisass`, `mips.urbotnetisass`, etc., indicates a focus on compromising IoT and embedded devices with different architectures.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, which is characteristic of credential stuffing attacks. The pair `345gs5662d34/345gs5662d34` was particularly common.
- **Persistent Access Attempts:** The repeated use of commands to modify the `.ssh/authorized_keys` file shows a clear intent to establish persistent, key-based access to the compromised systems.
