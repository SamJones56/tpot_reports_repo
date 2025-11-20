
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T05:01:33Z
**Timeframe:** 2025-10-14T04:20:01Z to 2025-10-14T05:00:02Z
**Files Used:** 
- agg_log_20251014T042001Z.json
- agg_log_20251014T044001Z.json
- agg_log_20251014T050002Z.json

## Executive Summary

This report summarizes 20,661 attacks recorded across three honeypot log files. The most targeted honeypot was Cowrie, with 6,836 events. The top attacking IP address was 128.199.13.81. The most targeted port was 5060/UDP (SIP). Several CVEs were detected, with CVE-2005-4050 being the most frequent. A significant amount of automated activity was observed, including SSH brute-force attempts and the execution of shell commands to download and execute malware.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 6836
- **Sentrypeer:** 3072
- **Honeytrap:** 2915
- **Dionaea:** 2676
- **Suricata:** 2256
- **Ciscoasa:** 1807
- **Mailoney:** 925
- **Tanner:** 31
- **Honeyaml:** 27
- **H0neytr4p:** 23
- **Redishoneypot:** 18
- **ConPot:** 15
- **Dicompot:** 24
- **Adbhoney:** 14
- **ElasticPot:** 13
- **Miniprint:** 9

### Top Attacking IPs

- **128.199.13.81:** 1245
- **46.32.178.94:** 1256
- **218.255.139.138:** 886
- **86.54.42.238:** 821
- **122.52.159.161:** 920
- **36.229.206.51:** 785
- **42.119.232.181:** 799
- **185.243.5.146:** 1058
- **103.119.179.140:** 523
- **45.236.188.4:** 690
- **185.243.5.148:** 776
- **85.192.63.240:** 287
- **172.86.95.115:** 373
- **172.86.95.98:** 358
- **62.141.43.183:** 324
- **88.210.63.16:** 286
- **101.36.113.241:** 203
- **202.125.94.71:** 194
- **4.213.177.240:** 169
- **198.23.190.58:** 110

### Top Targeted Ports/Protocols

- **5060:** 3072
- **445:** 2546
- **22:** 1187
- **25:** 927
- **TCP/445:** 524
- **5903:** 186
- **8000:** 111
- **23:** 47
- **TCP/1433:** 66
- **1433:** 64
- **UDP/5060:** 66
- **5908:** 81
- **5909:** 84
- **5901:** 75
- **81:** 46
- **5907:** 48
- **TCP/22:** 40

### Most Common CVEs

- **CVE-2005-4050:** 66
- **CVE-2019-11500 CVE-2019-11500:** 6
- **CVE-2021-3449 CVE-2021-3449:** 3
- **CVE-1999-0183:** 1
- **CVE-2002-0013 CVE-2002-0012:** 1

### Commands Attempted by Attackers

- **uname -s -v -n -r -m:** 6
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 13
- **lockr -ia .ssh:** 13
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...":** 13
- **cat /proc/cpuinfo | grep name | wc -l:** 13
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 13
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 13
- **ls -lh $(which ls):** 13
- **which ls:** 13
- **crontab -l:** 13
- **w:** 13
- **uname -m:** 13
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 13
- **top:** 13
- **uname:** 13
- **uname -a:** 12
- **whoami:** 12
- **lscpu | grep Model:** 12
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 12
- **Enter new UNIX password:** 8
- **Enter new UNIX password: :** 8

### Signatures Triggered

- **ET DROP Dshield Block Listed Source group 1:** 503
- **2402000:** 503
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 517
- **2024766:** 517
- **ET SCAN NMAP -sS window 1024:** 159
- **2009582:** 159
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 172
- **2023753:** 172
- **ET VOIP MultiTech SIP UDP Overflow:** 66
- **2003237:** 66
- **ET SCAN Suspicious inbound to MSSQL port 1433:** 65
- **2010935:** 65
- **ET INFO Reserved Internal IP Traffic:** 57
- **2002752:** 57
- **ET HUNTING RDP Authentication Bypass Attempt:** 72
- **2034857:** 72

### Users / Login Attempts

- **root/333333:** 6
- **345gs5662d34/345gs5662d34:** 12
- **support/alpine:** 7
- **blank/5555:** 6
- **centos/letmein:** 6
- **ubnt/9999999:** 6
- **guest/pass:** 6
- **unknown/unknown2009:** 6
- **root/Password@2025:** 5
- **test/test:** 4
- **default/121212:** 4
- **root/Nbx20x21x:** 4
- **test/77:** 4
- **user/444:** 4
- **root/root2000:** 4
- **root/NBX2020:** 4
- **root/Admin@123:** 4
- **unknown/unknown2015:** 4
- **root/GrupoGH2019:** 4
- **root/STLnbx20x21x:** 4

### Files Uploaded/Downloaded

- **arm.urbotnetisass;**: 3
- **arm.urbotnetisass**: 3
- **arm5.urbotnetisass;**: 3
- **arm5.urbotnetisass**: 3
- **arm6.urbotnetisass;**: 3
- **arm6.urbotnetisass**: 3
- **arm7.urbotnetisass;**: 3
- **arm7.urbotnetisass**: 3
- **x86_32.urbotnetisass;**: 3
- **x86_32.urbotnetisass**: 3
- **mips.urbotnetisass;**: 3
- **mips.urbotnetisass**: 3
- **mipsel.urbotnetisass;**: 3
- **mipsel.urbotnetisass**: 3

### HTTP User-Agents

- (No user agents recorded)

### SSH Clients

- (No SSH clients recorded)

### SSH Servers

- (No SSH servers recorded)

### Top Attacker AS Organizations

- (No AS organizations recorded)

## Key Observations and Anomalies

- A significant number of attacks are automated, indicated by the repetitive use of common usernames and passwords.
- The `urbotnetisass` malware was consistently downloaded across all three time periods, suggesting a coordinated campaign.
- The "DoublePulsar Backdoor" signature was triggered a high number of times, indicating attempts to exploit the EternalBlue vulnerability.
- Attackers are using a variety of commands to profile the system, check for running processes, and attempt to gain further access.
- The high number of SIP (5060) and SMB (445) port scans suggests widespread scanning for vulnerable VoIP and Windows systems.
