# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T17:01:29Z
**Timeframe:** 2025-10-02T16:20:01Z to 2025-10-02T17:00:01Z

**Files Used:**
- agg_log_20251002T162001Z.json
- agg_log_20251002T164001Z.json
- agg_log_20251002T170001Z.json

## Executive Summary

This report summarizes 14,698 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were detected by Suricata, Cowrie, Mailoney, and Ciscoasa honeypots. The most frequent attacks were SMB exploits, SSH brute-force attempts, and SMTP probes. A significant number of commands were executed on the Cowrie honeypot, indicating successful brute-force attacks.

## Detailed Analysis

### Attacks by Honeypot

- **Suricata:** 5374
- **Cowrie:** 4729
- **Mailoney:** 1688
- **Ciscoasa:** 2566
- **Dionaea:** 70
- **Tanner:** 30
- **Honeytrap:** 106
- **ConPot:** 21
- **Dicompot:** 10
- **Redishoneypot:** 16
- **H0neytr4p:** 40
- **Sentrypeer:** 10
- **ElasticPot:** 4
- **Adbhoney:** 11
- **Miniprint:** 15
- **Honeyaml:** 8

### Top Attacking IPs

- **94.54.220.145:** 3122
- **120.211.62.212:** 1315
- **176.65.141.117:** 1640
- **77.221.156.190:** 397
- **103.59.94.223:** 361
- **157.245.241.196:** 352
- **116.193.191.209:** 345
- **185.156.73.166:** 361
- **92.63.197.55:** 350
- **92.63.197.59:** 316
- **103.100.209.195:** 357
- **104.168.117.131:** 288
- **24.144.124.91:** 213
- **210.211.97.226:** 235
- **118.194.230.211:** 172
- **160.251.197.41:** 156
- **152.53.195.199:** 179

### Top Targeted Ports/Protocols

- **TCP/445:** 4425
- **25:** 1688
- **22:** 601
- **443:** 30
- **TCP/1080:** 25
- **80:** 32
- **23:** 24
- **TCP/1433:** 24
- **TCP/3389:** 12
- **6379:** 15
- **2404:** 16
- **TCP/5432:** 13

### Most Common CVEs

- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2001-0414
- CVE-1999-0517

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `top`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

### Signatures Triggered

- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 4419
- **ET DROP Dshield Block Listed Source group 1:** 220
- **ET SCAN NMAP -sS window 1024:** 168
- **ET INFO Reserved Internal IP Traffic:** 55
- **GPL INFO SOCKS Proxy attempt:** 24
- **ET CINS Active Threat Intelligence Poor Reputation IP group 66:** 11
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 32:** 22
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 8
- **ET CINS Active Threat Intelligence Poor Reputation IP group 67:** 18

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 27
- **root/2glehe5t24th1issZs:** 9
- **root/3245gs5662d34:** 8
- **root/Abcdef123456:** 3
- **root/password@2025:** 3
- **root/Root@2021:** 3
- **root/pass!123:** 5
- **jason/1234:** 4
- **admin/@a123456:** 2
- **admin/ftptest1:** 2
- **admin/kk:** 2
- **admin/Abc123++:** 2
- **admin/root10:** 2
- **root/0okm(IJN:** 5
- **root/Admin@123:** 2

### Files Uploaded/Downloaded

- `11`
- `fonts.gstatic.com`
- `css?family=Libre+Franklin...`
- `ie8.css?ver=1.0`
- `html5.js?ver=3.7.3`

### HTTP User-Agents
- No HTTP User-Agents were logged in the provided data.

### SSH Clients and Servers
- No specific SSH client or server versions were logged.

### Top Attacker AS Organizations
- No attacker AS organization data was available in the logs.

## Key Observations and Anomalies

- A large number of attacks are originating from a single IP address, `94.54.220.145`, which is primarily targeting SMB on TCP port 445.
- The commands executed on the Cowrie honeypot are consistent with automated scripts attempting to gather system information and install SSH keys for persistence.
- The DoublePulsar backdoor installation communication is the most frequently triggered signature, indicating widespread and automated exploitation of the EternalBlue vulnerability.
- The variety of usernames and passwords used in brute-force attempts suggests that attackers are using common and default credential lists.
