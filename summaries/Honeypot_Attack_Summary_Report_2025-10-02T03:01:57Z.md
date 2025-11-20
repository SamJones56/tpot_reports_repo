Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T03:01:25Z
**Timeframe:** 2025-10-02T02:20:01Z to 2025-10-02T03:00:01Z
**Files Used:**
- agg_log_20251002T022001Z.json
- agg_log_20251002T024002Z.json
- agg_log_20251002T030001Z.json

### Executive Summary

This report summarizes 28,872 events collected from our honeypot network over a 40-minute period. The majority of attacks were captured by the Honeytrap, Cowrie, and Dionaea honeypots. The most prominent attacker IP was 45.187.123.146, responsible for a significant portion of the traffic. The most targeted ports were 445 (SMB) and 22 (SSH). Several CVEs were observed, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
*   Honeytrap: 16970
*   Cowrie: 7641
*   Dionaea: 1214
*   Suricata: 1182
*   Mailoney: 852
*   Ciscoasa: 815
*   Adbhoney: 37
*   H0neytr4p: 44
*   Tanner: 30
*   Miniprint: 20
*   Redishoneypot: 16
*   Dicompot: 14
*   ConPot: 12
*   Honeyaml: 12
*   Sentrypeer: 13

**Top Attacking IPs:**
*   45.187.123.146: 14811
*   103.130.215.15: 3054
*   115.79.27.192: 1161
*   176.65.141.117: 820
*   165.227.117.213: 350
*   159.89.166.213: 366
*   101.126.67.255: 315
*   185.156.73.166: 289
*   147.50.227.79: 218
*   92.63.197.55: 279

**Top Targeted Ports/Protocols:**
*   445: 1161
*   22: 1277
*   25: 844
*   8333: 90
*   TCP/1080: 45
*   5901: 52
*   443: 44
*   37777: 37
*   TCP/80: 37
*   UDP/161: 19

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012: 12
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
*   CVE-2021-3449 CVE-2021-3449: 7
*   CVE-2019-11500 CVE-2019-11500: 5
*   CVE-2023-26801 CVE-2023-26801: 1

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 25
*   `lockr -ia .ssh`: 25
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 25
*   `uname -a`: 24
*   `cat /proc/cpuinfo | grep name | wc -l`: 23
*   `w`: 23
*   `whoami`: 23
*   `Enter new UNIX password: `: 13
*   `Enter new UNIX password:`: 13
*   `tftp; wget; /bin/busybox PVHKK`: 1

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1: 350
*   ET SCAN NMAP -sS window 1024: 149
*   ET INFO Reserved Internal IP Traffic: 48
*   GPL INFO SOCKS Proxy attempt: 43
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 30
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 25
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 21
*   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 19
*   ET CINS Active Threat Intelligence Poor Reputation IP group 41: 18
*   ET INFO CURL User Agent: 12

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34: 23
*   root/3245gs5662d34: 10
*   seekcy/Joysuch@Locate2020: 7
*   seekcy/Joysuch@Locate2021: 5
*   root/nPSpP4PBW0: 5
*   root/Ahgf3487@rtjhskl854hd47893@#a4nC: 5
*   seekcy/Joysuch@Locate2022: 5
*   root/Aa112211.: 4
*   seekcy/Joysuch@Locate2024: 3
*   root/zhbjETuyMffoL8F: 3

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass: 5
*   arm5.urbotnetisass: 5
*   arm6.urbotnetisass: 5
*   arm7.urbotnetisass: 5
*   x86_32.urbotnetisass: 5
*   mips.urbotnetisass: 5
*   mipsel.urbotnetisass: 5
*   skyljne.mpsl;: 3

**HTTP User-Agents:**
*   (No user agents recorded in this period)

**SSH Clients and Servers:**
*   (No specific clients or servers recorded in this period)

**Top Attacker AS Organizations:**
*   (No AS organizations recorded in this period)

### Key Observations and Anomalies

*   The IP address 45.187.123.146 was responsible for an overwhelming majority of the observed events, indicating a targeted or persistent attacker.
*   The commands executed suggest a focus on disabling security measures (`chattr -ia`), establishing SSH key-based persistence, and gathering system information.
*   The downloading and execution of `urbotnetisass` binaries across multiple architectures (ARM, x86, MIPS) suggests a botnet propagation attempt.
*   The frequent triggering of "Dshield Block Listed Source" and "Spamhaus DROP" signatures indicates that many of the attacking IPs are known malicious actors.
*   The presence of CVEs from as early as 1999 and 2002 suggests that attackers are still attempting to exploit old, well-known vulnerabilities.

This report provides a snapshot of the threat landscape as seen by our honeypots. Continuous monitoring is recommended to track the evolution of these and other attack campaigns.
