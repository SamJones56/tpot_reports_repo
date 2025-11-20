# Honeypot Attack Summary Report

- **Report Generation Time:** 2025-10-20T20:01:28Z
- **Timeframe:** 2025-10-20T19:20:01Z to 2025-10-20T20:00:01Z
- **Files Used:**
    - `agg_log_20251020T192001Z.json`
    - `agg_log_20251020T194001Z.json`
    - `agg_log_20251020T200001Z.json`

## Executive Summary

This report summarizes 14,997 malicious events detected by the honeypot network. The primary activity observed was from the Cowrie and Honeytrap honeypots, indicating a high volume of SSH and Telnet-based attacks. The most frequent attacker IP was `72.146.232.13`. A significant portion of the traffic targeted SMB (port 445) and SSH (port 22). Several CVEs were targeted, with `CVE-2022-27255` being the most prominent. Attackers were observed attempting to download and execute malicious scripts, notably `wget.sh` and binaries like `arm.urbotnetisass`.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4979
- **Honeytrap:** 5009
- **Suricata:** 2120
- **Dionaea:** 1904
- **Sentrypeer:** 598
- **Mailoney:** 110
- **Adbhoney:** 86
- **ElasticPot:** 33
- **Ciscoasa:** 36
- **Redishoneypot:** 30
- **Tanner:** 34
- **ConPot:** 26
- **H0neytr4p:** 13
- **Ipphoney:** 8
- **Dicompot:** 6
- **Honeyaml:** 5

### Top Attacking IPs
- `72.146.232.13`: 1260
- `89.40.247.135`: 644
- `198.23.190.58`: 506
- `196.203.109.209`: 434
- `165.22.105.153`: 337
- `43.229.78.35`: 314
- `12.189.234.27`: 283
- `107.170.36.5`: 251
- `92.48.105.91`: 300
- `185.243.5.158`: 196
- `103.181.143.99`: 169
- `14.22.89.30`: 157
- `152.32.135.217`: 127
- `130.250.189.166`: 119
- `167.250.224.25`: 120

### Top Targeted Ports/Protocols
- `445`: 1115
- `22`: 933
- `5060`: 598
- `UDP/5060`: 240
- `5903`: 238
- `TCP/21`: 211
- `2001`: 195
- `25`: 110
- `21`: 110
- `23`: 78
- `5901`: 114
- `TCP/80`: 87
- `8333`: 71
- `5905`: 78
- `5904`: 76

### Most Common CVEs
- `CVE-2022-27255`: 39
- `CVE-2019-11500`: 8
- `CVE-2021-3449`: 6
- `CVE-2002-0013 CVE-2002-0012`: 3
- `CVE-2024-12856 CVE-2024-12885`: 1
- `CVE-1999-0183`: 1

### Commands Attempted by Attackers
- `uname -a`: 21
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys`: 18
- `cat /proc/cpuinfo | grep name | wc -l`: 18
- `Enter new UNIX password:`: 17
- `lockr -ia .ssh`: 18
- `top`: 19
- `uname`: 19
- `whoami`: 19
- `lscpu | grep Model`: 19
- `df -h ...`: 19
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 19
- `free -m ...`: 18
- `ls -lh $(which ls)`: 18
- `which ls`: 18
- `crontab -l`: 18
- `w`: 18
- `uname -m`: 18
- `cd /tmp || cd /var/run || ... wget ...`: 6

### Signatures Triggered
- `ET DROP Dshield Block Listed Source group 1`: 374
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 287
- `ET SCAN Sipsak SIP scan`: 198
- `ET SCAN NMAP -sS window 1024`: 185
- `ET FTP FTP PWD command attempt without login`: 106
- `ET FTP FTP CWD command attempt without login`: 105
- `ET HUNTING RDP Authentication Bypass Attempt`: 89
- `ET INFO Reserved Internal IP Traffic`: 58
- `ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)`: 39
- `ET INFO curl User-Agent Outbound`: 31

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`: 16
- `user01/Password01`: 9
- `deploy/123123`: 5
- `root/adminserver2009`: 4
- `root/adminsu`: 4
- `user01/3245gs5662d34`: 4
- `git/git-123`: 3
- `fox/fox`: 3
- `ventas01/ventas01`: 3
- `root/!@#123QWEqwe`: 3
- `root/adminsisnazaret`: 3
- `root/abc.123456`: 3
- `root/Ab1234567`: 3
- `bot3/123`: 3
- `bitnami/bitnami`: 3

### Files Uploaded/Downloaded
- `wget.sh;`: 24
- `arm.urbotnetisass`: 5
- `arm.urbotnetisass;`: 5
- `arm5.urbotnetisass`: 5
- `arm5.urbotnetisass;`: 5
- `arm6.urbotnetisass`: 5
- `arm6.urbotnetisass;`: 5
- `arm7.urbotnetisass`: 5
- `arm7.urbotnetisass;`: 5
- `x86_32.urbotnetisass`: 5
- `x86_32.urbotnetisass;`: 5
- `mips.urbotnetisass`: 5
- `mips.urbotnetisass;`: 5
- `mipsel.urbotnetisass`: 5
- `mipsel.urbotnetisass;`: 5
- `w.sh;`: 6
- `c.sh;`: 6
- `bot;`: 4

### HTTP User-Agents
- No user agents were recorded in this period.

### SSH Clients
- No specific SSH clients were recorded in this period.

### SSH Servers
- No specific SSH servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

1.  **Botnet Activity:** The repeated attempts to download and execute `urbotnetisass` binaries across multiple architectures (ARM, x86, MIPS) from the IP `94.154.35.154` strongly suggests a coordinated botnet campaign targeting a wide range of IoT and embedded devices.
2.  **Credential Stuffing:** The wide variety of usernames and passwords attempted indicates automated credential stuffing attacks, likely using lists of previously compromised credentials.
3.  **Evasion and Persistence:** The common use of commands like `rm -rf .ssh` followed by adding a new authorized SSH key is a clear attempt by attackers to take control of a machine and ensure persistent access while locking out others.
4.  **Targeted Scans:** The high number of Suricata alerts for Dshield blocked IPs and scans for MS Terminal Server and SIP services indicates that attackers are broadly scanning for vulnerable systems before launching more targeted exploits.
