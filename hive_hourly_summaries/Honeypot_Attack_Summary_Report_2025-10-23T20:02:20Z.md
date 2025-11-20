# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T20:01:30Z
**Timeframe:** 2025-10-23T19:20:01Z to 2025-10-23T20:00:01Z
**Files Used:**
- `agg_log_20251023T192001Z.json`
- `agg_log_20251023T194001Z.json`
- `agg_log_20251023T200001Z.json`

## Executive Summary

This report summarizes 8,981 attacks recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot. Attackers predominantly targeted SSH (port 22) and SIP (port 5060). A significant number of attacks originated from IP address `147.182.205.88`. Multiple CVEs were targeted, with `CVE-2022-27255` being the most frequent. Attackers attempted various commands, including efforts to modify SSH authorized keys and perform system reconnaissance.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4,108
- **Ciscoasa:** 1,744
- **Honeytrap:** 1,330
- **Suricata:** 940
- **Sentrypeer:** 564
- **Tanner:** 144
- **Dionaea:** 64
- **H0neytr4p:** 41
- **Mailoney:** 15
- **Redishoneypot:** 9
- **ConPot:** 5
- **ElasticPot:** 5
- **Adbhoney:** 4
- **Ipphoney:** 3
- **Heralding:** 3
- **Honeyaml:** 2

### Top Attacking IPs
- `147.182.205.88`: 813
- `198.23.190.58`: 491
- `94.182.174.231`: 355
- `193.32.162.157`: 262
- `161.35.180.71`: 214
- `43.163.103.80`: 215
- `212.233.181.197`: 193
- `85.133.206.110`: 146
- `103.145.145.80`: 189
- `107.170.36.5`: 156
- `185.243.5.146`: 167

### Top Targeted Ports/Protocols
- `22` (SSH): 703
- `5060` (SIP): 564
- `UDP/5060`: 226
- `80` (HTTP): 144
- `2053`: 158
- `8333`: 104
- `5905`: 78
- `5904`: 78
- `445` (SMB): 35
- `TCP/22`: 30
- `23` (Telnet): 23

### Most Common CVEs
- `CVE-2022-27255`: 20
- `CVE-2021-3449`: 5
- `CVE-2019-11500`: 4
- `CVE-2024-4577`: 4
- `CVE-2002-0013`: 2
- `CVE-2002-0012`: 2
- `CVE-2021-41773`: 1
- `CVE-2021-42013`: 1
- `CVE-1999-0517`: 1

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 13
- `lockr -ia .ssh`: 13
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 13
- `cat /proc/cpuinfo | grep name | wc -l`: 13
- `uname -a`: 10
- `Enter new UNIX password: `: 8
- `Enter new UNIX password:`: 8
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 13
- `ls -lh $(which ls)`: 13
- `which ls`: 13
- `crontab -l`: 13
- `w`: 13
- `uname -m`: 13
- `top`: 13
- `uname`: 13
- `whoami`: 13

### Signatures Triggered
- `ET SCAN Sipsak SIP scan`: 200
- `ET DROP Dshield Block Listed Source group 1`: 193
- `ET SCAN NMAP -sS window 1024`: 94
- `ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)`: 44
- `ET INFO Reserved Internal IP Traffic`: 40
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 34
- `ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)`: 20
- `ET SCAN Potential SSH Scan`: 17

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`: 9
- `root/ubnt`: 2
- `root/County`: 2
- `user/user`: 2
- `root/cpgc110177`: 2
- `root/cpsphone`: 2
- `root/Cqx1256tr!`: 2
- `root/Cr!pt0Mund0`: 2
- `postgres/postgres`: 2
- `z/z`: 2
- `shinyproxy/shinyproxy`: 2

### Files Uploaded/Downloaded
- `sh`: 98
- `SOAP-ENV:Envelope>`: 3

### HTTP User-Agents
- No user agents recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH client or server versions recorded in this timeframe.

### Top Attacker AS Organizations
- No AS organization data recorded in this timeframe.

## Key Observations and Anomalies
- The high volume of attacks on SSH (port 22) and SIP (port 5060) suggests widespread scanning and exploitation attempts against these common services.
- The repeated use of commands to modify SSH authorized keys indicates a common tactic to establish persistent access to compromised systems.
- The targeting of `CVE-2022-27255` (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow) is a notable trend in this period.
- The lack of diverse HTTP User-Agents, SSH clients, or AS organization data might indicate that the attacks are coming from a limited set of tools or that this information was not captured by the honeypots.
