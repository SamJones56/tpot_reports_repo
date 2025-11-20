
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T18:01:29Z
**Timeframe:** 2025-10-27T17:20:01Z to 2025-10-27T18:01:29Z

**Files Used to Generate Report:**
- `agg_log_20251027T172001Z.json`
- `agg_log_20251027T174001Z.json`
- `agg_log_20251027T180001Z.json`

## Executive Summary

This report summarizes the honeypot network activity, consolidating data from the three most recent log files. Over the reporting period, a total of 12,318 attacks were recorded. The most targeted services were related to SSH, SIP, and various VNC ports. The majority of attacks originated from IP address `144.172.108.231`. A number of CVEs were targeted, and attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Honeytrap:** 3549
- **Cowrie:** 3470
- **Ciscoasa:** 1971
- **Suricata:** 1638
- **Sentrypeer:** 1188
- **Redishoneypot:** 101
- **Adbhoney:** 50
- **Mailoney:** 105
- **Dionaea:** 50
- **Tanner:** 92
- **H0neytr4p:** 36
- **ElasticPot:** 24
- **ConPot:** 25
- **Honeyaml:** 12
- **Ipphoney:** 7

### Top Attacking IPs
- `144.172.108.231`: 1139
- `128.199.45.217`: 582
- `102.134.17.194`: 326
- `71.70.164.48`: 266
- `156.246.91.141`: 263
- `107.170.36.5`: 251
- `114.220.238.224`: 226
- `186.248.197.77`: 143
- `156.227.27.55`: 124
- `194.107.115.11`: 174
- `88.210.63.16`: 135
- `167.250.224.25`: 130
- `36.50.54.25`: 176
- `77.83.207.203`: 81
- `68.183.149.135`: 110
- `61.76.112.4`: 105
- `68.183.207.213`: 64

### Top Targeted Ports/Protocols
- `5060`: 1188
- `22`: 536
- `5903`: 134
- `TCP/22`: 119
- `5901`: 117
- `80`: 75
- `8333`: 74
- `6379`: 92
- `25`: 105
- `5905`: 78
- `5904`: 77
- `23`: 67
- `5908`: 49
- `5909`: 50
- `5907`: 52
- `9200`: 23
- `TCP/80`: 18
- `TCP/1521`: 16

### Most Common CVEs
- `CVE-2002-0013 CVE-2002-0012`
- `CVE-2021-35394 CVE-2021-35394`
- `CVE-2005-4050`
- `CVE-2021-44228 CVE-2021-44228`
- `CVE-2025-22457 CVE-2025-22457`

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 13
- `lockr -ia .ssh`: 13
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 13
- `cat /proc/cpuinfo | grep name | wc -l`: 13
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 12
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 12
- `ls -lh $(which ls)`: 12
- `which ls`: 12
- `crontab -l`: 12
- `w`: 12
- `uname -m`: 12
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 12
- `top`: 12
- `uname`: 12
- `uname -a`: 15
- `whoami`: 12
- `lscpu | grep Model`: 12
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 12
- `Enter new UNIX password: `: 8
- `Enter new UNIX password:`: 8
- `rm -rf /data/local/tmp/*`: 4

### Signatures Triggered
- `ET DROP Dshield Block Listed Source group 1`: 332
- `2402000`: 332
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`: 249
- `2023753`: 249
- `ET SCAN NMAP -sS window 1024`: 189
- `2009582`: 189
- `ET HUNTING RDP Authentication Bypass Attempt`: 89
- `2034857`: 89
- `ET INFO Reserved Internal IP Traffic`: 60
- `2002752`: 60
- `ET SCAN Potential SSH Scan`: 63
- `2001219`: 63
- `ET CINS Active Threat Intelligence Poor Reputation IP group 48`: 34
- `2403347`: 34

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`: 11
- `root/izba2015legnica`: 4
- `root/j\x7fgar20007`: 4
- `root/j0rg3c3c`: 4
- `root/J1p1j4p4z`: 4
- `root/j2633669`: 4
- `root/vicidial`: 3
- `nick/changeme`: 3
- `root/J0shr27034`: 3
- `root/iysauhk5`: 2
- `root/openmediavault`: 2
- `root/3245gs5662d34`: 4
- `benny/12345`: 2
- `root/!Q2w3e4r`: 2
- `git/git`: 2
- `oracle/oracle`: 2
- `gpadmin/gpadmin123`: 2
- `root/btc`: 2
- `benjamin/test`: 2
- `ubuntu/pa$$w0rd`: 3

### Files Uploaded/Downloaded
- `wget.sh;`: 4
- `arm.uhavenobotsxd;`: 1
- `arm.uhavenobotsxd`: 1
- `arm5.uhavenobotsxd;`: 1
- `arm5.uhavenobotsxd`: 1
- `arm6.uhavenobotsxd;`: 1
- `arm6.uhavenobotsxd`: 1
- `arm7.uhavenobotsxd;`: 1
- `arm7.uhavenobotsxd`: 1
- `x86_32.uhavenobotsxd;`: 1
- `x86_32.uhavenobotsxd`: 1
- `mips.uhavenobotsxd;`: 1
- `mips.uhavenobotsxd`: 1
- `mipsel.uhavenobotsxd;`: 1
- `mipsel.uhavenobotsxd`: 1
- `irannet.mips;`: 1
- `irannet.mipsel;`: 1
- `w.sh;`: 1
- `c.sh;`: 1

### HTTP User-Agents
- No user agents recorded.

### SSH Clients
- No SSH clients recorded.

### SSH Servers
- No SSH servers recorded.

### Top Attacker AS Organizations
- No AS organizations recorded.

## Key Observations and Anomalies

- The high number of attacks from a single IP (`144.172.108.231`) suggests a targeted or persistent attacker.
- The variety of commands attempted indicates that attackers are performing reconnaissance to understand the system architecture and privileges.
- The presence of commands related to SSH key manipulation (`chattr`, `lockr`, adding to `authorized_keys`) is a strong indicator of attempts to establish persistent, passwordless access.
- The downloading and execution of `.sh` and other executable files indicate attempts to install malware or other tools.
- The targeting of CVEs, including older ones, shows that attackers are still exploiting well-known vulnerabilities.

This concludes the Honeypot Attack Summary Report.
