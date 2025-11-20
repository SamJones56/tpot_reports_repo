# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T11:01:27Z
**Timeframe:** 2025-10-18T10:20:01Z to 2025-10-18T11:00:01Z
**Files Used:**
- `agg_log_20251018T102001Z.json`
- `agg_log_20251018T104001Z.json`
- `agg_log_20251018T110001Z.json`

## Executive Summary

This report summarizes 11,370 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots. A significant portion of the attacks originated from the IP address `84.237.221.178`, primarily targeting port 445 (SMB). Other notable activity includes SSH brute-force attempts, scans for VNC and SIP services, and exploitation attempts against known vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 2885
- Honeytrap: 2529
- Dionaea: 2142
- Suricata: 1717
- Ciscoasa: 1301
- Sentrypeer: 493
- Mailoney: 93
- Tanner: 53
- H0neytr4p: 45
- Heralding: 42
- Miniprint: 27
- Redishoneypot: 12
- ConPot: 7
- Honeyaml: 7
- Dicompot: 6
- ElasticPot: 6
- Adbhoney: 3
- Ipphoney: 1
- Wordpot: 1

### Top Attacking IPs
- 84.237.221.178
- 72.146.232.13
- 198.23.190.58
- 88.210.63.16
- 107.170.36.5
- 194.147.34.192
- 103.144.3.40
- 40.83.182.122
- 36.50.177.248
- 68.183.149.135

### Top Targeted Ports/Protocols
- 445
- 22
- 5060
- 5903
- UDP/5060
- TCP/5900
- 5901
- 8333

### Most Common CVEs
- CVE-2022-27255
- CVE-2021-3449
- CVE-2019-11500
- CVE-2024-3721
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0183
- CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `system`
- `shell`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET SCAN Sipsak SIP scan
- ET HUNTING RDP Authentication Bypass Attempt
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET INFO VNC Authentication Failure
- ET INFO CURL User Agent
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41

### Users / Login Attempts
- ubnt/p@ssword
- ftpuser/ftppassword
- root/22ju1cy!
- nobody/1q2w3e4r
- root/Qaz123qaz
- root/123@@@
- centos/111111
- sharan/sharan123
- rocky/rocky
- ubnt/ubnt2019
- ander/123
- debian/77
- centos/3333333
- debian/44444
- blank/222222
- 345gs5662d34/345gs5662d34
- root/230786
- root/23203sgb
- /happy
- /4711
- /7895123
- root/
- root/2311gntlpc
- yy/yy123
- donna/123
- admin/112233
- user/777
- nobody/webadmin
- root/33
- root/2351869
- root/wangyu123
- ubuntu/Qwer1234!

### Files Uploaded/Downloaded
- `fonts.gstatic.com`
- `css?family=Libre+Franklin...`
- `ie8.css?ver=1.0`
- `html5.js?ver=3.7.3`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The high volume of traffic from `84.237.221.178` targeting port 445 suggests a large-scale SMB scanning or exploitation campaign.
- A variety of malware, including `urbotnetisass`, was downloaded to the honeypots, indicating that attackers are attempting to build botnets.
- The commands executed on the Cowrie honeypot show attempts to gather system information and establish persistent access by adding SSH keys to `authorized_keys`.
- The Suricata signatures triggered show a mix of scanning activity, exploitation attempts, and traffic from known malicious IP addresses.
- Several CVEs were targeted, with CVE-2022-27255 (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow) being the most frequently exploited.
