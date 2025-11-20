Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T09:01:52Z
**Timeframe of Analysis:** 2025-10-23T08:20:01Z to 2025-10-23T09:00:01Z
**Log Files Used:**
- agg_log_20251023T082001Z.json
- agg_log_20251023T084002Z.json
- agg_log_20251023T090001Z.json

### Executive Summary
This report summarizes 23,341 malicious events recorded by the T-Pot honeypot network. The majority of attacks were captured by the Honeytrap (7,035), Cowrie (7,008) and Suricata (5,414) honeypots. The most frequent attacks originated from the IP address 109.205.211.9, with a total of 2,296 attempts. The most targeted port was TCP/445, a common target for SMB exploits. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, with a large number of reconnaissance and remote access commands observed.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 7,035
- Cowrie: 7,008
- Suricata: 5,414
- Ciscoasa: 1,748
- Sentrypeer: 1,197
- Dionaea: 765
- Tanner: 80
- H0neytr4p: 23
- Mailoney: 20
- Adbhoney: 14
- ConPot: 9
- Heralding: 9
- Redishoneypot: 9
- Miniprint: 8
- Honeyaml: 2

**Top Attacking IPs:**
- 109.205.211.9: 2,296
- 80.82.34.82: 1,573
- 103.193.178.230: 883
- 203.135.22.130: 641
- 178.128.245.118: 469
- 162.240.109.153: 350
- 198.98.56.227: 320
- 23.94.26.58: 315
- 154.205.129.28: 281
- 197.5.145.73: 271
- 177.75.6.242: 247

**Top Targeted Ports/Protocols:**
- TCP/445: 1,617
- 5060: 1,197
- 22: 973
- 445: 708

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2021-3449 CVE-2021-3449
- CVE-2001-0414

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
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
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/cfegrtc
- root/cg
- root/cgeradm
- root/ch1n
- anon/anon123
- root/chamomilla
- root/Champi0n
- debian/temppwd
- esearch/esearch
- ian/ian123

**Files Uploaded/Downloaded:**
- SOAP-ENV:Envelope>
- )

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No attacker AS organizations recorded.

### Key Observations and Anomalies
- The high number of attacks on port TCP/445, coupled with the "DoublePulsar Backdoor" signature, suggests a continued campaign of SMB worm activity.
- The commands executed by attackers are consistent with reconnaissance and the establishment of persistent access, particularly through the manipulation of SSH keys.
- The variety of honeypots that were triggered indicates a broad spectrum of automated attacks, from simple scanning to more complex exploit attempts.
- The lack of data for HTTP User-Agents, SSH clients/servers and AS organizations may indicate that these fields are not being correctly populated in the logs, or that the attacks are of a nature that does not provide this information. This warrants further investigation.
