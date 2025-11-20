Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T13:01:46Z
**Timeframe:** 2025-10-26T12:20:01Z to 2025-10-26T13:00:01Z
**Files Used:**
- agg_log_20251026T122001Z.json
- agg_log_20251026T124001Z.json
- agg_log_20251026T130001Z.json

**Executive Summary**

This report summarizes 28,528 malicious events recorded across a distributed honeypot network. The primary attack vectors observed were reconnaissance and exploitation attempts against VOIP, SMB, and SSH services. A significant portion of the activity originated from a small number of IP addresses, suggesting targeted campaigns. Attackers were observed attempting to download and execute malicious scripts, as well as attempting to gain further access by adding SSH keys.

**Detailed Analysis**

**Attacks by Honeypot**
- Sentrypeer: 10656
- Cowrie: 5628
- Dionaea: 4447
- Suricata: 3620
- Honeytrap: 2716
- Ciscoasa: 1206
- Mailoney: 77
- Heralding: 67
- Adbhoney: 41
- Dicompot: 28
- H0neytr4p: 16
- Tanner: 9
- Redishoneypot: 6
- Honeyaml: 6
- ConPot: 3
- ElasticPot: 1
- Ipphoney: 1

**Top Attacking IPs**
- 2.57.121.61
- 109.205.211.9
- 91.224.45.33
- 172.188.91.73
- 138.197.43.50
- 62.60.131.18
- 129.226.61.249
- 144.130.11.9
- 41.139.164.134
- 144.172.108.231

**Top Targeted Ports/Protocols**
- 5060
- 445
- 22
- 8333
- 5903
- 3388
- TCP/22
- 25
- 5901
- 5678
- vnc/5900

**Most Common CVEs**
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2025-34036
- CVE-2001-0414

**Commands Attempted by Attackers**
- uname -s -v -n -r -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...
- Enter new UNIX password:

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO VNC Authentication Failure
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper

**Users / Login Attempts**
- root/110682
- root/02041992Ionela%^&
- root/ginn
- 345gs5662d34/345gs5662d34
- test/test
- user2/user123
- bash/Drag1823hcacatcuciocolataABC111
- ubuntu/tizi@123
- jla/xurros22$
- polkadot/polkadot
- uftp/uftp123

**Files Uploaded/Downloaded**
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm.uhavenobotsxd;
- arm.uhavenobotsxd
- arm5.uhavenobotsxd;
- arm5.uhavenobotsxd
- string.js
- perl|perl

**HTTP User-Agents**
- No HTTP User-Agents were logged in this period.

**SSH Clients and Servers**
- No SSH clients or servers were logged in this period.

**Top Attacker AS Organizations**
- No AS organizations were logged in this period.

**Key Observations and Anomalies**

- A large number of attacks are simple, automated probes, particularly for VOIP (port 5060) and SMB (port 445) services.
- The commands attempted by attackers indicate an intent to establish persistent access (e.g., by adding SSH keys) and to gather information about the compromised system (e.g., using `uname`, `lscpu`, `free`).
- Attackers are using `wget` and `curl` to download and execute scripts from remote servers. This is a common tactic for installing malware or cryptocurrency miners.
- The presence of commands like `lockr -ia .ssh` suggests that attackers are attempting to make their modifications to the `.ssh` directory immutable, preventing other attackers from taking control.
- CVEs indicate attempts to exploit older vulnerabilities.
- The lack of HTTP User-Agents, SSH clients, and AS organization data might indicate that the honeypots capturing this information did not see any relevant traffic during this period, or that the logging for these fields is not enabled or configured.
