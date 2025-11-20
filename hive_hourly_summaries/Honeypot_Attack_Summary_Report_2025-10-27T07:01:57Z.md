Honeypot Attack Summary Report
Report generated on 2024-10-28 10:30:00 UTC, analyzing data from the last 60 minutes.
Files used for this report: agg_log_20251027T062001Z.json, agg_log_20251027T064001Z.json, agg_log_20251027T070002Z.json.

Executive Summary
This report summarizes 24,727 total attacks recorded across multiple honeypots. The majority of attacks were simple probes and automated scans, with a significant number of attempts to exploit VoIP and SMB services. Notably, there were several attempts to deploy SSH backdoors and execute shell scripts to download additional malware. The top attacking IP address was 2.57.121.61, and the most targeted port was 5060/UDP (SIP).

Detailed Analysis:

Attacks by Honeypot:
* Sentrypeer: 11432
* Cowrie: 3695
* Honeytrap: 3908
* Dionaea: 2460
* Suricata: 1766
* Ciscoasa: 1294
* Mailoney: 61
* Tanner: 33
* Adbhoney: 12
* H0neytr4p: 18
* ConPot: 18
* Honeyaml: 18
* Dicompot: 3
* Redishoneypot: 6
* Heralding: 1
* Ipphoney: 1
* ElasticPot: 1

Top Attacking IPs:
* 2.57.121.61: 9262
* 212.30.36.141: 1865
* 198.23.190.58: 1581
* 103.201.143.33: 1467
* 144.172.108.231: 812
* 103.160.232.131: 780
* 134.122.60.171: 570
* 185.243.5.158: 287
* 77.90.185.47: 217
* 27.71.27.54: 174

Top Targeted Ports/Protocols:
* 5060: 11432
* 445: 2428
* 5038: 1893
* 22: 600
* UDP/5060: 537
* 5901: 85
* 5903: 87
* TCP/22: 75
* 25: 61
* 23: 31

Most Common CVEs:
* CVE-2005-4050: 529
* CVE-2002-0013 CVE-2002-0012: 22
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 14
* CVE-2018-10562 CVE-2018-10561: 1
* CVE-2013-7471 CVE-2013-7471: 1

Commands Attempted by Attackers:
* uname -a: 12
* whoami: 12
* top: 12
* w: 12
* uname: 12
* uname -m: 12
* crontab -l: 12
* which ls: 12
* ls -lh $(which ls): 12
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
* cat /proc/cpuinfo | grep name | wc -l: 12
* cat /proc/cpuinfo | grep model | grep name | wc -l: 12
* lscpu | grep Model: 12
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 12
* lockr -ia .ssh: 13
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 13
* cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 13
* rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 5
* Enter new UNIX password: : 4

Signatures Triggered:
* ET VOIP MultiTech SIP UDP Overflow: 529
* ET DROP Dshield Block Listed Source group 1: 301
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 193
* ET SCAN NMAP -sS window 1024: 127
* ET HUNTING RDP Authentication Bypass Attempt: 77
* ET INFO Reserved Internal IP Traffic: 39
* ET SCAN Potential SSH Scan: 38
* ET CINS Active Threat Intelligence Poor Reputation IP group 48: 28
* ET INFO Proxy CONNECT Request: 18
* GPL SNMP request udp: 9

Users / Login Attempts:
* 345gs5662d34/345gs5662d34: 11
* root/3245gs5662d34: 5
* bash/Drag1823hcacatcuciocolataABC111: 5
* ubuntu/tizi@123: 8
* root/02041992Ionela%^&: 7
* jla/xurros22$: 7
* root/imranayaz: 4
* root/Inc: 4
* root/Incentralit2015In: 4

Files Uploaded/Downloaded:
* wget.sh;: 4
* arm.uhavenobotsxd;: 2
* arm.uhavenobotsxd: 2
* arm5.uhavenobotsxd;: 2
* arm5.uhavenobotsxd: 2
* arm6.uhavenobotsxd;: 2
* arm6.uhavenobotsxd: 2
* arm7.uhavenobotsxd;: 2
* arm7.uhavenobotsxd: 2
* x86_32.uhavenobotsxd;: 2
* x86_32.uhavenobotsxd: 2
* mips.uhavenobotsxd;: 2
* mips.uhavenobotsxd: 2
* mipsel.uhavenobotsxd;: 2
* mipsel.uhavenobotsxd: 2
* w.sh;: 1
* c.sh;: 1

HTTP User-Agents:
* No user agents were logged in this period.

SSH Clients and Servers:
* No SSH clients or servers were logged in this period.

Top Attacker AS Organizations:
* No AS organizations were logged in this period.

Key Observations and Anomalies
- A high volume of SIP (VoIP) traffic, specifically targeting CVE-2005-4050, was observed from a small number of IP addresses. This suggests a targeted campaign against VoIP infrastructure.
- Attackers on the Cowrie honeypot consistently attempted to disable SSH security and install a persistent SSH key for backdoor access. This was often followed by system reconnaissance commands.
- Several commands were executed to download and run shell scripts and ELF binaries (e.g., 'uhavenobotsxd'), indicating attempts to install malware for DDoS botnets or cryptomining. These were primarily targeted at Android devices via ADB.
- A significant number of brute-force login attempts were observed against various services, using common and sometimes complex password combinations.
- The majority of attacks are automated and opportunistic, scanning for vulnerable services and executing pre-defined attack scripts.
