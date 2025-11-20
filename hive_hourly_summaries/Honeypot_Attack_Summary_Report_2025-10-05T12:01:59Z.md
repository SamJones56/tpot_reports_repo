
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T12:01:30Z
**Timeframe:** 2025-10-05T11:20:01Z to 2025-10-05T12:00:01Z
**Log Files:**
- `agg_log_20251005T112001Z.json`
- `agg_log_20251005T114001Z.json`
- `agg_log_20251005T120001Z.json`

## Executive Summary

This report summarizes 13,910 events collected from the T-Pot honeypot network over a 40-minute interval. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and command injections. The most targeted services were SMTP (Port 25), SMB (Port 445), and SSH (Port 22). A significant number of attacks originated from IP address `148.113.15.67`. The most frequently observed CVE was `CVE-2005-4050`, related to a vulnerability in SIP gateways. Attackers were observed attempting to download and execute malicious shell scripts.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6,898
- **Mailoney:** 1,601
- **Ciscoasa:** 1,490
- **Dionaea:** 1,498
- **Suricata:** 1,381
- **Sentrypeer:** 505
- **Honeytrap:** 367
- **H0neytr4p:** 68
- **Adbhoney:** 29
- **Tanner:** 23
- **ConPot:** 16
- **Honeyaml:** 16
- **ElasticPot:** 10
- **Redishoneypot:** 6
- **Dicompot:** 2

### Top Attacking IPs
- **148.113.15.67:** 1,720
- **45.78.192.92:** 1,244
- **187.237.97.188:** 1,051
- **176.65.141.117:** 820
- **86.54.42.238:** 773
- **89.110.102.210:** 445
- **57.129.70.232:** 454
- **122.185.26.34:** 406
- **185.255.90.146:** 375
- **172.86.95.98:** 293

### Top Targeted Ports/Protocols
- **25:** 1,599
- **445:** 1,459
- **22:** 1,217
- **5060:** 505
- **TCP/5900:** 327
- **UDP/5060:** 120
- **443:** 74
- **TCP/22:** 63
- **80:** 27
- **TCP/8080:** 27

### Most Common CVEs
- **CVE-2005-4050:** 114
- **CVE-2002-0013 CVE-2002-0012:** 12
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 8
- **CVE-2021-35394 CVE-2021-35394:** 1
- **CVE-2021-3449 CVE-2021-3449:** 1
- **CVE-1999-0183:** 1

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `crontab -l`
- `w`
- `top`
- `Enter new UNIX password:`

### Signatures Triggered
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 41:** 340
- **ET DROP Dshield Block Listed Source group 1:** 269
- **ET SCAN NMAP -sS window 1024:** 155
- **ET VOIP MultiTech SIP UDP Overflow:** 114
- **ET INFO Reserved Internal IP Traffic:** 59
- **ET SCAN Potential SSH Scan:** 44
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 28
- **GPL SNMP public access udp:** 6
- **GPL SNMP request udp:** 6

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 18
- **novinhost/novinhost.org:** 12
- **root/LeitboGi0ro:** 8
- **root/nPSpP4PBW0:** 8
- **root/3245gs5662d34:** 7
- **test/zhbjETuyMffoL8F:** 7
- **ubuntu/ubuntu:** 5
- **root/123:** 3
- **root/1:** 3

### Files Uploaded/Downloaded
- `wget.sh;`
- `c.sh;`
- `w.sh;`
- `?format=json`
- `catgirls;`
- `k.php?a=x86_64,7LP14ZUW48XBA257H`

### HTTP User-Agents
- No HTTP user-agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

- **High Volume of Credential Stuffing:** The large number of unique username/password combinations observed in Cowrie logs points to widespread, automated brute-force attacks.
- **Malware Delivery Attempts:** Attackers were observed using `wget` and `curl` to download shell scripts (`w.sh`, `c.sh`, `wget.sh`), a common tactic for establishing persistence or roping the device into a botnet.
- **Targeting of VoIP Services:** The `CVE-2005-4050` and related SIP-based alerts from Suricata indicate that attackers are actively scanning for and attempting to exploit vulnerabilities in VoIP systems.
- **Information Gathering:** A significant number of commands were related to system information gathering (e.g., `uname -a`, `lscpu`, `cat /proc/cpuinfo`), which attackers use to tailor future exploits to the compromised system.
- **SSH Key Manipulation:** Multiple commands focused on deleting existing SSH configurations and adding a new authorized key, a clear attempt to create a persistent backdoor into the system.
