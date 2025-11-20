
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T12:01:33Z
**Timeframe:** 2025-10-03T11:20:02Z to 2025-10-03T12:00:02Z
**Files Used:**
- agg_log_20251003T112002Z.json
- agg_log_20251003T114001Z.json
- agg_log_20251003T120002Z.json

---

### Executive Summary

This report summarizes 8,299 attacks recorded across the honeypot network. The most targeted honeypots were Ciscoasa, Cowrie, and Mailoney. A significant portion of attacks originated from IPs `176.65.141.117`, `86.54.42.238`, and `83.40.9.221`. The most targeted ports were port 25 (SMTP), port 445 (SMB), and port 5060 (SIP). Attackers attempted to exploit several vulnerabilities, with a notable number of commands related to SSH key manipulation and system reconnaissance.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Ciscoasa:** 2645
- **Cowrie:** 1786
- **Mailoney:** 1650
- **Suricata:** 976
- **Dionaea:** 684
- **Sentrypeer:** 325
- **Honeytrap:** 79
- **H0neytr4p:** 36
- **Tanner:** 32
- **Redishoneypot:** 29
- **ConPot:** 15
- **Honeyaml:** 20
- **ElasticPot:** 9
- **Adbhoney:** 8
- **Dicompot:** 3
- **Ipphoney:** 2

**Top Attacking IPs:**
- `176.65.141.117`: 820
- `86.54.42.238`: 820
- `83.40.9.221`: 642
- `185.156.73.166`: 379
- `92.63.197.59`: 326
- `92.63.197.55`: 259
- `200.195.162.70`: 192
- `46.105.87.113`: 175
- `152.32.145.111`: 139
- `154.83.15.101`: 124

**Top Targeted Ports/Protocols:**
- `25`: 1648
- `445`: 650
- `5060`: 325
- `22`: 225
- `TCP/8443`: 23
- `TCP/22`: 30
- `80`: 41
- `443`: 38
- `TCP/1433`: 23
- `6379`: 26

**Most Common CVEs:**
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2005-4050
- CVE-2021-41773
- CVE-2021-42013

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 11
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 11
- `lockr -ia .ssh`: 11
- `uname -a`: 11
- `cat /proc/cpuinfo | grep name | wc -l`: 10
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 10
- `ls -lh $(which ls)`: 10
- `which ls`: 10
- `crontab -l`: 10
- `w`: 10
- `uname -m`: 10
- `top`: 10
- `whoami`: 10
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...`: 4

**Signatures Triggered:**
- `ET DROP Dshield Block Listed Source group 1`: 222
- `2402000`: 222
- `ET SCAN NMAP -sS window 1024`: 181
- `2009582`: 181
- `ET INFO Reserved Internal IP Traffic`: 58
- `2002752`: 58
- `ET SCAN Suspicious inbound to PostgreSQL port 5432`: 47
- `2010939`: 47
- `ET DROP Spamhaus DROP Listed Traffic Inbound group 32`: 23
- `2400031`: 23

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`: 9
- `GET / HTTP/1.1/Host: ...`: 4
- `User-Agent: Mozilla/5.0 ...`: 4
- `root/3245gs5662d34`: 4
- `root/Hu123456.`: 3
- `myappuser/myappuser123`: 3
- `foundry/foundry`: 3
- `pi/pi123`: 3
- `admin/8585`: 2
- `deploy/Abcd@1234`: 2

**Files Uploaded/Downloaded:**
- `sh`: 26
- `arm.urbotnetisass`: 4
- `arm5.urbotnetisass`: 4
- `arm6.urbotnetisass`: 4
- `arm7.urbotnetisass`: 4
- `x86_32.urbotnetisass`: 4
- `mips.urbotnetisass`: 4
- `mipsel.urbotnetisass`: 4
- `11`: 5
- `fonts.gstatic.com`: 5
- `css?family=Libre+Franklin...`: 4
- `ie8.css?ver=1.0`: 4
- `html5.js?ver=3.7.3`: 4

**HTTP User-Agents:**
- No user agents were recorded in this timeframe.

**SSH Clients:**
- No SSH clients were recorded in this timeframe.

**SSH Servers:**
- No SSH servers were recorded in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this timeframe.

---

### Key Observations and Anomalies

- **SSH Key Manipulation:** A recurring command pattern involves deleting the existing `.ssh` directory, creating a new one, and inserting a specific public SSH key. This indicates a consistent campaign to maintain persistent access to compromised systems.
- **Malware Download Attempts:** The `adbhoney` and `cowrie` honeypots captured attempts to download and execute malware, specifically variants of `urbotnetisass` for different architectures. This suggests automated attacks targeting IoT or embedded devices.
- **High Volume Scans:** A large number of events were simple scans, particularly from IPs flagged by Dshield and Spamhaus blocklists, indicating widespread, opportunistic scanning activity.
- **Reconnaissance Commands:** Attackers frequently used commands like `uname -a`, `cat /proc/cpuinfo`, and `free -m` to gather system information, likely to tailor further attacks or assess the environment's value.
- **No Advanced Activity:** While there were numerous intrusion attempts, most were automated and did not show signs of advanced, targeted attacks by human operators. The attackers relied on common exploits and default credentials.
