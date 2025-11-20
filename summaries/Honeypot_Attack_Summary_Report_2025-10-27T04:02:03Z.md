## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T04:01:46Z
**Timeframe:** 2025-10-27T03:20:02Z to 2025-10-27T04:00:01Z
**Files Used:**
- agg_log_20251027T032002Z.json
- agg_log_20251027T034001Z.json
- agg_log_20251027T040001Z.json

### Executive Summary

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 22,995 events were recorded across various honeypots. The most targeted services were SSH (Cowrie), SIP (Sentrypeer), and network services monitored by Suricata and Honeytrap. A significant portion of the attacks involved attempts to download and execute malicious scripts, as well as reconnaissance activities to gather system information.

### Detailed Analysis

#### Attacks by Honeypot:
- **Cowrie:** 8684
- **Sentrypeer:** 3395
- **Honeytrap:** 2732
- **Suricata:** 2713
- **Dionaea:** 1852
- **Ciscoasa:** 1830
- **Redishoneypot:** 1428
- **Mailoney:** 108
- **ssh-rsa:** 98
- **Adbhoney:** 52
- **Tanner:** 34
- **ElasticPot:** 24
- **H0neytr4p:** 22
- **Honeyaml:** 7
- **ConPot:** 7
- **Ipphoney:** 5
- **Heralding:** 3
- **Wordpot:** 1

#### Top Attacking IPs:
- 198.23.190.58
- 47.180.61.210
- 8.138.186.69
- 144.172.108.231
- 180.232.204.50
- 85.215.236.90
- 94.181.229.254
- 185.243.5.158
- 178.128.80.162
- 185.243.5.148
- 121.125.70.58
- 96.92.63.243
- 162.254.32.88
- 46.20.111.2
- 103.187.147.165
- 189.36.132.232
- 197.5.145.73
- 69.63.77.146

#### Top Targeted Ports/Protocols:
- 5060
- 445
- 6379
- 22
- UDP/5060
- 23
- 25
- 5901
- 5903
- TCP/80

#### Most Common CVEs:
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0517

#### Commands Attempted by Attackers:
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `Enter new UNIX password:`
- `tftp; wget; /bin/busybox ...`

#### Signatures Triggered:
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

#### Users / Login Attempts:
- root/...
- 345gs5662d34/345gs5662d34
- ubuntu/tizi@123
- jla/xurros22$
- bash/Drag1823hcacatcuciocolataABC111
- root/02041992Ionela%^&

#### Files Uploaded/Downloaded:
- wget.sh;
- w.sh;
- c.sh;
- arm.uhavenobotsxd;
- ?format=json

#### HTTP User-Agents:
- No user agents recorded.

#### SSH Clients:
- No SSH clients recorded.

#### SSH Servers:
- No SSH servers recorded.

#### Top Attacker AS Organizations:
- No AS organizations recorded.

### Key Observations and Anomalies

- A high volume of automated attacks targeting SSH and SIP protocols was observed.
- Many attackers attempted to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`), indicating attempts to install malware or establish persistence.
- The commands executed suggest a focus on reconnaissance and disabling security measures (e.g., modifying `.ssh/authorized_keys`, clearing `hosts.deny`).
- The CVEs targeted are relatively old, suggesting that attackers are targeting unpatched or legacy systems.
- The lack of diverse HTTP user-agents, SSH clients, or server versions indicates that many of the attacks are likely automated and not highly sophisticated.
- There is a noticeable overlap in the top attacking IPs across the different time snippets, suggesting persistent actors.
