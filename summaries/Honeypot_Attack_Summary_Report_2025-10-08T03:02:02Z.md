
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T03:01:38Z
**Timeframe:** Approximately 40 minutes of data from 2025-10-08T02:20:02Z to 2025-10-08T03:00:01Z.
**Files Used:**
- agg_log_20251008T022002Z.json
- agg_log_20251008T024001Z.json
- agg_log_20251008T030001Z.json

## Executive Summary

This report summarizes 15,481 recorded attacks across a distributed honeypot network over an approximate 40-minute period. The most engaged honeypots were Dionaea (4,123 events), Honeytrap (3,010 events), and Mailoney (2,517 events). A significant majority of the attacks targeted SMB (port 445) and SMTP (port 25). The IP address `103.6.4.2` was the most prominent attacker, responsible for over 26% of the total traffic, focusing almost exclusively on port 445. Analysis of SSH-based attacks on the Cowrie honeypot reveals a consistent pattern of reconnaissance followed by attempts to install a malicious SSH key for persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Dionaea:** 4,123
- **Honeytrap:** 3,010
- **Mailoney:** 2,517
- **Cowrie:** 2,308
- **Ciscoasa:** 1,660
- **Suricata:** 1,531
- **Miniprint:** 51
- **Sentrypeer:** 47
- **Redishoneypot:** 48
- **Adbhoney:** 36
- **Tanner:** 42
- **Dicompot:** 22
- **H0neytr4p:** 32
- **ElasticPot:** 20
- **ConPot:** 13
- **Honeyaml:** 14
- **Heralding:** 4
- **Ipphoney:** 3

### Top Attacking IPs
- `103.6.4.2`: 4,047
- `86.54.42.238`: 1,641
- `176.65.141.117`: 820
- `66.70.103.183`: 193
- `185.255.91.226`: 183
- `146.56.40.179`: 207
- `45.157.150.160`: 114
- `186.219.133.136`: 114
- `89.152.55.51`: 113
- `45.78.196.188`: 109
- `200.118.99.170`: 104
- `140.106.25.217`: 129
- `140.238.247.199`: 94
- `107.170.36.5`: 98
- `68.183.207.213`: 95

### Top Targeted Ports/Protocols
- `445`: 4,062
- `25`: 2,517
- `22`: 278
- `8333`: 140
- `5903`: 95
- `8086`: 71
- `9100`: 51
- `9092`: 57
- `44818`: 48
- `80`: 38
- `11211`: 37
- `6379`: 30
- `5060`: 47
- `9200`: 19

### Most Common CVEs
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers
Attackers frequently attempted system reconnaissance and tried to establish persistence via SSH.
- **SSH Key Installation:** A common chain involved removing existing `.ssh` directories and adding a new authorized key.
  - `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3N... mdrfckr" >> .ssh/authorized_keys`
- **System Reconnaissance:**
  - `uname -a`
  - `whoami`
  - `w`
  - `crontab -l`
  - `cat /proc/cpuinfo | grep name | wc -l`
  - `free -m | grep Mem`
- **Security Disablement:**
  - `cd ~; chattr -ia .ssh; lockr -ia .ssh`

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 592
- **ET SCAN NMAP -sS window 1024:** 165
- **ET INFO Reserved Internal IP Traffic:** 56
- **GPL INFO SOCKS Proxy attempt:** 28
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 36
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 30
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 23
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 14

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`: 12
- `ubnt/ubnt1234567`: 8
- `admin/admin66`: 6
- `root/root444`: 6
- `default/qwerty123456`: 6
- `operator/121212`: 6
- `admin/admin55`: 6
- `guest/987654321`: 6
- `1/2`: 6
- `anonymous/anonymous`: 6
- `support/a123456`: 6
- `sysadmin/sysadmin@1`: 4

### Files Uploaded/Downloaded
- No file uploads or downloads were recorded during this period.

### HTTP User-Agents
- No significant HTTP user agents were logged.

### SSH Clients and Servers
- No specific SSH client or server versions were identified in the logs.

### Top Attacker AS Organizations
- ASN organization data was not available in the logs.

## Key Observations and Anomalies

1.  **High-Volume Targeted Scans:** The IP `103.6.4.2` was responsible for a disproportionately high volume of traffic (4,047 events), almost entirely focused on port 445 (SMB). This indicates either a very aggressive, targeted scan from a single source or potential IP address spoofing.

2.  **Automated SSH Takeover Scripts:** The command execution patterns observed on the Cowrie honeypot are highly consistent and indicative of automated scripts. Attackers systematically perform reconnaissance, attempt to disable file immutability with `chattr`, remove existing SSH configurations, and then insert their own public key to maintain persistent access.

3.  **Prevalence of Known Bad IPs:** The most frequently triggered Suricata signature was `ET DROP Dshield Block Listed Source group 1`. This confirms that a large portion of the attack traffic originates from IP addresses already identified and blocklisted by the security community, reinforcing the value of threat intelligence feeds.
