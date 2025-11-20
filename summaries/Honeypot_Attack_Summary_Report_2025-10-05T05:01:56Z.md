
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T05:01:34Z
**Timeframe:** 2025-10-05T04:20:01Z to 2025-10-05T05:00:01Z
**Files Used:**
- agg_log_20251005T042001Z.json
- agg_log_20251005T044001Z.json
- agg_log_20251005T050001Z.json

## Executive Summary

This report summarizes 12,082 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie and Mailoney honeypots. A significant portion of the activity involved brute-force attempts against SSH (port 22) and SMTP (port 25). Attackers were observed attempting to modify SSH authorized_keys, gather system information, and download malicious scripts. Multiple network scan signatures were triggered, with a high number of events blocked due to originating from IPs on the Dshield blocklist.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 4590
- **Mailoney:** 2491
- **Honeytrap:** 1661
- **Ciscoasa:** 1520
- **Suricata:** 1064
- **Sentrypeer:** 544
- **Dionaea:** 108
- **H0neytr4p:** 44
- **ConPot:** 14
- **Tanner:** 14
- **Adbhoney:** 12
- **Honeyaml:** 9
- **ElasticPot:** 4
- **Redishoneypot:** 6
- **Ipphoney:** 1

### Top Attacking IPs
- 86.54.42.238
- 196.251.88.103
- 170.64.185.131
- 176.65.141.117
- 50.6.225.98
- 172.86.95.98
- 198.12.68.114
- 24.199.100.234
- 216.107.136.92
- 179.40.112.10

### Top Targeted Ports/Protocols
- 25
- 22
- 5060
- 9092
- 27017
- UDP/5060
- 443
- 23
- 10000
- 58000

### Most Common CVEs
- CVE-2005-4050
- CVE-2019-11500
- CVE-2021-3449
- CVE-2001-0414
- CVE-2024-12856
- CVE-2024-12885
- CVE-2018-11776
- CVE-2002-0013
- CVE-2002-0012

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc...mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- uname -s -v -n -r -m
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:
- echo 1 > /dev/null && cat /bin/echo

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- 2403350
- ET SCAN Potential SSH Scan
- 2001219

### Users / Login Attempts
- root/nPSpP4PBW0
- 345gs5662d34/345gs5662d34
- novinhost/novinhost.org
- root/Timtim@123
- debug/debug123
- build/build123
- gitlab-psql/gitlab-psql
- user/111111
- root/QWERTY123
- developer/developer
- jenkins/jenkins

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- 3.253.97.195:8088
- apply.cgi

### HTTP User-Agents
- No user agents were recorded in this period.

### SSH Clients
- No specific SSH clients were recorded in this period.

### SSH Servers
- No specific SSH servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies

1.  **High Volume Mailoney Traffic:** A significant portion of the total events (over 20%) were directed at the Mailoney honeypot, primarily targeting port 25 (SMTP). This indicates a widespread campaign of email server scanning or exploitation attempts.
2.  **SSH Key Manipulation:** A recurring pattern in the Cowrie honeypot logs is the attempt to delete the existing `.ssh` directory and add a specific public SSH key. This is a common tactic for attackers to gain persistent access to a compromised machine.
3.  **System Reconnaissance:** Attackers frequently ran commands like `uname -a`, `cat /proc/cpuinfo`, and `free -m` to gather information about the system's architecture and resources, likely to tailor further attacks or malware.
4.  **Dominance of Blocklisted IPs:** The most frequently triggered Suricata signature was "ET DROP Dshield Block Listed Source group 1," demonstrating the effectiveness of IP-based reputation lists in blocking a large volume of malicious traffic at the network edge.
