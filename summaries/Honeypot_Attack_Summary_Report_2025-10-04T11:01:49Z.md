# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T11:01:23Z
**Timeframe Covered:** 2025-10-04T10:20:01Z to 2025-10-04T11:00:01Z
**Log Files Used:**
- `agg_log_20251004T102001Z.json`
- `agg_log_20251004T104001Z.json`
- `agg_log_20251004T110001Z.json`

## Executive Summary

This report summarizes honeypot activity over the last hour, based on three aggregated log files. A total of 21,330 events were recorded. The most active honeypot was Cowrie, with 6,061 events. The most frequent attacker IP was 45.234.176.18, with 4,721 attempts. The most targeted port was 445/TCP (SMB), with 3,879 events. A number of CVEs were detected, with the most common being CVE-2019-11500, CVE-2021-3449, CVE-2002-0013, CVE-2002-0012 and CVE-2016-5696. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access. The most common signature triggered was "ET DROP Dshield Block Listed Source group 1", indicating that many of the attacks originated from known malicious IPs.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6,061
- **Honeytrap:** 5,480
- **Dionaea:** 3,976
- **Mailoney:** 1,663
- **Suricata:** 1,604
- **Ciscoasa:** 1,588
- **Sentrypeer:** 758
- **Adbhoney:** 72
- **H0neytr4p:** 39
- **ConPot:** 27
- **Redishoneypot:** 18
- **Tanner:** 17
- **Honeyaml:** 14
- **Miniprint:** 5
- **ElasticPot:** 4
- **Medpot:** 4

### Top Attacking IPs
- 45.234.176.18
- 115.124.85.161
- 154.83.15.101
- 86.54.42.238
- 176.65.141.117
- 15.235.131.242
- 78.30.1.201
- 198.23.190.58

### Top Targeted Ports/Protocols
- 445/TCP
- 25/TCP
- 22/TCP
- 5060/UDP

### Most Common CVEs
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012
- CVE-2016-5696
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `Enter new UNIX password:`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic

### Users / Login Attempts
- a2billinguser/
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/LeitboGi0ro

### Files Uploaded/Downloaded
- wget.sh
- w.sh
- c.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies

- A significant amount of scanning activity was observed from a small number of IP addresses, with `45.234.176.18` being responsible for a large portion of the total events.
- The most common commands attempted by attackers were related to establishing persistent SSH access by adding their own public key to the `authorized_keys` file.
- The `urbotnetisass` malware was downloaded multiple times, indicating a coordinated campaign to infect devices.
- The high number of events on port 25/TCP (SMTP) is notable and suggests a large-scale attempt to exploit vulnerable mail servers.
- The "ET DROP Dshield Block Listed Source group 1" signature was the most frequently triggered, which is a positive indication that the honeypot is effectively identifying and blocking known malicious actors.
