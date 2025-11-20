# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T18:01:39Z
**Timeframe:** 2025-10-19T17:20:01Z to 2025-10-19T18:00:01Z
**Files Used:** `agg_log_20251019T172001Z.json`, `agg_log_20251019T174002Z.json`, `agg_log_20251019T180001Z.json`

## Executive Summary

This report summarizes 20,796 events collected from the T-Pot honeypot network. The primary activity involved reconnaissance and exploitation attempts targeting various services. The most active honeypots were Cowrie, Honeytrap, and Dionaea, indicating a high volume of SSH, web, and SMB probes. The most frequent attacks originated from IP addresses `198.23.238.154` and `80.246.81.187`.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6,426
- **Honeytrap:** 6,211
- **Dionaea:** 2,615
- **Suricata:** 2,337
- **Sentrypeer:** 2,194
- **Ciscoasa:** 742
- **Mailoney:** 93
- **H0neytr4p:** 54
- **Tanner:** 43
- **ElasticPot:** 29
- **ConPot:** 23
- **Redishoneypot:** 12
- **Honeyaml:** 7
- **Heralding:** 4
- **Adbhoney:** 3
- **Ipphoney:** 3

### Top Attacking IPs
- `198.23.238.154`
- `80.246.81.187`
- `72.146.232.13`
- `198.23.190.58`
- `23.94.26.58`
- `47.253.227.124`
- `198.12.68.114`
- `77.83.240.70`
- `68.233.116.124`
- `14.116.156.100`

### Top Targeted Ports/Protocols
- `5038`
- `445`
- `5060`
- `22`
- `UDP/5060`
- `5903`
- `8333`
- `5901`

### Most Common CVEs
- `CVE-2005-4050`
- `CVE-2002-0013 CVE-2002-0012`
- `CVE-2021-3449 CVE-2021-3449`
- `CVE-2019-11500 CVE-2019-11500`

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`

### Signatures Triggered
- `ET VOIP MultiTech SIP UDP Overflow`
- `2003237`
- `ET DROP Dshield Block Listed Source group 1`
- `2402000`
- `ET SCAN NMAP -sS window 1024`

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`
- `user01/Password01`
- `deploy/123123`
- `nobody/8`
- `config/config2025`

### Files Uploaded/Downloaded
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

### HTTP User-Agents
- No user agents recorded.

### SSH Clients and Servers
- No specific SSH clients or servers recorded.

### Top Attacker AS Organizations
- No AS organization data recorded.

## Key Observations and Anomalies

- A significant number of attacks are automated, focusing on known vulnerabilities and default credentials.
- The `urbotnetisass` malware was downloaded, indicating a campaign targeting IoT devices.
- The high number of events on port `5038` (Asterisk) and `5060` (SIP) suggests a focus on VoIP-related services.
- Attackers frequently attempted to install their own SSH keys for persistent access.
- There is a noticeable overlap in the top attacking IPs across the different log files, indicating persistent threat actors.
