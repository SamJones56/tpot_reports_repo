# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T01:01:25Z
**Timeframe:** 2025-10-20T00:20:01Z to 2025-10-20T01:00:01Z
**Files:** `agg_log_20251020T002001Z.json`, `agg_log_20251020T004001Z.json`, `agg_log_20251020T010001Z.json`

## Executive Summary

This report summarizes 5,841 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most frequently targeted ports were 445 (SMB) and 22 (SSH). A significant number of attacks originated from the IP address 72.146.232.13. Attackers attempted a variety of commands, including reconnaissance and attempts to install malware.

## Detailed Analysis

### Attacks by Honeypot
*   Cowrie: 2098
*   Honeytrap: 1540
*   Suricata: 783
*   Dionaea: 600
*   Ciscoasa: 596
*   Sentrypeer: 123
*   Redishoneypot: 34
*   Mailoney: 19
*   H0neytr4p: 18
*   Tanner: 16
*   Adbhoney: 13
*   Wordpot: 1

### Top Attacking IPs
*   72.146.232.13
*   89.40.247.135
*   193.32.162.157
*   63.41.9.210
*   107.170.36.5
*   198.23.190.58

### Top Targeted Ports/Protocols
*   445
*   22
*   8333
*   5060
*   1980

### Most Common CVEs
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2002-0013 CVE-2002-0012

### Commands Attempted by Attackers
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh`
*   `cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps\n`
*   `curl2`
*   `uname -s -m`

### Signatures Triggered
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET SCAN Sipsak SIP scan
*   ET SCAN Suspicious inbound to MSSQL port 1433

### Users / Login Attempts
A wide variety of usernames and passwords were attempted, with no single credential pair being overwhelmingly favored. Common usernames included "root", "admin", "sa", and "user".

### Files Uploaded/Downloaded
*   `arm.urbotnetisass`
*   `arm5.urbotnetisass`
*   `arm6.urbotnetisass`
*   `arm7.urbotnetisass`
*   `x86_32.urbotnetisass`
*   `mips.urbotnetisass`
*   `mipsel.urbotnetisass`

### HTTP User-Agents
*   No HTTP user agents were recorded in this period.

### SSH Clients and Servers
*   No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
*   No attacker AS organizations were identified in this period.

## Key Observations and Anomalies

*   **Malware Download Attempts:** The downloaded files with the `.urbotnetisass` extension suggest a coordinated campaign to install a specific botnet or malware variant.
*   **Reconnaissance and Information Gathering:** Commands like `cat /proc/cpuinfo`, `uname -a`, and `lscpu` indicate that attackers are performing reconnaissance to understand the system architecture before deploying payloads.
*   **Targeting of Multiple Architectures:** The variety of `urbotnetisass` files (arm, x86, mips) shows an attempt to target a wide range of device architectures.
*   **SSH Key Manipulation:** The commands related to `.ssh` and `authorized_keys` are indicative of attempts to establish persistent access to the compromised machine.
