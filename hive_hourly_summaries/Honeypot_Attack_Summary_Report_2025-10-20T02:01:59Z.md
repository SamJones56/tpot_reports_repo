# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T02:01:33Z
**Timeframe Covered:** 2025-10-20T01:20:01Z to 2025-10-20T02:00:01Z
**Log Files Used:**
- agg_log_20251020T012001Z.json
- agg_log_20251020T014002Z.json
- agg_log_20251020T020001Z.json

## Executive Summary

This report summarizes 8,288 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Suricata, and Cowrie honeypots. The most frequent attacks originated from the IP address 210.1.85.163, primarily targeting TCP port 445. A significant number of attacks also came from 45.132.225.225, targeting port 5038. Several CVEs were observed, including CVE-2023-26801, CVE-2002-0013, CVE-2002-0012, and CVE-1999-0517.

## Detailed Analysis

### Attacks by Honeypot

*   **Honeytrap:** 3,114
*   **Suricata:** 2,332
*   **Cowrie:** 2,015
*   **Ciscoasa:** 500
*   **Sentrypeer:** 165
*   **Dionaea:** 25
*   **ElasticPot:** 23
*   **Mailoney:** 22
*   **Redishoneypot:** 21
*   **Miniprint:** 20
*   **ConPot:** 15
*   **Adbhoney:** 12
*   **Tanner:** 9
*   **H0neytr4p:** 8
*   **Dicompot:** 6
*   **Honeyaml:** 1

### Top Attacking IPs

*   210.1.85.163
*   45.132.225.225
*   72.146.232.13
*   194.180.11.80
*   160.25.81.58

### Top Targeted Ports/Protocols

*   TCP/445
*   5038
*   22
*   8333
*   5060

### Most Common CVEs

*   CVE-2023-26801
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

### Commands Attempted by Attackers

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `Enter new UNIX password:`

### Signatures Triggered

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766)
*   ET DROP Dshield Block Listed Source group 1 (2402000)
*   ET SCAN NMAP -sS window 1024 (2009582)
*   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
*   ET INFO Reserved Internal IP Traffic (2002752)

### Users / Login Attempts

*   root/root2003
*   345gs5662d34/345gs5662d34
*   user01/Password01
*   root/94Fbrd3dx8
*   ubuntu/ubuntu

### Files Uploaded/Downloaded

*   wget.sh;
*   w.sh;
*   c.sh;
*   arm.urbotnetisass;
*   json

### HTTP User-Agents
*No user agents were logged in this timeframe.*

### SSH Clients
*No SSH clients were logged in this timeframe.*

### SSH Servers
*No SSH servers were logged in this timeframe.*

### Top Attacker AS Organizations
*No attacker AS organizations were logged in this timeframe.*

## Key Observations and Anomalies

*   A massive number of attacks from `210.1.85.163` were observed, specifically targeting TCP port 445. These triggered the "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature, indicating attempts to exploit the SMBv1 vulnerability.
*   The IP `45.132.225.225` was consistently aggressive, targeting port 5038, which is commonly used for Asterisk's AMI protocol.
*   Attackers attempted to modify the `.ssh/authorized_keys` file to add their own public key, allowing for persistent access.
*   Multiple download attempts of `.sh` and `.urbotnetisass` files were observed, suggesting attempts to install malware or botnet clients.
*   A variety of generic and default credentials were attempted, highlighting the continued prevalence of brute-force attacks against SSH.
