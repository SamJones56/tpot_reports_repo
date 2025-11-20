# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T00:01:24Z
**Timeframe:** 2025-10-07T23:20:01Z to 2025-10-08T00:00:02Z
**Files Used:** `agg_log_20251007T232001Z.json`, `agg_log_20251007T234001Z.json`, `agg_log_20251008T000002Z.json`

## Executive Summary

This report summarizes 9,703 malicious events detected by the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Ciscoasa honeypots. The most frequent attacks originated from IP address `185.255.126.223`. The most targeted port was 5060 (SIP). A number of CVEs were detected, with `CVE-2022-27255` and `CVE-2005-4050` being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
*   **Cowrie:** 3128
*   **Honeytrap:** 2339
*   **Ciscoasa:** 1762
*   **Suricata:** 1500
*   **Sentrypeer:** 718
*   **Dionaea:** 47
*   **Mailoney:** 62
*   **ConPot:** 35
*   **H0neytr4p:** 39
*   **Tanner:** 21
*   **Honeyaml:** 19
*   **Redishoneypot:** 15
*   **Adbhoney:** 11
*   **ElasticPot:** 4
*   **Heralding:** 3

### Top Attacking IPs
*   185.255.126.223
*   198.23.190.58
*   42.54.64.54
*   103.172.112.192
*   109.205.178.177
*   103.2.225.33
*   45.190.24.67
*   14.103.115.25
*   58.48.170.235
*   198.163.206.36

### Top Targeted Ports/Protocols
*   5060
*   22
*   UDP/5060
*   8333
*   23
*   5903
*   25
*   443
*   3333
*   TCP/5432

### Most Common CVEs
*   CVE-2022-27255 CVE-2022-27255
*   CVE-2005-4050
*   CVE-2010-0569
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-2021-35394 CVE-2021-35394

### Commands Attempted by Attackers
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   Enter new UNIX password:
*   uname -a
*   w
*   whoami
*   top
*   crontab -l

### Signatures Triggered
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET SCAN Sipsak SIP scan
*   2008598
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   2024766
*   ET VOIP MultiTech SIP UDP Overflow
*   2003237

### Users / Login Attempts
*   sysadmin/sysadmin@1
*   345gs5662d34/345gs5662d34
*   root/qwertyuiop
*   guest/1234567
*   vpn/password123
*   default/qwerty123
*   default/123123123
*   admin/Abcd1234
*   Root/Root2010
*   ubnt/ubnt1234567890

### Files Uploaded/Downloaded
*   rondo.kqa.sh|sh&echo

### HTTP User-Agents
*   *No user agents recorded in this period.*

### SSH Clients
*   *No SSH clients recorded in this period.*

### SSH Servers
*   *No SSH servers recorded in this period.*

### Top Attacker AS Organizations
*   *No AS organizations recorded in this period.*

## Key Observations and Anomalies

*   **High Volume of SIP Scans:** A significant portion of the traffic targeted SIP services on port 5060, indicating a focus on exploiting VoIP systems.
*   **Repetitive SSH Commands:** The commands executed via SSH are consistent across multiple attacking IPs, suggesting an automated attack script is in use. The commands focus on system reconnaissance and establishing persistent access by adding an SSH key to `authorized_keys`.
*   **Targeting of Realtek SDK:** The repeated triggering of `CVE-2022-27255` suggests that attackers are actively scanning for vulnerable devices using the Realtek eCos RSDK/MSDK.
*   **Dshield Block List Efficacy:** The "ET DROP Dshield Block Listed Source group 1" signature was the most frequently triggered, indicating that many of the attacking IPs are known bad actors.
