# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T13:01:25Z
**Timeframe:** 2025-10-07T12:20:01Z to 2025-10-07T13:01:25Z
**Files Used:**
- agg_log_20251007T122001Z.json
- agg_log_20251007T124001Z.json
- agg_log_20251007T130001Z.json

---

## Executive Summary

This report summarizes 11,215 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. Attackers primarily targeted SSH (port 22) and Telnet (port 23), with a significant number of scans for SIP (port 5060) and email services (port 25). The most frequent attacks originated from IP addresses 86.54.42.238, 113.238.160.137, and 152.32.129.236. Several CVEs were targeted, with CVE-2021-44228 (Log4Shell) being the most common. A large number of automated commands were attempted, indicating botnet activity.

---

## Detailed Analysis

### Attacks by Honeypot

*   **Cowrie:** 6436
*   **Honeytrap:** 2188
*   **Suricata:** 1124
*   **Mailoney:** 875
*   **Sentrypeer:** 453
*   **ConPot:** 29
*   **Honeyaml:** 27
*   **H0neytr4p:** 23
*   **Tanner:** 21
*   **Redishoneypot:** 15
*   **Ciscoasa:** 11
*   **ElasticPot:** 8
*   **Dionaea:** 4
*   **Wordpot:** 1

### Top Attacking IPs

*   **86.54.42.238:** 821
*   **113.238.160.137:** 298
*   **152.32.129.236:** 327
*   **181.212.81.227:** 322
*   **106.57.6.81:** 285
*   **172.86.95.98:** 380
*   **89.144.35.234:** 267
*   **104.248.48.183:** 219
*   **118.193.61.170:** 238
*   **103.23.61.4:** 258
*   **5.56.132.82:** 258
*   **158.174.210.161:** 248

### Top Targeted Ports/Protocols

*   **22:** 816
*   **25:** 875
*   **5060:** 453
*   **23:** 173
*   **8333:** 184
*   **5903:** 94
*   **5038:** 107
*   **TCP/22:** 29
*   **80:** 28
*   **6379:** 12
*   **443:** 13

### Most Common CVEs

*   **CVE-2021-44228:** 24
*   **CVE-2002-0013 CVE-2002-0012:** 9
*   **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 7
*   **CVE-2021-3449:** 3
*   **CVE-1999-0265:** 3
*   **CVE-2019-11500:** 2

### Commands Attempted by Attackers

*   **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 38
*   **lockr -ia .ssh:** 38
*   **cd ~ && rm -rf .ssh && ...:** 38
*   **cat /proc/cpuinfo | grep name | wc -l:** 38
*   **Enter new UNIX password:** 38
*   **free -m | grep Mem | ...:** 38
*   **ls -lh $(which ls):** 38
*   **which ls:** 38
*   **crontab -l:** 38
*   **w:** 38
*   **uname -m:** 38
*   **top:** 38
*   **whoami:** 38

### Signatures Triggered

*   **ET DROP Dshield Block Listed Source group 1:** 338
*   **2402000:** 338
*   **ET SCAN NMAP -sS window 1024:** 142
*   **2009582:** 142
*   **ET INFO Reserved Internal IP Traffic:** 58
*   **2002752:** 58
*   **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 43
*   **2023753:** 43
*   **ET INFO CURL User Agent:** 21
*   **2002824:** 21

### Users / Login Attempts

*   **345gs5662d34/345gs5662d34:** 32
*   **sysadmin/sysadmin@1:** 15
*   **nginx/123123:** 4
*   **odoo/123321:** 4
*   **manager/manager!:** 7
*   **sysadmin/3245gs5662d34:** 4
*   **ubuntu/3245gs5662d34:** 6
*   **mysql/mysql@2025:** 5
*   **vpn/vpn12345:** 5
*   **postgres/postgres123:** 4
*   **ts3server/ts3server@1:** 4

### Files Uploaded/Downloaded

*   **bot.html:** 4
*   **get?src=cl1ckh0use:** 4
*   **discovery:** 2
*   **soap-envelope:** 1
*   **soap-encoding:** 1
*   **addressing:** 1
*   **a:ReplyTo><a:To:** 1
*   **wsdl:** 1

### HTTP User-Agents

*   *No user agents recorded in this period.*

### SSH Clients and Servers

*   *No specific SSH clients or servers recorded in this period.*

### Top Attacker AS Organizations

*   *No AS organization data recorded in this period.*

---

## Key Observations and Anomalies

*   The high number of commands related to modifying the `.ssh` directory and `authorized_keys` file indicates a clear attempt by attackers to establish persistent access.
*   The prevalence of CVE-2021-44228 (Log4Shell) continues to be a significant threat vector.
*   The variety of honeypots that were triggered suggests a broad spectrum of scanning and exploitation techniques are being used by attackers.

---
