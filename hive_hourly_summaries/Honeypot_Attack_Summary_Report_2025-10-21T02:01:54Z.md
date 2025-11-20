# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T02:01:29Z
**Timeframe:** 2025-10-21T01:20:01Z to 2025-10-21T02:00:01Z
**Files Used:**
- agg_log_20251021T012001Z.json
- agg_log_20251021T014002Z.json
- agg_log_20251021T020001Z.json

## Executive Summary
This report summarizes 6,559 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of events were also logged by the Honeytrap and Suricata honeypots. The most frequent attacks originated from the IP address 72.146.232.13. The most targeted port was 22 (SSH). Several CVEs were identified, with CVE-2002-1149 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 3104
- Honeytrap: 2006
- Suricata: 862
- Sentrypeer: 203
- Tanner: 180
- Dionaea: 47
- Mailoney: 38
- Adbhoney: 36
- Redishoneypot: 20
- Miniprint: 19
- Dicompot: 12
- Ciscoasa: 10
- H0neytr4p: 10
- ConPot: 8
- Honeyaml: 4

### Top Attacking IPs
- 72.146.232.13
- 163.5.79.179
- 114.130.85.36
- 165.154.12.20
- 92.191.96.115
- 187.230.125.7
- 185.243.5.158
- 107.170.36.5
- 24.144.124.91
- 103.144.87.192

### Top Targeted Ports/Protocols
- 22
- 5060
- 80
- 8333
- 6000
- 5904
- 5905
- TCP/80
- 25
- 2222

### Most Common CVEs
- CVE-2002-1149
- CVE-2019-11500 CVE-2019-11500
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- Enter new UNIX password
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET INFO CURL User Agent
- 2002824

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- deploy/1234
- root/agi123telecom
- root/admin11
- test/test
- root/agitel
- user01/Password01
- deploy/123123
- root/Qa789456
- john/P@ssw0rd123

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients
- No SSH clients were logged in this timeframe.

### SSH Servers
- No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies
- The high number of attacks on port 22 (SSH) suggests a sustained campaign of brute-force attacks and automated scripts attempting to gain unauthorized access.
- The variety of commands attempted indicates that attackers are not only trying to gain access but also to perform reconnaissance and establish persistence on the compromised systems.
- The presence of commands related to downloading and executing scripts (e.g., using `wget` and `curl`) from external sources is a strong indicator of malware infection attempts.
- The "ET DROP Dshield Block Listed Source group 1" signature was the most frequently triggered, indicating that many of the attacking IPs are known malicious actors.
- The variety of honeypots that were triggered suggests that the attackers are using a wide range of attack vectors, targeting multiple services and protocols.
