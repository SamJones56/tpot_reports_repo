Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T02:01:38Z
**Timeframe:** 2025-10-26T01:20:01Z to 2025-10-26T02:00:02Z
**Log Files:**
- agg_log_20251026T012001Z.json
- agg_log_20251026T014001Z.json
- agg_log_20251026T020002Z.json

---

### Executive Summary

This report summarizes 17,758 malicious events recorded across three honeypot log files. The majority of attacks were detected by Suricata IDS, followed by Honeytrap and Cowrie honeypots. The most prominent attacker IP was 109.205.211.9, responsible for a significant volume of traffic. Attacks primarily targeted SMB (port 445) and SSH (port 22). Analysis of payloads revealed numerous attempts to download and execute malicious scripts, modify SSH authorized_keys, and exploit various vulnerabilities, including older CVEs.

---

### Detailed Analysis

**Attacks by Honeypot**
- Suricata: 5387
- Honeytrap: 4940
- Cowrie: 3829
- Dionaea: 1005
- Ciscoasa: 1812
- Tanner: 282
- Sentrypeer: 140
- Mailoney: 148
- H0neytr4p: 66
- Adbhoney: 17
- Dicompot: 12
- ConPot: 11
- Redishoneypot: 10
- ElasticPot: 7
- Miniprint: 39
- Heralding: 6
- Honeyaml: 5

**Top Attacking IPs**
- 109.205.211.9
- 80.94.95.238
- 131.226.213.69
- 178.62.254.40
- 24.232.50.5
- 4.211.84.189
- 87.248.131.80
- 157.66.34.121
- 184.168.29.142
- 107.170.36.5

**Top Targeted Ports/Protocols**
- 445
- 22
- 80
- 8333
- 5060
- 25
- 5903
- 5901
- 443
- 9100

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2018-7600 CVE-2018-7600
- CVE-1999-0183
- CVE-2024-3721 CVE-2024-3721
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2021-35394 CVE-2021-35394

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- uname -a
- whoami

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)

**Users / Login Attempts (user/password)**
- 345gs5662d34/345gs5662d34
- root/Fr33fr0nt
- root/Francois9177
- root/freedom123!
- root/Freedom5647
- root/FraSte2006
- admin/13061993
- admin/13061978
- admin/13051980
- root/freepbx1

**Files Uploaded/Downloaded**
- sh
- rondo.dtm.sh||busybox
- rondo.dtm.sh||curl
- rondo.dtm.sh)|sh
- wget.sh;
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- ohsitsvegawellrip.sh

**HTTP User-Agents**
- N/A

**SSH Clients**
- N/A

**SSH Servers**
- N/A

**Top Attacker AS Organizations**
- N/A

---

### Key Observations and Anomalies

1.  **High Volume Scanning:** The dominant activity was scanning, particularly for RDP on non-standard ports and SMB services, indicated by the high counts for `ET SCAN MS Terminal Server Traffic` and traffic on port 445.
2.  **Repetitive SSH Commands:** A specific set of commands was repeatedly executed by multiple attackers, aimed at reconnaissance (e.g., `uname -a`, `lscpu`) and establishing persistence by adding an SSH key to `authorized_keys`.
3.  **Malware Downloads:** Several attacker sessions involved attempts to download and execute shell scripts and ELF binaries (`.urbotnetisass` files), suggesting automated infection campaigns targeting IoT/embedded devices with various architectures (ARM, x86, MIPS).
4.  **CVE Exploitation:** Attackers attempted to exploit a mix of old and recent vulnerabilities. The presence of attempts against CVEs from 1999 and 2002 alongside those from 2024 indicates that attackers use broad-spectrum scanning tools.
5.  **Data Consistency:** The top attacker IP (109.205.211.9) and the primary attack patterns remained consistent across all three log files, pointing to a persistent, automated campaign.
