Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T00:01:32Z
**Timeframe:** 2025-10-25T23:20:01Z to 2025-10-26T00:00:01Z
**Log Files:**
- agg_log_20251025T232001Z.json
- agg_log_20251025T234001Z.json
- agg_log_20251026T000001Z.json

### Executive Summary

This report summarizes 15,224 malicious activities recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Suricata, and Cowrie honeypots. The most prominent attacker IP was 80.94.95.238. A significant portion of the traffic targeted SSH (port 22). Attackers attempted to exploit several vulnerabilities, including older CVEs and more recent ones like CVE-2023-49103. A variety of commands were executed, primarily for reconnaissance and establishing persistent access by adding SSH keys or downloading malware.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 5520
- Suricata: 3800
- Cowrie: 3434
- Ciscoasa: 1854
- Sentrypeer: 256
- Dionaea: 85
- Mailoney: 107
- H0neytr4p: 63
- Tanner: 32
- ConPot: 16
- ssh-rsa: 30
- Adbhoney: 6
- Honeyaml: 6
- ElasticPot: 6
- Redishoneypot: 6
- Dicompot: 3

**Top Attacking IPs:**
- 80.94.95.238: 3598
- 165.232.87.113: 846
- 167.172.36.108: 712
- 205.185.126.121: 209
- 107.170.36.5: 252
- 193.24.211.28: 208
- 103.183.75.239: 207
- 223.197.248.209: 139
- 191.242.105.131: 129
- 77.83.207.203: 142

**Top Targeted Ports/Protocols:**
- 22: 616
- 5060: 256
- 8333: 178
- 5903: 142
- 5901: 116
- TCP/22: 101
- 25: 107
- 5905: 79
- 5904: 78
- 443: 57

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2023-49103
- CVE-1999-0265
- CVE-2005-4050
- CVE-2025-22457

**Commands Attempted by Attackers:**
- Reconnaissance commands (uname, whoami, lscpu, cat /proc/cpuinfo, w)
- Attempts to add SSH keys to `authorized_keys`
- Changing user passwords
- Downloading and executing malware payloads (e.g., urbotnetisass, rondo.dtm.sh)
- File and directory manipulation (cd, rm, mkdir)
- Checking cron jobs (crontab -l)

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET SCAN Potential SSH Scan (2001219)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET CINS Active Threat Intelligence Poor Reputation IP

**Users / Login Attempts:**
- Common usernames such as root, admin, user, guest, pasto, yf, limpa, dr, telecomadmin.
- A mix of default, simple, and complex passwords were attempted.

**Files Uploaded/Downloaded:**
- rondo.dtm.sh
- busybox
- curl
- Mozi.m
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- clean.sh
- setup.sh

**HTTP User-Agents:**
- None recorded.

**SSH Clients and Servers:**
- None recorded.

**Top Attacker AS Organizations:**
- None recorded.

### Key Observations and Anomalies

- **Persistent SSH Key Installation:** A recurring pattern involves attackers attempting to remove existing SSH configurations and install their own public key for persistent access. The specific key `AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr` was frequently used.
- **Malware Delivery:** A notable command sequence involved downloading and executing several variants of a payload named `urbotnetisass` for different architectures (ARM, x86, MIPS). This indicates a sophisticated attempt to infect a wide range of devices.
- **High Volume Scans:** A large number of events are related to scanning activities, particularly for MS Terminal Server on non-standard ports, as evidenced by the top Suricata signature.
