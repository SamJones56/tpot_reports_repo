# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T09:02:20Z
**Timeframe:** 2025-10-11T08:20:01Z - 2025-10-11T09:00:01Z
**Files Used:** agg_log_20251011T082001Z.json, agg_log_20251011T084001Z.json, agg_log_20251011T090001Z.json

## Executive Summary
This report summarizes honeypot network traffic captured over a period of approximately 40 minutes. A total of **18351** attacks were detected across multiple honeypots. The most targeted services were SMB (port 445) and SSH (port 22). The majority of attacks originated from a diverse set of IP addresses, with significant activity from `103.119.147.126`, `210.236.249.126` and `123.255.249.106`. A number of CVEs were targeted, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing persistence. The Suricata and Cowrie honeypots recorded the highest number of events.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5661
- Suricata: 4633
- Honeytrap: 3177
- Dionaea: 1721
- Ciscoasa: 1829
- Mailoney: 852
- Sentrypeer: 293
- Tanner: 58
- H0neytr4p: 44
- Redishoneypot: 39
- Adbhoney: 14
- Honeyaml: 22
- ConPot: 7
- Ipphoney: 1

### Top Attacking IPs
- 103.119.147.126: 1512
- 210.236.249.126: 1244
- 123.255.249.106: 1377
- 124.105.235.52: 673
- 45.64.83.49: 953
- 176.65.141.117: 820
- 195.10.205.242: 510
- 157.230.85.50: 365
- 61.219.181.31: 321
- 216.9.225.39: 247
- 106.13.39.89: 225
- 8.243.64.226: 249
- 203.130.9.37: 233
- 91.237.163.112: 202
- 57.128.173.133: 208
- 125.124.205.207: 165
- 167.250.224.25: 142
- 115.190.94.21: 196
- 103.171.84.217: 124
- 209.141.43.77: 149
- 188.246.224.87: 96
- 36.255.71.151: 149

### Top Targeted Ports/Protocols
- TCP/445: 2882
- 445: 1690
- 22: 827
- 25: 843
- 5060: 293
- 5903: 191
- UDP/5060: 112
- 5908: 84
- 5909: 83
- 5901: 81
- 80: 53
- 443: 37
- TCP/22: 41
- 6379: 31
- 23: 46

### Most Common CVEs
- CVE-2022-27255: 11
- CVE-2021-3449: 3
- CVE-2019-11500: 3
- CVE-2002-0013: 1
- CVE-2002-0012: 1

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 31
- `lockr -ia .ssh`: 31
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 31
- `lscpu | grep Model`: 27
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 27
- `cat /proc/cpuinfo | grep name | wc -l`: 27
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 27
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 27
- `ls -lh $(which ls)`: 26
- `which ls`: 26
- `crontab -l`: 26
- `w`: 26
- `uname -m`: 26
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 26
- `top`: 26
- `uname`: 26
- `uname -a`: 26
- `whoami`: 26
- `Enter new UNIX password: `: 23
- `Enter new UNIX password:`: 23

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2876
- 2024766: 2876
- ET DROP Dshield Block Listed Source group 1: 505
- 2402000: 505
- ET SCAN NMAP -sS window 1024: 161
- 2009582: 161
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 144
- 2023753: 144
- ET SCAN Sipsak SIP scan: 99
- 2008598: 99
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61
- ET HUNTING RDP Authentication Bypass Attempt: 54
- 2034857: 54
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 36
- 2400031: 36
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 21
- 2403346: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- 2403345: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 11
- 2403344: 11
- ET SCAN Potential SSH Scan: 23
- 2001219: 23
- GPL SHELLCODE x86 inc ebx NOOP: 16
- 2101390: 16
- ET SCAN NMAP OS Detection Probe: 16
- 2018489: 16
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 11
- 2010936: 11

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 29
- root/nPSpP4PBW0: 12
- supervisor/supervisor2018: 6
- root/fibranne: 6
- test/1111: 6
- admin/raspberry: 6
- vpn/vpn321: 5
- ubnt/ubnt2: 4
- alex/1234: 4
- root/El@st!xtpl-su2.5: 4
- user/dietpi: 4
- root/articomp: 4
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 7
- root/Future564Minds132: 4
- root/reFEstesp2ch@W: 4
- root/admin1234567: 4
- github/password1: 4
- root/ViTgRaNdSrL14022013: 3
- root/pri@123: 3
- staging/staging!: 3
- root/3245gs5662d34: 3
- amir/P@ssw0rd123: 3
- root/c0nv3rg14: 3
- bitrix/1: 3
- david/david1234: 3
- gitlab-runner/gitlab1: 3
- ansible/ansible@123: 3
- ansible/ansible.123: 3
- dockeruser/dockeruser21: 3
- root/LeitboGi0ro: 5

### Files Uploaded/Downloaded
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3
- 11: 2
- fonts.gstatic.com: 2
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 2
- ie8.css?ver=1.0: 2
- html5.js?ver=3.7.3: 2
- ?format=json: 2

### HTTP User-Agents
- No HTTP User-Agents recorded.

### SSH Clients
- No SSH clients recorded.

### SSH Servers
- No SSH servers recorded.

### Top Attacker AS Organizations
- No AS organizations recorded.

## Key Observations and Anomalies
- **High Volume of SMB Scans:** A significant portion of the traffic was directed at port 445, indicating widespread scanning for SMB vulnerabilities, likely related to exploits like EternalBlue.
- **Persistent SSH Brute-Forcing:** The Cowrie honeypot captured numerous SSH login attempts with common and default credentials, indicating automated brute-force attacks.
- **Payload Delivery Attempts:** There were several attempts to download and execute malicious payloads, as seen in the commands logged by the Cowrie honeypot. The filenames suggest malware targeting IoT devices.
- **CVE Targeting:** Attackers were observed targeting specific CVEs, including CVE-2022-27255, CVE-2021-3449, and CVE-2019-11500.
