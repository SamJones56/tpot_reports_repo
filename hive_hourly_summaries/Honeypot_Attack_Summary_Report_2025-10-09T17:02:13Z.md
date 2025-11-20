Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T17:01:31Z
**Timeframe:** 2025-10-09T16:20:01Z to 2025-10-09T17:00:01Z
**Files Used:**
- agg_log_20251009T162001Z.json
- agg_log_20251009T164001Z.json
- agg_log_20251009T170001Z.json

**Executive Summary**

This report summarizes 15,449 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected by Suricata and Honeytrap. The most prominent attack vector appears to be SSH, with a large number of brute-force attempts and subsequent command executions. A significant number of attacks also targeted SMB services, as evidenced by the high count of events on TCP/445 and the triggering of DoublePulsar-related signatures.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 5888
- Suricata: 3346
- Honeytrap: 2655
- Ciscoasa: 1639
- Dionaea: 340
- Sentrypeer: 452
- Mailoney: 893
- Heralding: 68
- Tanner: 41
- Adbhoney: 20
- ConPot: 34
- H0neytr4p: 30
- Redishoneypot: 11
- Honeyaml: 13
- ElasticPot: 5
- Dicompot: 10
- ssh-ed25519: 2
- Medpot: 1
- Ipphoney: 1

***Top Attacking IPs:***
- 167.250.224.25: 2265
- 113.26.249.50: 1329
- 176.65.141.117: 820
- 80.94.95.238: 757
- 124.235.224.202: 277
- 20.88.55.220: 321
- 1.221.66.66: 219
- 88.210.63.16: 351
- 79.104.0.82: 208
- 103.154.77.2: 242

***Top Targeted Ports/Protocols:***
- TCP/445: 1327
- 22: 923
- 25: 896
- 5060: 452
- 445: 281
- 5903: 204
- vnc/5900: 65
- 8333: 83
- 1050: 117

***Most Common CVEs:***
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2001-0414
- CVE-2018-10562 CVE-2018-10561
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

***Commands Attempted by Attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

***Signatures Triggered:***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN Potential SSH Scan
- 2001219

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34
- centos/centos7
- root/aA123456
- root/1ssabel12345
- support/support12
- admin/Admin@123
- ali/ali!123
- centos/centos8
- linaro/linaro
- support/Password123!
- support/1234

***Files Uploaded/Downloaded:***
- wget.sh;
- gpon80&ipv=0
- w.sh;
- c.sh;
- 1.sh;
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

***HTTP User-Agents:***
- No HTTP user agents were logged in this period.

***SSH Clients and Servers:***
- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations:***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A high volume of SSH-based attacks from a distributed set of IP addresses was observed, with attackers attempting to gain initial access and perform reconnaissance.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...` is a clear indicator of attempts to install persistent backdoors.
- The `DoublePulsar Backdoor` signature suggests exploitation of the EternalBlue vulnerability (MS17-010).
- Several commands are focused on system enumeration, such as gathering CPU and memory information (`/proc/cpuinfo`, `free -m`).
- Attackers are also attempting to download and execute malicious scripts using `wget` and `curl`. One such script is `1.sh` from `194.15.36.146`.
- There is a noticeable amount of scanning for MS Terminal Server on non-standard ports.
- The variety of credentials used in brute-force attacks suggests the use of common password lists.
- It is anomalous that no HTTP User-Agents, SSH clients/servers, or AS organizations were logged, which might indicate a misconfiguration in the logging pipeline or that the attacks did not involve these elements.
