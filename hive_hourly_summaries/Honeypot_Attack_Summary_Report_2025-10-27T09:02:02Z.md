# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T09:01:35Z
**Timeframe of Analysis:** 2025-10-27T08:20:01Z to 2025-10-27T09:00:01Z
**Log Files Analyzed:**
- agg_log_20251027T082001Z.json
- agg_log_20251027T084001Z.json
- agg_log_20251027T090001Z.json

## Executive Summary

This report summarizes 18,216 malicious activities recorded by the honeypot network. The primary vectors of attack were network scanning and exploitation attempts targeting VOIP services and Windows SMB. A significant number of brute-force attempts were observed against SSH services. The most prominent attack sources originated from a diverse set of IP addresses, with a notable concentration from a few specific actors.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 4,133
- **Suricata:** 3,860
- **Sentrypeer:** 3,040
- **Honeytrap:** 2,662
- **Ciscoasa:** 1,900
- **Dionaea:** 448
- **Miniprint:** 343
- **Adbhoney:** 333
- **H0neytr4p:** 240
- **Mailoney:** 128
- **ConPot:** 28
- **ElasticPot:** 23
- **Tanner:** 28
- **Redishoneypot:** 32
- **Honeyaml:** 11
- **Dicompot:** 6
- **Ipphoney:** 1

### Top Attacking IPs

- **198.23.190.58:** 2,272
- **139.87.112.100:** 1,435
- **103.79.156.42:** 1,314
- **144.172.108.231:** 1,095
- **134.199.205.99:** 481
- **209.38.98.72:** 505
- **185.243.5.158:** 401
- **197.5.145.102:** 367
- **110.49.3.18:** 334
- **107.170.36.5:** 254

### Top Targeted Ports/Protocols

- **5060:** 3,040
- **TCP/445:** 1,310
- **445:** 409
- **UDP/5060:** 758
- **22:** 642
- **9100:** 343
- **25:** 128
- **23:** 118
- **5901:** 160
- **5903:** 135

### Most Common CVEs

- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449
- CVE-2025-34036
- CVE-2021-35394
- CVE-2017-3506
- CVE-2017-3606
- CVE-2019-16920
- CVE-2021-35395
- CVE-2016-20017
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-47565
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-42013
- CVE-2018-7600

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `uname -a`
- `whoami`

### Signatures Triggered

- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766):** 1,308
- **ET VOIP MultiTech SIP UDP Overflow (2003237):** 756
- **ET DROP Dshield Block Listed Source group 1 (2402000):** 468
- **ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753):** 282
- **ET SCAN NMAP -sS window 1024 (2009582):** 183
- **ET HUNTING RDP Authentication Bypass Attempt (2034857):** 100
- **ET INFO Reserved Internal IP Traffic (2002752):** 60

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 16
- **root/infopasa2014:** 4
- **root/InformEtiqa:** 4
- **root/ingadmin2014:** 4
- **root/infoprof:** 4
- **user/3245gs5662d34:** 4
- **jla/xurros22$:** 3
- **bash/Drag1823hcacatcuciocolataABC111:** 4
- **ubuntu/tizi@123:** 4
- **root/gay:** 2
- **root/fa:** 2
- **root/Aa111111.:** 2
- **root/dreambox:** 2

### Files Uploaded/Downloaded

- **rondo.dtm.sh||busybox:** 4
- **rondo.dtm.sh||curl:** 4
- **rondo.dtm.sh)|sh:** 4
- **rondo.xcw.sh||busybox:** 3
- **rondo.xcw.sh||curl:** 3
- **string>:** 3
- **server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=:** 3
- **rondo.dgx.sh||busybox:** 3
- **rondo.dgx.sh||curl:** 3
- **rondo.dgx.sh)|sh&:** 3
- **json:** 2
- **lol.sh;**: 2

### HTTP User-Agents
- No user agents were logged during this period.

### SSH Clients and Servers
- No specific SSH client or server versions were logged during this period.

### Top Attacker AS Organizations
- No AS organization data was available in the logs for this period.

## Key Observations and Anomalies

- **High Volume of VOIP Attacks:** A significant portion of the traffic targeted SIP ports (5060), primarily with overflow attempts related to CVE-2005-4050. This indicates a widespread, automated campaign against VOIP infrastructure.
- **Persistent SMB Exploitation:** The "DoublePulsar" backdoor signature was triggered over a thousand times, suggesting continued attempts to exploit the EternalBlue vulnerability (MS17-010) on Windows systems.
- **SSH Brute-Force and Payload Delivery:** Attackers were observed attempting to log in with common and default credentials. Successful logins were followed by commands to download and execute malicious shell scripts, as well as attempts to add SSH keys for persistent access. The repeated use of `cd ~ && rm -rf .ssh && ...` is indicative of automated scripts taking over user accounts.
- **Lack of Sophistication:** The majority of attacks appear to be automated and opportunistic, relying on known vulnerabilities and weak credentials rather than advanced techniques.
