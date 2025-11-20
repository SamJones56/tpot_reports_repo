Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T22:01:51Z
**Timeframe:** 2025-10-02T21:20:01Z to 2025-10-02T22:00:01Z
**Files Used:**
- agg_log_20251002T212001Z.json
- agg_log_20251002T214001Z.json
- agg_log_20251002T220001Z.json

### Executive Summary

This report summarizes 10,887 attacks recorded by honeypots over a 40-minute period. The most targeted services were Ciscoasa, Cowrie, and Sentrypeer. A significant portion of attacks originated from IP address 23.175.48.211. Attackers frequently targeted port 5060 and attempted to exploit several vulnerabilities, including CVE-2019-11500 and CVE-2021-3449. Common post-exploitation commands involved reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- **Ciscoasa:** 2701
- **Cowrie:** 2613
- **Sentrypeer:** 1924
- **Suricata:** 1580
- **Mailoney:** 891
- **Tanner:** 491
- **Dionaea:** 270
- **Honeytrap:** 156
- **ConPot:** 68
- **H0neytr4p:** 42
- **ssh-rsa:** 38
- **Honeyaml:** 35
- **Adbhoney:** 31
- **ElasticPot:** 26
- **Miniprint:** 10
- **Redishoneypot:** 9
- **Wordpot:** 1
- **Ipphoney:** 1

**Top Attacking IPs:**
- **23.175.48.211:** 1253
- **45.207.223.64:** 855
- **176.65.141.117:** 820
- **46.105.87.113:** 516
- **92.63.197.55:** 352
- **185.156.73.166:** 350
- **92.63.197.59:** 320
- **138.68.167.183:** 234
- **195.112.111.130:** 163
- **150.95.157.171:** 125

**Top Targeted Ports/Protocols:**
- **5060:** 1924
- **25:** 891
- **80:** 504
- **TCP/80:** 458
- **22:** 434
- **3306:** 163
- **1025:** 60
- **443:** 50
- **445:** 33
- **23:** 32

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2016-6563
- CVE-2006-2369

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `lockr -ia .ssh`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `uname -a`
- `Enter new UNIX password: `
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET INFO Login Credentials Possibly Passed in POST Data
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 49

**Users / Login Attempts:**
- **example/:** 162
- **root/:** 38
- **345gs5662d34/345gs5662d34:** 9
- **root/nPSpP4PBW0:** 6
- **sa/:** 6

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- wget.sh

**HTTP User-Agents:**
- No data recorded.

**SSH Clients and Servers:**
- No data recorded.

**Top Attacker AS Organizations:**
- No data recorded.

### Key Observations and Anomalies

- A large number of attacks targeting Ciscoasa and Cowrie suggest widespread scanning for vulnerabilities in these systems.
- The high volume of attacks from a single IP (23.175.48.211) indicates a targeted campaign.
- The commands attempted by attackers show a clear pattern of establishing SSH persistence and gathering system information.
- The download of multiple `urbotnetisass` files suggests an attempt to install a botnet client on compromised systems.
- The "ET INFO Login Credentials Possibly Passed in POST Data" signature was triggered a large number of times, indicating a focus on web-based credential theft.
