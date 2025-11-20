Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T10:01:33Z
**Timeframe:** 2025-10-12T09:20:01Z to 2025-10-12T10:00:01Z
**Files Used:**
- agg_log_20251012T092001Z.json
- agg_log_20251012T094001Z.json
- agg_log_20251012T100001Z.json

### Executive Summary
This report summarizes 28,651 events collected from the honeypot network. The majority of attacks were captured by the Honeytrap, Cowrie, and Dionaea honeypots. The most prominent attacker IP was 173.239.216.40, primarily targeting port 5038. A significant number of attacks also targeted SMB (port 445). Several CVEs were detected, with CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, primarily focused on system enumeration and establishing persistent access via SSH.

### Detailed Analysis

**Attacks by Honeypot:**
- **Honeytrap:** 10,034
- **Cowrie:** 8,364
- **Dionaea:** 3,585
- **Suricata:** 3,211
- **Ciscoasa:** 1,771
- **Sentrypeer:** 1,358
- **Mailoney:** 96
- **Tanner:** 59
- **H0neytr4p:** 54
- **Redishoneypot:** 28
- **Miniprint:** 27
- **Adbhoney:** 24
- **Honeyaml:** 20
- **ConPot:** 12
- **Dicompot:** 4
- **ssh-rsa:** 2
- **Wordpot:** 2

**Top Attacking IPs:**
- 173.239.216.40
- 39.38.234.133
- 41.111.150.13
- 157.245.101.239
- 45.128.199.212
- 186.118.142.216
- 138.197.43.50

**Top Targeted Ports/Protocols:**
- 5038
- 445
- TCP/445
- 5060
- 22
- 1433
- TCP/21

**Most Common CVEs:**
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2002-1149
- CVE-1999-0183
- CVE-2005-4050

**Commands Attempted by Attackers:**
- `w`
- `uname -m`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Sipsak SIP scan
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET SCAN Potential SSH Scan
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication

**Users / Login Attempts:**
- cron/
- 345gs5662d34/345gs5662d34
- root/55555
- support/support00
- ubnt/ubnt11
- admin/passwd
- root/3245gs5662d34
- game/game123
- root/A123456!

**Files Uploaded/Downloaded:**
- `?format=json`
- `wget.sh`
- `w.sh`
- `c.sh`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

### Key Observations and Anomalies
- The IP address 173.239.216.40 was responsible for a large volume of traffic, consistently targeting port 5038. This suggests a targeted or automated attack against a specific service.
- A significant number of commands are related to establishing a persistent SSH connection by adding a public key to `authorized_keys`.
- The "DoublePulsar Backdoor" signature was triggered a large number of times, indicating attempts to exploit a known SMB vulnerability.
- Attackers are attempting to download and execute malicious shell scripts and binaries for various architectures (ARM, x86, MIPS).
- Login attempts use common and default credentials, indicating brute-force attacks are prevalent.