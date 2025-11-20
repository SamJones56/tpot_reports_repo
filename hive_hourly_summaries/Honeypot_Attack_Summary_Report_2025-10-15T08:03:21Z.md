
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T08:02:32Z
**Timeframe:** 2025-10-15T07:20:01Z to 2025-10-15T08:00:01Z
**Log Files:** agg_log_20251015T072001Z.json, agg_log_20251015T074001Z.json, agg_log_20251015T080001Z.json

## Executive Summary

This report summarizes 21862 events collected from the honeypot network over the last hour. The majority of attacks were detected by the Suricata, Cowrie, and Honeytrap honeypots. A significant number of attacks originated from IP addresses 185.243.5.121 and 111.2.19.63. The most targeted ports were 5060 (SIP) and 445 (SMB). Several commands were executed on the honeypots, including attempts to download and execute malicious files. The CVEs CVE-2009-2765, CVE-2002-0013, and CVE-2002-0012 were detected.

## Detailed Analysis

### Attacks by Honeypot
*   Suricata: 4699
*   Cowrie: 5124
*   Honeytrap: 4760
*   Sentrypeer: 3126
*   Ciscoasa: 1793
*   Mailoney: 1689
*   Heralding: 428
*   Dionaea: 109
*   H0neytr4p: 66
*   Redishoneypot: 20
*   Tanner: 21
*   ElasticPot: 10
*   Adbhoney: 7
*   ConPot: 3
*   Honeyaml: 7

### Top Attacking IPs
*   185.243.5.121: 1855
*   111.2.19.63: 1429
*   206.191.154.180: 1319
*   154.72.93.170: 1248
*   125.16.9.181: 1345
*   86.54.42.238: 822
*   176.65.141.119: 821
*   8.222.241.140: 646
*   172.86.95.115: 455
*   172.86.95.98: 454

### Top Targeted Ports/Protocols
*   5060: 3126
*   TCP/445: 2794
*   22: 871
*   25: 1689
*   5903: 189
*   1494: 156
*   8333: 140
*   5908: 85
*   5909: 84
*   UDP/5060: 82

### Most Common CVEs
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2009-2765

### Commands Attempted by Attackers
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 11
*   lockr -ia .ssh: 11
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 11
*   cat /proc/cpuinfo | grep name | wc -l: 11
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 11
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 11
*   ls -lh $(which ls): 11
*   which ls: 11
*   crontab -l: 11
*   w: 11

### Signatures Triggered
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2788
*   2024766: 2788
*   ET DROP Dshield Block Listed Source group 1: 498
*   2402000: 498
*   ET SCAN NMAP -sS window 1024: 162
*   2009582: 162
*   ET INFO VNC Authentication Failure: 337
*   2002920: 337
*   ET INFO Reserved Internal IP Traffic: 58
*   2002752: 58

### Users / Login Attempts
*   /maryland: 10
*   /1234: 10
*   /1988: 10
*   /pass: 10
*   /user: 10
*   sa/000000: 10
*   root/123@@@: 10
*   /default: 9
*   345gs5662d34/345gs5662d34: 8
*   root/Password@2025: 7

### Files Uploaded/Downloaded
*   Mozi.m: 1
*   arm.urbotnetisass;: 1
*   arm.urbotnetisass: 1
*   arm5.urbotnetisass;: 1
*   arm5.urbotnetisass: 1
*   arm6.urbotnetisass;: 1
*   arm6.urbotnetisass: 1
*   arm7.urbotnetisass;: 1
*   arm7.urbotnetisass: 1
*   x86_32.urbotnetisass;: 1

### HTTP User-Agents
*   No HTTP User-Agents were logged in this timeframe.

### SSH Clients and Servers
*   No SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
*   No Attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

*   The high number of events related to the "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" signature suggests a targeted campaign against SMB services.
*   The commands executed by attackers indicate attempts to disable security measures (`chattr -ia .ssh`), add SSH keys for persistence, and gather system information.
*   The variety of usernames and passwords attempted shows a brute-force approach against common services like SSH and Telnet.
*   A significant amount of SIP (port 5060) scanning activity was observed, likely searching for vulnerable VoIP systems.
