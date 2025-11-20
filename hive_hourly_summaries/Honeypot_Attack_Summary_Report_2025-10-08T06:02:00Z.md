# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T06:01:29Z
**Timeframe:** 2025-10-08T05:20:02Z to 2025-10-08T06:00:01Z
**Files Used:**
- agg_log_20251008T052002Z.json
- agg_log_20251008T054001Z.json
- agg_log_20251008T060001Z.json

## Executive Summary

This report summarizes the malicious activities recorded by our honeypot network over the last hour. A total of 20,642 attacks were detected. The majority of these attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force attempts. A significant number of attacks also targeted SMB services, as evidenced by the high count of events on TCP port 445 and the prevalence of the "DoublePulsar Backdoor" signature. Attackers persistently attempted to gain access using common default credentials and execute post-exploitation commands, including modifying SSH authorized_keys.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 9,636
- **Suricata:** 4,412
- **Honeytrap:** 2,691
- **Ciscoasa:** 1,585
- **Dionaea:** 1,054
- **Mailoney:** 881
- **Heralding:** 105
- **H0neytr4p:** 56
- **Sentrypeer:** 67
- **Tanner:** 66
- **Redishoneypot:** 41
- **Honeyaml:** 23
- **Miniprint:** 10
- **ElasticPot:** 5
- **ConPot:** 6
- **Dicompot:** 3
- **Ipphoney:** 1

### Top Attacking IPs

- **196.251.88.103:** 1,990
- **117.240.26.120:** 1,567
- **202.141.244.236:** 1,394
- **86.54.42.238:** 821
- **165.227.174.138:** 683
- **91.192.47.240:** 464
- **172.185.24.228:** 555
- **40.117.97.0:** 475
- **18.229.149.231:** 421
- **103.179.231.3:** 424

### Top Targeted Ports/Protocols

- **TCP/445:** 3,016
- **22:** 1,304
- **445:** 1,000
- **25:** 881
- **8333:** 148
- **TCP/1080:** 109
- **socks5/1080:** 105
- **5903:** 95
- **80:** 76
- **5060:** 67

### Most Common CVEs

- CVE-2005-4050
- CVE-2021-35394
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2002-1149

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `uname -a`
- `whoami`

### Signatures Triggered

- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 3,008
- **2024766:** 3,008
- **ET DROP Dshield Block Listed Source group 1:** 345
- **2402000:** 345
- **ET SCAN NMAP -sS window 1024:** 167
- **2009582:** 167
- **GPL INFO SOCKS Proxy attempt:** 116
- **2100615:** 116
- **ET INFO Reserved Internal IP Traffic:** 62
- **2002752:** 62

### Users / Login Attempts

- **345gs5662d34/345gs5662d34:** 55
- **sysadmin/sysadmin@1:** 16
- **operator/operator55:** 6
- **supervisor/5:** 6
- **operator/asdfgh:** 6
- **operator/Passw0rd:** 6
- **raspberrypi/mymagicpass228:** 6
- **Unknown/22222222:** 6
- **default/alpine:** 5
- **adminuser/adminuser:** 5

### Files Uploaded/Downloaded

- boatnet.mpsl;

### HTTP User-Agents

- None observed.

### SSH Clients and Servers

- **Clients:** None observed.
- **Servers:** None observed.

### Top Attacker AS Organizations

- None observed.

## Key Observations and Anomalies

- The high number of attacks on port 445, combined with the "DoublePulsar" signature, strongly suggests automated worm-like activity attempting to exploit the EternalBlue vulnerability (MS17-010).
- The repeated use of commands to modify SSH `authorized_keys` indicates a clear objective to establish persistent access. The specific SSH key seen in these commands should be considered a compromised asset.
- The variety of honeypots that were triggered (from SSH to Industrial Control Systems like ConPot) shows a broad, untargeted scanning approach by most attackers.
- The `boatnet.mpsl` file download is indicative of attempts to install malware, likely a botnet client, onto compromised systems.
- A significant increase in Mailoney activity was observed in the last 20 minutes of the reporting period, with a focus on port 25 (SMTP). This suggests a shift towards email service exploitation or spam relay attempts.
