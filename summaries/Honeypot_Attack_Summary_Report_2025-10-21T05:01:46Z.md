### Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T05:01:20Z
**Timeframe:** 2025-10-21T04:20:01Z to 2025-10-21T05:00:01Z
**Log Files:**
- `agg_log_20251021T042001Z.json`
- `agg_log_20251021T044001Z.json`
- `agg_log_20251021T050001Z.json`

---

### Executive Summary

Over the past hour, our honeypot network detected a total of **6,297** suspicious events. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap). A significant portion of the attacks originated from a diverse set of IP addresses, with `72.146.232.13` being the most persistent attacker. A number of common vulnerabilities were targeted, including CVE-2024-3721, CVE-2019-11500, CVE-2021-3449, and CVE-2002-0013. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access by adding SSH keys.

---

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 3,981
- **Honeytrap:** 1,282
- **Suricata:** 624
- **Sentrypeer:** 230
- **Dionaea:** 40
- **Tanner:** 46
- **ConPot:** 21
- **Mailoney:** 13
- **Adbhoney:** 10
- **Dicompot:** 9
- **H0neytr4p:** 17
- **Honeyaml:** 14
- **ElasticPot:** 6
- **Redishoneypot:** 2
- **Ciscoasa:** 2

**Top Attacking IPs:**
- 72.146.232.13: 606
- 190.184.222.63: 425
- 85.133.193.72: 426
- 124.223.219.9: 288
- 165.154.170.25: 357
- 128.1.132.137: 317
- 102.218.89.110: 218
- 185.243.5.158: 222
- 213.199.41.2: 154
- 36.88.28.122: 134

**Top Targeted Ports/Protocols:**
- 22: 585
- 5060: 230
- 8333: 128
- 8000: 62
- 5905: 77
- 5904: 75
- 80: 42
- TCP/22: 10
- 445: 22
- 5901: 40
- 5902: 39
- 5903: 37
- 20000: 26

**Most Common CVEs:**
- CVE-2024-3721
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013, CVE-2002-0012

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET Cins Active Threat Intelligence Poor Reputation IP group 97

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/abcABC123!@#
- samsat/samsat123
- user01/Password01
- postgres/1234
- ubuntu/P@ssw0rd1
- root/QWer1234
- justine/justine

**Files Uploaded/Downloaded:**
- None observed.

**HTTP User-Agents:**
- None observed.

**SSH Clients and Servers:**
- **Clients:** None observed.
- **Servers:** None observed.

**Top Attacker AS Organizations:**
- None observed.

---

### Key Observations and Anomalies

- The vast majority of commands are reconnaissance-focused, gathering system information (CPU, memory, OS).
- A recurring pattern is the attempt to add a specific SSH public key to the `authorized_keys` file, indicating a widespread campaign to gain persistent access.
- Attackers frequently use `chattr -ia .ssh` and `lockr -ia .ssh` to ensure they can modify the SSH configuration.
- The most common CVEs targeted are relatively recent, suggesting attackers are actively exploiting new vulnerabilities.
- The high volume of traffic from a small number of IPs suggests either a coordinated campaign or the use of compromised machines for attacks.

This concludes the Honeypot Attack Summary Report.
