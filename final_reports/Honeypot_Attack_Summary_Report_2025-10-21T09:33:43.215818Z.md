# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T09:33:18.936247Z
**Timeframe:** 2025-10-21T08:33:18.936247Z to 2025-10-21T09:33:18.936247Z

## Executive Summary

This report summarizes the attacks detected by our honeypot network over the past hour. A total of 17,344 attacks were recorded across various honeypots. The majority of these attacks originated from the United States, followed by Ukraine and Canada. The Cowrie honeypot was the most targeted, indicating a high volume of SSH-based attacks. A significant portion of the attacking IPs are known attackers, with a smaller number identified as mass scanners. The most common operating system observed from the attackers was Windows NT kernel.

## Detailed Analysis

### Our IPs

| Honeypot | Private IP      | Public IP        |
|----------|-----------------|------------------|
| hive-us  | 10.128.0.3      | 34.123.129.205   |
| sens-tai | 10.140.0.3      | 104.199.212.115  |
| sens-tel | 10.208.0.3      | 34.165.197.224   |
| sens-dub | 172.31.36.128   | 3.253.97.195     |
| sens-ny  | 10.108.0.2      | 161.35.180.163   |

### Attacks by Honeypot

| Honeypot          | Attack Count |
|-------------------|--------------|
| Cowrie            | 7911         |
| Honeytrap         | 5197         |
| Dionaea           | 3323         |
| Sentrypeer        | 600          |
| Tanner            | 88           |
| Redishoneypot     | 66           |
| Ciscoasa          | 56           |
| Mailoney          | 40           |
| ConPot            | 16           |
| H0neytr4p         | 14           |
| Dicompot          | 9            |
| Honeyaml          | 9            |
| Heralding         | 3            |
| Adbhoney          | 2            |
| ElasticPot        | 1            |

### Top Source Countries

| Country          | Attack Count |
|------------------|--------------|
| United States    | 3546         |
| Ukraine          | 3199         |
| Canada           | 1382         |
| China            | 1288         |
| Italy            | 1214         |
| India            | 862          |
| France           | 816          |
| Germany          | 726          |
| United Kingdom   | 683          |
| Hong Kong        | 553          |

### Top Attacking IP Reputation

| Reputation     | Count |
|----------------|-------|
| known attacker | 9212  |
| mass scanner   | 381   |

### Attacker OS Distribution

| Operating System            | Count  |
|-----------------------------|--------|
| Windows NT kernel           | 106682 |
| Linux 2.2.x-3.x             | 10117  |
| Windows 7 or 8              | 3347   |
| Linux 2.2.x-3.x (barebone)  | 1700   |
| Linux 3.11 and newer        | 1171   |
| Solaris 6                   | 635    |
| Windows NT kernel 5.x       | 397    |
| Linux 3.1-3.10              | 38     |
| Linux 2.2.x-3.x (no timestamps) | 29     |
| Linux 2.4.x                 | 4      |
