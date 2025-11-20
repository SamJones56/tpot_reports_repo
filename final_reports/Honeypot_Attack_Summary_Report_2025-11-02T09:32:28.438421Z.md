## OSINT Investigation Report on Low Attack Count IP Addresses

**Date:** 2023-11-02

### Executive Summary

This report presents the findings of an Open-Source Intelligence (OSINT) investigation into a list of 100 IP addresses, each associated with a single attack count against our honeypot network. The investigation aimed to gather information about the origin, ownership, and reputation of these IP addresses to assess the potential threat they pose.

The investigation revealed that a significant majority of the analyzed IP addresses originate from China and are associated with major Chinese Internet Service Providers (ISPs), particularly CHINANET and CHINA UNICOM. A large number of these IPs are present on one or more blacklists, indicating a history of involvement in malicious activities such as spam, phishing, botnet operations (including the MIRAI botnet), and other forms of cybercrime.

While the attack count from each individual IP was low (a single instance), the concentration of malicious IPs within specific network blocks and from a particular geographical region suggests a potential pattern of widespread, low-intensity scanning or probing from a larger, coordinated infrastructure. The findings of this report should be used to inform our threat intelligence and to strengthen our defensive posture against threats emanating from these regions and networks.

### Methodology

The investigation was conducted using Open-Source Intelligence (OSINT) gathering techniques. The primary tool used was the `search_agent`, which was employed to query various public sources, including threat intelligence platforms, blacklists, and network information databases, for information on each of the 100 IP addresses provided. The gathered data was then collated and analyzed to produce this report.

### Detailed Findings

The following table provides a detailed summary of the OSINT findings for each of the investigated IP addresses.

| IP Address | Country | City | ISP | ASN | Notable Observations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1.173.140.138 | Taiwan | - | Hoshin Multimedia Center Inc. | AS3462 | Dynamically assigned address. Open ports 80 and 443. No conclusive evidence of malicious activity. |
| 1.182.192.2 | China | Shanghai | - | - | No specific, publicly available information linking this IP address to any malicious activities. |
| 1.193.63.102 | China | - | CHINANET | AS4134 | Blacklisted. Linked to spam, phishing, and other forms of cybercrime. |
| 1.193.63.117 | China | Fushun | China Unicom | - | Blacklisted. Associated with bad bots, hacking, spam, and phishing. |
| 1.193.63.136 | China | - | CHINANET | AS4134 | No direct evidence of malicious activity, but part of a network with a history of cyber threats. |
| 1.193.63.16 | China | - | CHINANET-BACKBONE | AS4134 | Blacklisted on AbuseIPDB. Associated with a network known for abusive activity. |
| 1.193.63.176 | China | - | Chinanet | - | Blacklisted. Linked to spam and phishing. |
| 1.193.63.191 | China | - | CHINANET | AS4134 | Appears on several blacklists. Part of a network associated with malware hosting and botnets. |
| 1.193.63.2 | China | - | CHINANET-BACKBONE | AS4134 | Blacklisted. Associated with spamming activities and a network with a history of malicious traffic. |
| 1.193.63.203 | China | - | CHINANET-BACKBONE | AS4134 | Blacklisted. Part of a network with a history of malicious activity. |
| 1.193.63.239 | China | Sichuan | CHINANET | - | Blacklisted. A neighboring IP has also been reported for abuse. |
| 1.193.63.252 | China | Wuhan | CHINANET-BACKBONE | AS4134 | Blacklisted. Part of a high-risk network. |
| 1.193.63.62 | China | - | CHINANET | AS4134 | Listed on multiple abuse blocklists. Flagged for spamming activities. |
| 1.193.63.85 | - | - | - | - | Limited public information available. Potential association with AS4134 CHINANET-BACKBONE. |
| 1.193.63.89 | China | Wuhan | CHINANET | AS4134 | Blacklisted. Part of a network with a history of spam, malware, and other malicious activities. |
| 1.20.209.142 | Thailand | Bangkok | TOT Public Company Limited | - | No publicly documented malicious activity. |
| 1.205.201.220 | - | - | - | - | No specific, publicly available information. |
| 1.212.92.138 | South Korea | Seoul | SK Telecom | - | No direct evidence of malicious activity. |
| 1.217.119.94 | Philippines | - | - | - | Not flagged for malicious activities. ISP and specific location not definitively identified. |
| 1.22.228.191 | India | - | Tikona Infinet Ltd. | - | Blacklisted. Associated with an ISP with a contentious reputation. |
| 1.23.167.235 | India | - | Tikona Infinet Ltd. | - | No direct evidence of malicious activity. |
| 1.234.25.137 | South Korea | - | SK Broadband Co Ltd | - | No recorded instances of malicious activity. Likely not hosting public services. |
| 1.237.186.40 | South Korea | Seoul | SK Broadband Co Ltd | - | No documented history of involvement in malicious cyber activities. |
| 1.24.16.10 | China | - | China Unicom Neimeng Province Network | AS4837 | Blacklisted. Associated with a network known for hosting various cyber threats, including DDoS attacks and malware. |
| 1.24.16.101 | China | - | - | - | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.103 | China | Nei Mongol | China Unicom | AS4837 | Blacklisted. Associated with hacking attempts, spamming, and other malicious behavior. |
| 1.24.16.106 | China | Baotou | CHINA UNICOM China169 Backbone | AS4837 | No direct evidence of malicious activity, but the broader network has been linked to cyber threats. |
| 1.24.16.109 | China | Beijing | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Part of a network with a history of hosting malware and facilitating spam and hacking. |
| 1.24.16.112 | China | Zhangzhou | China Unicom Neimeng Province Network | AS4837 | Blacklisted. Associated with spam, port scanning, DDoS attacks, and brute-force attempts. |
| 1.24.16.117 | China | Inner Mongolia | China Unicom | - | Blacklisted. History of abusive behavior. |
| 1.24.16.118 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple threat intelligence feeds. Part of a network with a high volume of malicious activity. |
| 1.24.16.119 | China | Baotou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Involved in port scanning, SSH brute force attacks, DDoS attacks, and spam. |
| 1.24.16.121 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple threat intelligence platforms. |
| 1.24.16.126 | China | Baotou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.128 | China | Baotou | CHINA UNICOM China169 Backbone | - | Blacklisted on AbuseIPDB for abusive behavior. |
| 1.24.16.129 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Part of an ASN known for a high volume of malicious traffic, including malware hosting. |
| 1.24.16.134 | China | - | CHINA UNICOM China169 Backbone | AS4837 | No direct evidence of malicious activity, but the broader network has been linked to cybersecurity threats. |
| 1.24.16.137 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Flagged in a Chinese "Attack IP Record Table." |
| 1.24.16.138 | China | - | CHINA UNICOM China169 Backbone | - | Blacklisted. Part of a network range flagged for malicious behavior and bot activity. |
| 1.24.16.14 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. |
| 1.24.16.140 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The entire /24 subnet is on a blocklist for widespread malicious activity. |
| 1.24.16.142 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Involved in suspicious SSH activity. |
| 1.24.16.143 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.147 | China | Hohhot | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple security platforms. |
| 1.24.16.149 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Implicated in unsolicited SMTP activity (spam). The parent network is associated with malware distribution. |
| 1.24.16.155 | China | - | CHINA UNICOM China169 Backbone | AS4837 | No direct evidence of malicious activity from major IP reputation services. |
| 1.24.16.166 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. Part of a network linked to Chinese state-sponsored cyber activities. |
| 1.24.16.167 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Involved in suspicious SSH activity and hitting unusual ports. The parent network is linked to botnet operations. |
| 1.24.16.17 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. The parent network is linked to a state-sponsored threat actor (Flax Typhoon). |
| 1.24.16.171 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with a network known for hosting malware and botnets. |
| 1.24.16.172 | China | Beijing | CHINA UNICOM China169 Backbone | - | Blacklisted on multiple security platforms for connections to various cyber threats. |
| 1.24.16.176 | China | Inner Mongolia | CHINA UNICOM China169 Backbone | - | Blacklisted on multiple threat intelligence feeds. |
| 1.24.16.180 | China | Inner Mongolia | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple threat intelligence platforms. |
| 1.24.16.181 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted with high confidence of abuse. Associated with scanning, spam, and brute-force attacks. |
| 1.24.16.183 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with spam operations and the MIRAI botnet. |
| 1.24.16.186 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Listed in a Network Entity Reputation Database. The parent network has a history of malicious activity. |
| 1.24.16.187 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. History of being reported for malicious activities. |
| 1.24.16.19 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Flagged for "BruteForce" activity. |
| 1.24.16.190 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. The parent network has a history of hosting malware. |
| 1.24.16.191 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with DDoS attacks, spam, and malicious bot activity. |
| 1.24.16.192 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. The parent network has been linked to PRC-based threat actors. |
| 1.24.16.194 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.195 | China | Beijing | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Flagged for spamming and other malicious acts. The parent network has a history of hosting malware. |
| 1.24.16.199 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Involved in SSH brute-force attacks and is a component of the MIRAI botnet. |
| 1.24.16.2 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. The parent network is associated with IoT malware (Mozi, Mirai). |
| 1.24.16.200 | China | - | China Unicom Innermongolia Province Network | - | Blacklisted on multiple threat intelligence feeds. |
| 1.24.16.203 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.204 | - | - | CHINA UNICOM China169 Backbone | AS4837 | The surrounding /24 subnet is on a public blocklist for malicious behavior and bot activity. The ISP has a history of abuse reports. |
| 1.24.16.208 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. |
| 1.24.16.209 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.21 | China | Hohhot | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The parent network is associated with malware hosting and botnet operations. |
| 1.24.16.211 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple threat intelligence feeds for spam, phishing, and scanning. |
| 1.24.16.218 | China | - | China Unicom Inner Mongolia Province Network | - | Blacklisted on AbuseIPDB. Implicated in an attack targeting vCenter. |
| 1.24.16.219 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet and port scanning. |
| 1.24.16.223 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with spam, port scanning, DDoS, and brute-force attacks. Suspicious activity on port 9000 (common trojan port). |
| 1.24.16.224 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The parent network is under scrutiny by the U.S. government for national security concerns. |
| 1.24.16.226 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with port scanning, SSH brute force attacks, DDoS attacks, and spam. |
| 1.24.16.23 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The parent network is a prominent source of malware. |
| 1.24.16.239 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The parent network is associated with malware, botnets (Mirai, Mozi), and DDoS attacks. |
| 1.24.16.245 | China | Baotou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The surrounding /24 subnet is also flagged for suspicious behavior. The parent network is a significant source of malware. |
| 1.24.16.249 | China | - | CHINA UNICOM China169 Backbone | - | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.252 | China | Nei Mongol | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on the CINS Army list for poor reputation and malicious traffic. The parent network has a history of hosting malware. |
| 1.24.16.26 | China | - | China Unicom Innermongolia Province Network | AS4837 | No direct evidence of malicious activity. The parent network has a history of abuse. |
| 1.24.16.28 | China | Zhangzhou | CHINANET Fujian province network / CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Negative reputation. |
| 1.24.16.3 | China | Baotou | CHINA UNICOM China169 Backbone | - | Blacklisted on multiple threat intelligence feeds. |
| 1.24.16.35 | China | Zhangzhou | China Unicom Neimeng Province Network | AS4837 | Blacklisted on AbuseIPDB. Reported on VirusTotal. Associated with suspicious SMTP activity. |
| 1.24.16.38 | China | Zhangzhou | China Unicom Neimeng Province Network | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.40 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.43 | China | - | China United Network Communications Group Co., Ltd. (China Unicom) | AS4837 | No direct evidence of malicious activity, but the parent network has a history of hosting malware and botnets. |
| 1.24.16.49 | China | Hohhot/Baotou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB with high confidence. |
| 1.24.16.50 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with mail spamming, SSH attacks, IoT attacks, and DDoS attacks. |
| 1.24.16.54 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on multiple platforms. |
| 1.24.16.56 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted on AbuseIPDB. Flagged for suspicious SSH client activity. |
| 1.24.16.58 | - | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. The parent network is associated with malware distribution. |
| 1.24.16.59 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with bots, hacking, spam, and phishing. |
| 1.24.16.60 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with the MIRAI botnet. |
| 1.24.16.62 | China | Zhangzhou | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with DDoS attacks and port scanning. The parent network is linked to IoT malware (Mozi, Mirai). |
| 1.24.16.63 | China | - | China Unicom Neimeng Province Network | AS4837 | Blacklisted on AbuseIPDB. High-threat entity targeting mail servers. The parent network is associated with malware, spam, and botnets. |
| 1.24.16.65 | China | Inner Mongolia | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Associated with port scanning, SSH brute-force attacks, and DDoS attacks. |
| 1.24.16.67 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Suspicious activity on port 2809. The parent network is associated with malware and network abuse. |
| 1.24.16.99 | China | - | CHINA UNICOM China169 Backbone | AS4837 | Blacklisted. Implicated in malicious SSH protocol activities. |

### Conclusion

The OSINT investigation of these 100 low-attack-count IP addresses has revealed a significant concentration of malicious actors, primarily located in China and operating within the networks of major state-owned telecommunications providers. The prevalence of these IPs on various blacklists and their association with known malware and botnets, such as MIRAI, indicates that even single, isolated attacks can be part of a much larger, orchestrated threat landscape.

The findings underscore the importance of not dismissing low-frequency attack data and highlight the value of OSINT in enriching our understanding of the adversaries we face. The information gathered in this report should be integrated into our threat intelligence feeds and used to proactively block and monitor the identified malicious IP addresses and network ranges. It is recommended to maintain a heightened level of vigilance for traffic originating from the identified high-risk networks and to continue monitoring these and other low-frequency attackers for any changes in their tactics, techniques, and procedures.