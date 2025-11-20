## **Honeypot Attack Research Report: Detailed Analysis of Covert Crypto Mining Campaign**

**Report Generation Time:** 2025-10-30T17:51:33.197781Z
**Timeframe:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

**Files Used:**
*   Live query results from Elasticstack

### **1. Executive Summary**

This report provides a detailed analysis of a multi-faceted crypto mining campaign detected across our honeypot network. The investigation revealed a persistent and sophisticated operation involving Monero (XMR), Ethereum (ETH), and Bitcoin (BTC) mining. Attackers utilized covert channels, primarily ICMP tunneling, to disguise their activities. A significant portion of the attacks originated from IP addresses with known malicious reputations, hosted on major cloud and VPS platforms. Furthermore, a targeted campaign using the DoublePulsar backdoor was identified in conjunction with Bitcoin mining indicators, suggesting a more advanced threat aimed at deeper system compromise.

### **2. Attacker Profile & Infrastructure**

Analysis of the attack traffic reveals a distributed and well-established operation.
*   **Top Attacking IP Addresses:**
    *   `2.57.121.61` (906,566 attacks)
    *   `92.205.59.208` (231,492 attacks)
    *   `176.65.141.117` (162,689 attacks)
    *   `185.243.96.105` (140,111 attacks)
    *   `86.54.42.238` (139,546 attacks)
*   **Network Origin (Top ASNs):**
    *   **AS215540 (Global Connectivity Solutions Llp):** 938,647 attacks
    *   **AS47890 (Unmanaged Ltd):** 929,310 attacks
    *   **AS14061 (DigitalOcean):** 909,812 attacks
    *   **AS396982 (Google Cloud):** 429,539 attacks
    *   **AS8075 (Microsoft):** 388,287 attacks
    *   **AS16509 (Amazon-02):** 100,503 attacks
*   **Reputation:** Over 6 million events were tied to IPs flagged as **"known attacker,"** with an additional 161,560 from **"mass scanners."** This confirms the malicious nature of the observed traffic.

The heavy reliance on cloud and VPS providers (DigitalOcean, Google, Microsoft, AWS) is a common tactic, allowing attackers to quickly cycle through IP addresses and leverage high-bandwidth infrastructure.

### **3. Crypto Mining Activity by Type**

**3.1. Monero (XMR) & Ethereum (ETH) via ICMP Tunneling**
*   **Description:** The investigation uncovered numerous instances where ICMP packets, typically used for network diagnostics, were used to carry malicious payloads. The strings "xmr" (Monero) and "eth" (Ethereum) were frequently found within the `payload_printable` field of these packets. This method effectively tunnels mining traffic over a protocol that often receives less scrutiny than TCP or UDP.
*   **Targeted Honeypots:** `hive-us`, `sens-tai`, `sens-tel`
*   **Alerts Generated:** This activity consistently triggered the generic `GPL ICMP PING` alert. The alert itself is low-severity, but the payload content confirms the malicious intent. This highlights a limitation in signature-based detection that does not perform deep packet inspection on ICMP.

**3.2. Bitcoin (BTC) Activity**
Bitcoin-related attacks were observed through three distinct vectors:
*   **Port 8333 Traffic:** A high volume of connections to TCP port 8333, the standard port for Bitcoin peer-to-peer communication, was recorded. This indicates nodes attempting to communicate with what they perceive as part of the Bitcoin network.
*   **ICMP Tunneling:** Similar to XMR and ETH, the string "btc" was found in ICMP packet payloads, primarily targeting the `sens-tai` honeypot.
*   **DoublePulsar Exploit Association:** The most concerning finding was the correlation between "btc" strings in packet payloads and alerts for the **"ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication."**

### **4. In-Depth: DoublePulsar Backdoor Campaign**
*   **Description:** The DoublePulsar exploit, notoriously linked to the EternalBlue SMB vulnerability, was detected in a targeted campaign. The alerts were triggered by traffic on port 445 (SMB) originating from a single source.
*   **Attacker:**
    *   **IP Address:** `188.225.66.220`
    *   **ASN:** AS28840 (Pjsc tattelecom)
    *   **Country:** Russia
*   **Target:** `sens-ny` Honeypot (10.108.0.2 / 161.35.180.163)
*   **Correlation:** The presence of "btc" within the payload of these exploit attempts strongly suggests that the objective of the compromise was to install Bitcoin mining malware. This represents a more severe threat than the ICMP-based mining, as it involves a full system compromise via a known backdoor.

### **5. Negative Findings**
*   **Mining Pool Keywords:** Searches for terms directly associated with mining pool connections, such as "pool" and "stratum," yielded no results related to crypto mining. The hits for "pool" were confirmed to be legitimate Linux APT package manager requests. This suggests that if pool connections were made, they were likely obfuscated or occurred over a different channel.
*   **Telegram Keyword:** A specific search for the keyword "telegram" within packet payloads returned no results, indicating no observed command-and-control (C2) or data exfiltration activity related to the Telegram service.

### **6. Conclusion and Recommendations**
This investigation reveals a persistent and multi-pronged crypto mining campaign. While some of the activity appears to be automated scanning and opportunistic mining over ICMP, the use of the DoublePulsar backdoor indicates a more targeted and intrusive effort to compromise systems for Bitcoin mining.

**Recommendations:**
1.  **Block Malicious Infrastructure:** The identified attacker IPs, particularly `188.225.66.220`, and the top ASNs associated with this campaign should be added to firewall blocklists.
2.  **Enhance Network Monitoring:** Implement stricter inspection of ICMP traffic. While blocking all ICMP is not feasible, rules can be created to flag ICMP packets with unusual payload sizes or content.
3.  **Prioritize SMB Vulnerabilities:** The detection of the DoublePulsar exploit highlights the continued threat of SMB vulnerabilities. Ensure all systems are patched against EternalBlue and related exploits, and that SMB access is heavily restricted from the internet.
4.  **Develop Custom Signatures:** Create threat intelligence queries and IDS signatures to specifically detect "xmr," "eth," and "btc" strings within ICMP and other unexpected protocols to provide higher-fidelity alerts than the generic "ICMP PING" rule.
