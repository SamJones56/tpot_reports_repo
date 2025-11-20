## **Fact-Checked Honeypot Attack Research Report**

**Report Generation Time:** 2025-10-29T17:48:47.765026Z
**Fact-Check Completion Time:** 2025-10-29T17:49:31.542189Z
**Analysis Timeframe:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

**Data Sources Used:**
*   Honeypot event logs from the Elasticstack cluster.
*   Open-source intelligence (OSINT) gathered via the `search_agent`.

---

### **1. Executive Summary**

This report provides a verified open-source intelligence (OSINT) analysis of the top five most active IP addresses that targeted our honeypot network between September 28, 2025, and October 28, 2025. The investigation confirms that these attackers are globally distributed and utilize a range of malicious techniques, from large-scale VoIP service disruption to targeted brute-force attacks on email and remote access protocols. All investigated IPs have a confirmed history of malicious activity, are listed on various threat intelligence platforms and blacklists, and pose a significant risk. The most prominent attacker, **2.57.121.61**, was responsible for over 900,000 observed events and is linked to an exceptionally high volume of SIP/VoIP-based attacks.

It is strongly recommended that all IP addresses detailed in this report are added to network blocklists to mitigate potential threats.

### **2. Introduction**

The purpose of this report is to analyze and verify the most prominent threats identified by our honeypot network during the specified one-month period. By correlating honeypot logs with publicly available threat intelligence, we can better understand the tactics, techniques, and origins of our adversaries. This report focuses on the top five source IP addresses by attack volume and presents the findings from OSINT investigations into their reputation and activities.

### **3. Top 5 Attacking IP Addresses by Volume**

The following IP addresses have been verified as the top 5 attackers by volume, consistent with the initial report:
1.  **2.57.121.61** (907,689 attacks)
2.  **92.205.59.208** (231,642 attacks)
3.  **176.65.141.117** (162,689 attacks)
4.  **86.54.42.238** (144,466 attacks)
5.  **185.243.96.105** (140,467 attacks)

### **4. Open-Source Intelligence (OSINT) Investigation**

#### **4.1. IP Address: 2.57.121.61**
*   **ASN/ISP:** AS47890 / Unmanaged Ltd
*   **Geographic Location:** United Kingdom
*   **Summary of Malicious Activities:** This IP is a significant source of high-volume cyberattacks, with threat intelligence platforms reporting tens of millions of attacks. The primary activity is focused on VoIP services, specifically "VOIP REGISTER Message Flood UDP" attacks targeting the SIP protocol on port 5060. The sheer volume of attacks suggests automated and widespread campaigns.
*   **Reputation and Blacklist Status:** The IP is flagged as malicious across multiple platforms, including AbuseIPDB, MalwareURL, and blocklist.de. It is considered a high-risk Indicator of Compromise (IOC) by multiple security firms.

#### **4.2. IP Address: 92.205.59.208**
*   **ASN/ISP:** AS21499 / Host Europe GmbH
*   **Geographic Location:** Germany
*   **Summary of Malicious Activities:** This IP is explicitly classified as a "Malicious IP" by MalwareURL. While specific attack types for this IP are not detailed, its host network (AS21499) has a known history of facilitating phishing campaigns, spam, and brute-force attacks (IMAP). The associated hostname `208.59.205.92.host.secureserver.net` may be an attempt to appear legitimate.
*   **Reputation and Blacklist Status:** Consistently flagged as malicious by threat intelligence platforms. The surrounding network's reputation for hosting cyber threats increases the risk posed by this IP.

#### **4.3. IP Address: 176.65.141.117**
*   **ASN/ISP:** SPRINT S.A.
*   **Geographic Location:** Poland
*   **Summary of Malicious Activities:** This IP is primarily associated with brute-force and authentication attacks against email servers. Reports specify "too many errors after EHLO" and "dovecot auth-worker" errors, which are characteristic of automated attempts to guess email credentials. AbuseIPDB confirms it has been identified as a VPN, proxy, or TOR exit node, which allows attackers to obscure their true origin.
*   **Reputation and Blacklist Status:** Reported multiple times on AbuseIPDB for brute-force attacks. While not flagged as malicious by all vendors on VirusTotal, its use as an anonymizing node combined with direct abuse reports makes it a credible threat.

#### **4.4. IP Address: 86.54.42.238**
*   **ASN/ISP:** AS42624 / Global-Data System IT Corporation
*   **Geographic Location:** Romania
*   **Summary of Malicious Activities:** This IP has an extremely poor reputation, with a 100% "Confidence of Abuse" score on AbuseIPDB based on over 1,200 reports from nearly 250 sources. It is heavily involved in email-related abuse, including spam and brute-force attacks against IMAP services. The associated hostname is `rdp-mwkejlli`.
*   **Reputation and Blacklist Status:** Confirmed to be on multiple blacklists, including blocklist.de and the Spamhaus Zen blocklist. It is flagged as a "Bad IP" and an "Infected System," indicating a high likelihood of compromise and active involvement in malicious campaigns.

#### **4.5. IP Address: 185.243.96.105**
*   **ASN/ISP:** AS3257 / GTT Communications Inc.
*   **Geographic Location:** New York, United States
*   **Summary of Malicious Activities:** This IP has been observed engaging in suspicious remote access attempts, specifically initiating VNC (Virtual Network Computing) connections on port 5900. While not universally blacklisted, its network neighbors (e.g., 185.243.96.130) are known IOCs for active scanning and RDP exploitation, suggesting the entire subnet may be utilized for malicious purposes.
*   **Reputation and Blacklist Status:** While not flagged by all security vendors, it has been reported on AbuseIPDB and IPThreat for brute-force and RDP-related attacks. The suspicious activity and the poor reputation of its network neighborhood warrant caution.

### **5. Conclusion & Recommendations**

The OSINT investigation confirms that the top five IP addresses targeting our honeypot infrastructure are operated by malicious actors and are involved in a variety of global attack campaigns. The tactics observed range from large-scale service disruption (VoIP floods) to credential harvesting (email brute-force) and reconnaissance (VNC/RDP scanning).

Based on these findings, the following actions are recommended:

1.  **Block Malicious IPs:** Add all five identified IP addresses to the network firewall blocklist to prevent any inbound or outbound communication.
2.  **Monitor Associated Subnets:** Given the evidence of malicious activity within the associated network ranges of 86.54.42.0/24 and 185.243.96.0/24, consider heightened monitoring or proactive blocking of these subnets.
3.  **Enhance Service Hardening:** The prevalence of attacks against VoIP, email, and remote access protocols underscores the importance of robust security controls for these services, including strong password policies, multi-factor authentication, and rate-limiting.
