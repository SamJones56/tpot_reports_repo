## **Fact-Checked Honeypot Research Report: Detailed Analysis of Covert Crypto Mining Campaign**

**Report Generation Time:** 2025-10-30T17:51:33.197781Z
**Fact-Check Completion Time:** 2025-10-30T17:54:00.000000Z
**Timeframe:** 2025-09-28T00:00:00.000Z - 2025-10-28T23:59:59.999Z

**Sources Used:**
*   Live query results from Elasticstack

### **1. Executive Summary**

This report provides a detailed, fact-checked analysis of a multi-faceted crypto mining campaign detected across our honeypot network. The investigation confirmed a persistent and sophisticated operation involving Monero (XMR), Ethereum (ETH), and Bitcoin (BTC) mining. Attackers utilized covert channels, primarily ICMP and SSH tunneling, to disguise their activities. A significant portion of the attacks originated from IP addresses with known malicious reputations, hosted on major cloud and VPS platforms. Furthermore, a targeted campaign using the DoublePulsar backdoor was identified in conjunction with Bitcoin mining indicators, suggesting a more advanced threat aimed at deeper system compromise.

### **2. Attacker Profile & Infrastructure (Verified)**

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
    *   **(Correction): AS36352 (AS-COLOCROSSING):** 356,522 attacks was also a top attacker, ranking 6th.
*   **Reputation:** **Over 6 million events (6,023,895)** were tied to IPs flagged as **"known attacker,"** with an additional 161,560 from **"mass scanners."**

The heavy reliance on cloud and VPS providers (DigitalOcean, Google, Microsoft, AWS, ColoCrossing) is confirmed.

### **3. Crypto Mining Activity by Type (Verified with Corrections)**

**3.1. Monero (XMR) & Ethereum (ETH) via Covert Tunneling**
*   **Description:** Payloads containing the strings "xmr" and "eth" were confirmed within ICMP and SSH packets. This method effectively tunnels mining traffic over protocols that often receive less scrutiny.
*   **Targeted Honeypots:**
    *   **XMR:** `hive-us`, `sens-tai`, `sens-tel`, and `sens-dub`. **(Correction: The initial report missed the `sens-dub` honeypot).** The use of SSH for tunneling was also an unmentioned detail.
    *   **ETH:** `hive-us`, `sens-tai`, and `sens-ny`. **(Correction: The initial report missed the `sens-ny` honeypot).** The activity targeting `sens-ny` was tunneled over TCP, not ICMP.
*   **Alerts Generated:** This activity was confirmed to have triggered generic alerts like `GPL ICMP PING` and `ET INFO SSH session in progress on Expected Port`.

**3.2. Bitcoin (BTC) Activity (Verified)**
*   **Port 8333 Traffic:** A high volume of connections (58,826 events) to TCP port 8333 was confirmed.
*   **ICMP Tunneling:** The string "btc" was confirmed in ICMP payloads targeting the `sens-tai` honeypot.
*   **DoublePulsar Exploit Association:** The correlation between "btc" strings in packet payloads and alerts for the **"ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication"** is confirmed.

### **4. In-Depth: DoublePulsar Backdoor Campaign (Verified)**
*   **Description:** The DoublePulsar exploit campaign was confirmed to be a targeted attack using the SMB protocol (port 445).
*   **Attacker:**
    *   **IP Address:** `188.225.66.220`
    *   **ASN:** AS28840 (Pjsc tattelecom)
    *   **Country:** Russia
*   **Target:** `sens-ny` Honeypot (`161.35.180.163`)
*   **Correlation:** The presence of "btc" in the exploit payloads strongly supports the hypothesis that the campaign's goal was to install Bitcoin mining malware.

### **5. Negative Findings (Verified)**
*   **Mining Pool Keywords:** It is confirmed that searches for "pool" and "stratum" did not return results related to crypto mining activity.
*   **Telegram Keyword:** It is confirmed that a search for "telegram" yielded no relevant results.

### **6. Conclusion and Recommendations (Verified & Endorsed)**
The investigation's conclusions are well-supported by the evidence. A persistent, multi-faceted crypto mining campaign is underway, using both opportunistic and targeted methods. The recommendations provided in the initial report are sound and are endorsed by this fact-check.