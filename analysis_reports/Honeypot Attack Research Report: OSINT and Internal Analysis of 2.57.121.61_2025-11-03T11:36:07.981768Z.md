### **Fact-Checked Honeypot Attack Research Report: OSINT and Internal Analysis of 2.57.121.61**

**Report Generation Time:** 2025-11-03 11:35:02 UTC
**Timeframe of Analysis:** September 28, 2025, 00:00:00.000 to October 28, 2025, 23:59:59.999

**Files Used:**
*   Honeypot logs from the Elastic Stack cluster.
*   External OSINT gathered via the `search_agent`.

**Verification Summary:**
*   **Attacker Profile:** Confirmed. Queries verify the attacker's IP is associated with ASN `47890` and ISP `Unmanaged Ltd` in Romania.
*   **Internal Observations:** Confirmed. Log analysis verifies that all attacks from this IP were directed at the `sens-ny` honeypot, exclusively targeting the SIP service on UDP port `5060` and using the `friendly-scanner` user agent. The traffic was logged by both `Suricata` and `Sentrypeer` systems.
*   **External Intelligence:** Confirmed. The summary accurately reflects the details provided by the `search_agent`, including the IP's presence on blacklists and its high threat score.
*   **Analysis and Hypothesis:** The conclusion drawn by the `query_agent` is a sound and logical interpretation of the verified data.

---

### **Verified Report**

**Executive Summary:**

This report provides a comprehensive analysis of the malicious activity originating from the IP address **2.57.121.61**. The investigation combines external open-source intelligence (OSINT) with internal honeypot logs. The attacker, located in Romania, has been conducting high-volume, automated attacks against our honeypot network. The activity is exclusively focused on scanning and enumerating Session Initiation Protocol (SIP) services, which is consistent with preparations for VoIP-based attacks such as toll fraud or denial-of-service.

**Attacker Profile:**

*   **IP Address:** 2.57.121.61
*   **Geolocation:** Bucharest, Romania
*   **ASN:** 47890
*   **ISP:** Unmanaged Ltd (a Romanian hosting provider)

**Internal Observations (Honeypot Data):**

Our internal logs from the specified timeframe show a clear and consistent pattern of attack from this IP address:

*   **Targeted Service:** The attacker exclusively targeted the Session Initiation Protocol (SIP) on UDP port 5060.
*   **Affected Honeypot:** All observed attacks were directed at our `sens-ny` honeypot (Public IP: 161.35.180.163).
*   **Attack Method:** The attacker sent a high volume of SIP `INVITE` requests. This is a common technique for scanning for vulnerable VoIP systems.
*   **User-Agent:** The user-agent string `friendly-scanner` was used in all requests. This is likely a tactic to appear as a legitimate scanner and avoid detection.
*   **Detection Systems:** The activity was detected and logged by our `Sentrypeer` and `Suricata` honeypot systems.

**External Intelligence (OSINT):**

The OSINT investigation conducted via the `search_agent` corroborates our internal findings and provides additional context:

*   **High-Volume Attack Source:** The IP address 2.57.121.61 is a known high-volume attack source, with one report attributing over 127,000 attacks to it.
*   **Blacklisted:** The IP is present on the "ci-badguys" blacklist, a list of known malicious actors.
*   **Malicious VoIP Activity:** The IP has been specifically flagged for "VOIP REGISTER Message Flood UDP" activity, which aligns with the SIP `INVITE` requests we observed.
*   **High Threat Score:** The IP has been assigned a high threat score of 80 by IP geolocation services.

**Analysis and Hypothesis:**

Based on the combined internal and external data, we can form the following hypothesis:

The IP address 2.57.121.61 is being used as a dedicated platform for malicious VoIP scanning and enumeration. The systematic and high-volume nature of the attacks suggests an automated process. The use of the deceptive user-agent "friendly-scanner" indicates a deliberate attempt to mask the malicious intent. The ultimate goal of this activity is likely to identify vulnerable VoIP systems for further exploitation, which could include toll fraud, eavesdropping, or denial-of-service attacks.

**Recommendations:**

*   **Block Traffic:** It is strongly recommended to block all inbound and outbound traffic from the IP address 2.57.121.61 at the network perimeter.
*   **Monitor Logs:** Review historical network and security logs for any communication with this IP address to identify potential past compromises or targeting.
*   **Threat Hunting:** Proactively hunt for indicators of compromise (IoCs) associated with the types of attacks originating from this IP, particularly VoIP-related anomalies.

**Conclusion:**

The IP address 2.57.121.61 represents a credible and active threat to our network and any organization with exposed VoIP services. The evidence from both our internal honeypot network and external threat intelligence sources paints a clear picture of a malicious actor focused on exploiting VoIP systems. The recommendations provided should be implemented to mitigate the risk from this attacker.
