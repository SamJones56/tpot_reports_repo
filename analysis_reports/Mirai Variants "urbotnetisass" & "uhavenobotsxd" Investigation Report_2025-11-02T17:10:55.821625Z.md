**Honeypot Attack Research Report: Investigation of Mirai Variants "urbotnetisass" & "uhavenobotsxd"**

**Report Generation Time:** 2025-11-02T17:00:59.441602Z

**Timeframe:** September 28, 2025, 00:00:00.000 to October 28, 2025, 23:59:59.999.

**Files Used:** Elasticstack Database Logs

**Executive Summary**

This report details the investigation into the suspected activity of two Mirai variants, "urbotnetisass" and "uhavenobotsxd," within the honeypot network. The investigation was initiated based on the user's request to confirm the presence of these variants and their associated Command and Control (C2) IPs. The investigation has confirmed the presence of the "uhavenobotsxd" variant, and the malicious nature of all three provided C2 IPs. While the "urbotnetisass" variant was not directly observed, the investigation uncovered a significant amount of activity related to the "uhavenobotsxd" variant, including the download of malicious binaries, downloader scripts, and the use of the "busybox" fingerprint. The investigation also identified additional attacker IPs and downloader scripts, providing a comprehensive view of the attack campaign.

**Detailed Findings**

**Initial Intelligence**

The investigation was initiated with the following information:
*   **Mirai Variants:** "urbotnetisass" & "uhavenobotsxd"
*   **Fingerprint:** "busybox" download & exec directory, "urbotnetisass" or "uhavenobotsxd"
*   **Command & Control IPs:**
    *   94.154.35.154 ("urbotnetisass" Mirai variant)
    *   141.98.10.66 (Mirai variant payloads)
    *   213.209.143.62 (Mirai variant downloader scripts - w.sh)

**Investigation of Fingerprints**

*   **"urbotnetisass":** A search for the string "urbotnetisass" in the logs did not yield any results. This suggests that this specific variant was not active in the honeypot network during the specified timeframe.
*   **"uhavenobotsxd":** A search for the string "uhavenobotsxd" in the logs revealed multiple hits. The string was found in the filenames of downloaded ELF executables, confirming the presence of this Mirai variant in the honeypot network. The filenames included: `/mips.uhavenobotsxd`, `/x86_32.uhavenobotsxd`, `/arm7.uhavenobotsxd`, `/arm6.uhavenobotsxd`.

**Investigation of C2 IPs**

All three provided C2 IPs were investigated and confirmed to be involved in malicious activity.

*   **94.154.35.154:**
    *   **Total Attacks:** 68
    *   **Country of Origin:** The Netherlands
    *   **ASN:** 214943 (Railnet LLC)
    *   **Activity:** This IP was observed serving the "uhavenobotsxd" Mirai binaries for different architectures. It was also flagged by Suricata with the signature "ET DROP Spamhaus DROP Listed Traffic Inbound group 15".

*   **141.98.10.66:**
    *   **Total Attacks:** 82
    *   **Country of Origin:** Lithuania
    *   **ASN:** 209605 (UAB Host Baltic)
    *   **Activity:** This IP was observed serving the downloader scripts "w.sh" and "c.sh".

*   **213.209.143.62:**
    *   **Total Attacks:** 2668
    *   **Country of Origin:** Germany
    *   **ASN:** 214943 (Railnet LLC)
    *   **Activity:** This IP was observed serving the downloader scripts "w.sh", "c.sh", and "wget.sh". It was also flagged by Suricata with the signature "ET DROP Spamhaus DROP Listed Traffic Inbound group 58".

**Downloader Scripts Analysis**

The investigation identified three downloader scripts used in the attacks: "w.sh", "c.sh", and "wget.sh". These scripts were downloaded from the C2 IPs and executed on the honeypots to download the Mirai binaries. The scripts were downloaded using `curl` and `wget` commands, often with the help of `busybox`.

**"Busybox" Fingerprint Analysis**

The investigation confirmed the use of "busybox" as a fingerprint of the attack. The `Adbhoney` logs revealed the exact commands executed by the attackers, which clearly showed the use of `busybox wget` and `busybox curl` to download the downloader scripts and the Mirai binaries. The commands also showed the execution of the downloaded scripts and binaries.

**Attacker Infrastructure**

In addition to the C2 IPs, the investigation identified the following attacker IPs:
*   87.121.84.6 (United States, ASN 215925 - Vpsvault.host Ltd)
*   51.81.141.174 (United States, ASN 16276 - OVH SAS)
*   94.74.191.7 (Iran, ASN 214967 - Optibounce, LLC)
*   135.148.99.44 (United States, ASN 16276 - OVH SAS)
*   31.97.223.111 (Indonesia, ASN 47583 - Hostinger International Limited)
*   202.55.132.254 (Vietnam, ASN 63737 - VIETSERVER SERVICES TECHNOLOGY COMPANY LIMITED)

**Indicators of Compromise (IOCs)**

*   **Mirai Variant:** "uhavenobotsxd"
*   **C2 IPs:**
    *   94.154.35.154
    *   141.98.10.66
    *   213.209.143.62
*   **Downloader Scripts:**
    *   w.sh
    *   c.sh
    *   wget.sh
*   **Attacker IPs:**
    *   87.121.84.6
    *   51.81.141.174
    *   94.74.191.7
    *   135.148.99.44
    *   31.97.223.111
    *   202.55.132.254
*   **Malware Filenames:**
    *   /mips.uhavenobotsxd
    *   /x86_32.uhavenobotsxd
    *   /arm7.uhavenobotsxd
    *   /arm6.uhavenobotsxd

**Conclusion**

The investigation has successfully confirmed the presence of the "uhavenobotsxd" Mirai variant in the honeypot network. The provided C2 IPs were all confirmed to be malicious and actively involved in the distribution of the malware and its downloader scripts. The investigation has also provided a clear picture of the attack chain, from the initial compromise to the execution of the Mirai binaries. The identified IOCs can be used to improve the security posture of the network and to detect and prevent future attacks from this specific campaign. Although the "urbotnetisass" variant was not observed, the confirmed activity of "uhavenobotsxd" and its associated infrastructure represents a significant threat to IoT devices.

---

**Fact-Check Report: Verification of Mirai Variants Investigation**

**Report Generation Time:** 2025-11-02T17:07:33.362293Z

**Timeframe of Data Verification:** September 28, 2025, 00:00:00.000 to October 28, 2025, 23:59:59.999.

**Subject:** Fact-check of "Honeypot Attack Research Report: Investigation of Mirai Variants 'urbotnetisass' & 'uhavenobotsxd'"

**Executive Summary**

This report confirms that the findings presented by the `query_agent` regarding the Mirai variants "urbotnetisass" and "uhavenobotsxd" are accurate and corroborated by the honeypot logs. All key data points, including the presence of the "uhavenobotsxd" variant, the malicious activities of the specified Command & Control (C2) IPs, the identified downloader scripts, the "busybox" fingerprint, and the newly discovered attacker infrastructure, have been independently verified. The initial report is sound and provides a reliable assessment of the threat activity.

**Verification of Findings**

The following sections detail the verification process for each claim made in the original report.

**1. Fingerprint Analysis**
*   **"urbotnetisass":** **Confirmed.** A thorough search of the logs within the specified timeframe yielded no results for the string "urbotnetisass," supporting the conclusion that this variant was not observed.
*   **"uhavenobotsxd":** **Confirmed.** Log analysis verified the presence of multiple files containing this string, including `/mips.uhavenobotsxd`, `/x86_32.uhavenobotsxd`, `/arm7.uhavenobotsxd`, and `/arm6.uhavenobotsxd`.

**2. C2 IP Verification**
The activity, location, and ownership of all three C2 IPs were confirmed as reported.

*   **94.154.35.154:**
    *   **Total Attacks:** **Confirmed (68).**
    *   **Country & ASN:** **Confirmed** (The Netherlands, AS214943 - Railnet LLC).
    *   **Activity:** **Confirmed.** This IP was verified as the source for downloading "uhavenobotsxd" binaries.

*   **141.98.10.66:**
    *   **Total Attacks:** **Confirmed (82).**
    *   **Country & ASN:** **Confirmed** (Lithuania, AS209605 - UAB Host Baltic).
    *   **Activity:** **Confirmed.** Log entries show this IP serving the downloader scripts "w.sh" and "c.sh".

*   **213.209.143.62:**
    *   **Total Attacks:** **Confirmed (2668).**
    *   **Country & ASN:** **Confirmed** (Germany, AS214943 - Railnet LLC).
    *   **Activity:** **Confirmed.** This IP was verified as a source for the scripts "w.sh," "c.sh," and "wget.sh."

**3. Downloader Scripts and "Busybox" Fingerprint**
*   **Script Verification:** **Confirmed.** The scripts "w.sh," "c.sh," and "wget.sh" were consistently observed being downloaded from the verified C2 IPs.
*   **"Busybox" Usage:** **Confirmed.** `Adbhoney` logs contain multiple entries showing command sequences using `busybox wget` and `busybox curl` to fetch and execute both the downloader scripts and the Mirai variant binaries.

**4. Attacker Infrastructure Verification**
The additional attacker IPs identified in the initial report have been verified for their geographic location and Autonomous System Number (ASN).

*   `87.121.84.6`: **Confirmed** (United States, AS215925 - Vpsvault.host Ltd).
*   `51.81.141.174`: **Confirmed** (United States, AS16276 - OVH SAS).
*   `94.74.191.7`: **Confirmed** (Iran, AS214967 - Optibounce, LLC).
*   `135.148.99.44`: **Confirmed** (United States, AS16276 - OVH SAS).
*   `31.97.223.111`: **Confirmed** (Indonesia, AS47583 - Hostinger International Limited).
*   `202.55.132.254`: **Confirmed** (Vietnam, AS63737 - VIETSERVER SERVICES TECHNOLOGY COMPANY LIMITED).

**Conclusion**

The fact-checking process validates the accuracy and reliability of the `query_agent`'s report. All claims regarding the Mirai variant activity, associated infrastructure, and Indicators of Compromise (IOCs) are supported by the available log data. The initial report can be considered a trustworthy source for understanding this attack campaign.
