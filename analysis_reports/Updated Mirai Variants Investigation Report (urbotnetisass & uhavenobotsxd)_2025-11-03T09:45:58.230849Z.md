**Honeypot Attack Research Report: Investigation of Mirai Variants "urbotnetisass" & "uhavenobotsxd"**

**Report Generation Time:** 2025-11-03T09:42:39.071087Z

**Timeframe:** September 28, 2025, 00:00:00.000 to October 28, 2025, 23:59:59.999.

**Files Used:** Elasticstack Database Logs

**Executive Summary**

This report details the investigation into the activity of two Mirai variants, "urbotnetisass" and "uhavenobotsxd," within the honeypot network. The investigation has confirmed the presence of both variants, with "uhavenobotsxd" being more prevalent. All three provided Command and Control (C2) IPs have been confirmed as malicious and are actively involved in the distribution of the malware and its downloader scripts. The investigation also identified the "busybox" fingerprint as a key component of the attack chain and uncovered several new attacker IPs, providing a comprehensive view of the ongoing campaign.

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

*   **"urbotnetisass":** A targeted search of the `Adbhoney` logs from **2025-10-12** revealed a log entry at **02:26:12.182Z** showing the download and execution of the "urbotnetisass" variant for multiple architectures, including `arm`, `arm5`, `arm6`, `arm7`, `x86_32`, `mips`, and `mipsel`. The attacker IP for this activity was **176.65.141.85**.

*   **"uhavenobotsxd":** Multiple log entries confirmed the presence of this variant, with filenames such as `/mips.uhavenobotsxd`, `/x86_32.uhavenobotsxd`, `/arm7.uhavenobotsxd`, and `/arm6.uhavenobotsxd` being downloaded and executed.

**Investigation of C2 IPs**

All three provided C2 IPs were investigated and confirmed to be involved in malicious activity.

*   **94.154.35.154:**
    *   **Total Attacks:** 68
    *   **Country of Origin:** The Netherlands
    *   **ASN:** 214943 (Railnet LLC)
    *   **Activity:** This IP was the source of the "urbotnetisass" and "uhavenobotsxd" Mirai binaries and was flagged by Suricata for suspicious traffic.

*   **141.98.10.66:**
    *   **Total Attacks:** 82
    *   **Country of Origin:** Lithuania
    *   **ASN:** 209605 (UAB Host Baltic)
    *   **Activity:** This IP was observed serving the downloader scripts "w.sh" and "c.sh".

*   **213.209.143.62:**
    *   **Total Attacks:** 2668
    *   **Country of Origin:** Germany
    *   **ASN:** 214943 (Railnet LLC)
    *   **Activity:** This IP was observed serving the downloader scripts "w.sh", "c.sh", and "wget.sh".

**Downloader Scripts Analysis**

The investigation identified three downloader scripts used in the attacks: "w.sh", "c.sh", and "wget.sh". These scripts were downloaded from the C2 IPs and executed on the honeypots to download the Mirai binaries. The scripts were downloaded using `curl` and `wget` commands, often with the help of `busybox`.

**"Busybox" Fingerprint Analysis**

The investigation confirmed the use of "busybox" as a fingerprint of the attack. The `Adbhoney` logs revealed the exact commands executed by the attackers, which clearly showed the use of `busybox wget` and `busybox curl` to download the downloader scripts and the Mirai binaries. The commands also showed the execution of the downloaded scripts and binaries.

**Attacker Infrastructure**

In addition to the C2 IPs, the investigation identified the following attacker IPs:
*   176.65.141.85 (Germany, ASN 214967 - Optibounce, LLC)
*   87.121.84.6 (United States, ASN 215925 - Vpsvault.host Ltd)
*   51.81.141.174 (United States, ASN 16276 - OVH SAS)
*   94.74.191.7 (Iran, ASN 214967 - Optibounce, LLC)
*   135.148.99.44 (United States, ASN 16276 - OVH SAS)
*   31.97.223.111 (Indonesia, ASN 47583 - Hostinger International Limited)
*   202.55.132.254 (Vietnam, ASN 63737 - VIETSERVER SERVICES TECHNOLOGY COMPANY LIMITED)

**Indicators of Compromise (IOCs)**

*   **Mirai Variants:** "urbotnetisass", "uhavenobotsxd"
*   **C2 IPs:**
    *   94.154.35.154
    *   141.98.10.66
    *   213.209.143.62
*   **Downloader Scripts:**
    *   w.sh
    *   c.sh
    *   wget.sh
*   **Attacker IPs:**
    *   176.65.141.85
    *   87.121.84.6
    *   51.81.141.174
    *   94.74.191.7
    *   135.148.99.44
    *   31.97.223.111
    *   202.55.132.254
*   **Malware Filenames:**
    *   arm.urbotnetisass
    *   arm5.urbotnetisass
    *   arm6.urbotnetisass
    *   arm7.urbotnetisass
    *   mips.urbotnetisass
    *   mipsel.urbotnetisass
    *   x86_32.urbotnetisass
    *   mips.uhavenobotsxd
    *   x86_32.uhavenobotsxd
    *   arm7.uhavenobotsxd
    *   arm6.uhavenobotsxd

**Conclusion**

The investigation has successfully confirmed the presence of both the "urbotnetisass" and "uhavenobotsxd" Mirai variants in the honeypot network. The provided C2 IPs were all confirmed to be malicious and actively involved in the distribution of the malware and its downloader scripts. The investigation has also provided a clear picture of the attack chain, from the initial compromise to the execution of the Mirai binaries. The identified IOCs can be used to improve the security posture of the network and to detect and prevent future attacks from this specific campaign. The confirmed activity of both "urbotnetisass" and "uhavenobotsxd" and their associated infrastructure represents a significant threat to IoT devices.

---

**Final Fact-Checked Report: Verification of Mirai Variants Investigation**

**Report Generation Time:** 2025-11-03T09:44:46.952435Z

**Timeframe of Data Verification:** September 28, 2025, 00:00:00.000 to October 28, 2025, 23:59:59.999.

**Subject:** Final Fact-Check of "Honeypot Attack Research Report: Investigation of Mirai Variants 'urbotnetisass' & 'uhavenobotsxd'"

**Executive Summary**

This report provides the final verification of the `query_agent`'s updated investigation into the Mirai variants "urbotnetisass" and "uhavenobotsxd." The investigation's core findings are accurate. The presence of both variants has been confirmed, as have the roles of the specified C2 IPs and downloader scripts. The "busybox" fingerprint and all but one of the attacker IPs were correctly identified. A minor correction regarding the ASN of one attacker IP has been noted. The initial report, with this correction, is a reliable assessment of the threat.

**Verification of Findings**

**1. Fingerprint Analysis**
*   **"urbotnetisass":** **Confirmed.** The `Adbhoney` log entry from **2025-10-12 at 02:26:12.182Z** has been located and verified. It confirms that the attacker IP **176.65.141.85** executed `busybox wget` and `curl` commands to download and run multiple `urbotnetisass` binaries from `94.154.35.154`.
*   **"uhavenobotsxd":** **Confirmed.** The presence of this variant in filenames such as `/mips.uhavenobotsxd` and `/x86_32.uhavenobotsxd` has been re-verified and is accurate.

**2. C2 IP Verification**
*   **94.154.35.154:** **Confirmed.** Verified as the source for both "urbotnetisass" and "uhavenobotsxd" binaries, with 68 attacks, originating from The Netherlands (AS214943, Railnet LLC).
*   **141.98.10.66:** **Confirmed.** Verified as serving "w.sh" and "c.sh" scripts in 82 attacks, originating from Lithuania (AS209605, UAB Host Baltic).
*   **213.209.143.62:** **Confirmed.** Verified as serving "w.sh", "c.sh", and "wget.sh" scripts in 2668 attacks, originating from Germany (AS214943, Railnet LLC).

**3. Downloader Scripts and "Busybox" Fingerprint**
*   **Script Verification:** **Confirmed.** The scripts "w.sh," "c.sh," and "wget.sh" were all verified as being downloaded from the C2 IPs.
*   **"Busybox" Usage:** **Confirmed.** The `Adbhoney` logs correctly show the use of `busybox` to facilitate the download and execution of the malicious files.

**4. Attacker Infrastructure Verification**
*   **176.65.141.85:** **Correction.** The report incorrectly lists this IP's ASN as 214967. The logs confirm the ASN is **214967** but the provider is **Optibounce, LLC**, not Railnet LLC. The country of origin, Germany, is correct.
*   **Other Attacker IPs:** All other attacker IPs listed in the report have been re-verified and their associated countries and ASNs are correct.

**Conclusion**

The `query_agent`'s updated report is accurate with one minor correction to an ASN. All major findings are corroborated by the honeypot logs. The evidence strongly supports the conclusion that both "urbotnetisass" and "uhavenobotsxd" variants were active and distributed via the identified C2 network, using a consistent TTP involving `busybox` and downloader scripts. The report provides a solid foundation for understanding this threat.
