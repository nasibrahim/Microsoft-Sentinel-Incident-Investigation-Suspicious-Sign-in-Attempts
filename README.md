 Microsoft Sentinel Incident Investigation – Suspicious Sign-in Attempts

 Overview

This project documents a real-world security investigation conducted using Microsoft Sentinel. My focus on this investigation was on suspicious sign-in attempts targeting disabled accounts from an external IP address.

---

 Incident Summary

- Incident Type: Suspicious Sign-in Activity
- Alert: Sign-ins from IPs attempting access to disabled accounts
- Severity: Medium/High
- Data Source: Azure AD Sign-in Logs

---

 Environment

- SIEM: Microsoft Sentinel
- Log Source: Azure Active Directory
- Investigation Tools:
  - WHOIS Lookup
  - NSLookup
  - VirusTotal
  - AbuseIPDB

---

 IP Investigation

 Source IP Analysis

The suspicious activity originated from an external IP address identified during the incident.

 WHOIS Findings

- IP Range: 147.45.128.0 – 147.45.191.255
- Subnet: 147.45.176.0/24
- Netname: AGROSNAB-NET-128
- Organization: OOO AGROSNAB
- Location: Yekaterinburg, Russia
- ASN: AS216068
- Status: Sub-allocated (likely hosted infrastructure)

🔹 Key Insight

The IP belongs to a sub-allocated network, indicating it may be part of rented or hosted infrastructure often used in automated attacks.

---

 Investigation Findings

- Multiple sign-in attempts were detected from a single IP
- Targeted accounts were disabled accounts
- No successful authentication observed
- Activity pattern suggests automated probing or brute-force attempt

---

 Log Analysis (KQL)

SigninLogs
 where IPAddress startswith "147.45."
 summarize AttemptCount = count() by IPAddress, bin(TimeGenerated, 1h)
 sort by AttemptCount desc

 Outcome:

- Confirmed repeated login attempts from same IP range
- Identified potential infrastructure reuse

---

 Threat Intelligence

- External checks performed using VirusTotal and AbuseIPDB
- Indicators suggest potential malicious or suspicious behavior

* No direct attribution to a specific attacker

---

 Important Note

Geolocation indicates Russia; however:

«This reflects infrastructure location, not necessarily the attacker’s physical location.»

---

 Conclusion

The investigation indicates that the activity is consistent with:

- Automated scanning
- Credential-based attack attempts
- Use of hosted infrastructure for anonymity

---

 Recommendations

- Block or monitor the identified IP and subnet
- Enable Multi-Factor Authentication (MFA)
- Monitor ASN AS216068 for repeated activity
- Implement alert tuning for similar patterns

---

 Skills Demonstrated

- SIEM Investigation (Microsoft Sentinel)
- Log Analysis (KQL)
- Threat Intelligence Enrichment
- WHOIS & Network Analysis
- Incident Reporting

---

 Author
NASIRU IBRAHIM

Cybersecurity enthusiast building SOC and threat detection skills through hands-on labs and real-world simulations.
