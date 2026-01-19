# TA577 PCAP Investigation Walkthrough


This walkthrough documents the **step-by-step analyst workflow** used to investigate suspected **TA577 activity** using only a packet capture (PCAP).  
The goal is to show **how conclusions were reached**, not just the final result.

---

## Step 1 Investigation Preparation & PCAP Overview

Before analysis, the PCAP was validated to understand capture scope, timing, and integrity.

![PCAP Overview](screenshots/01-prep-investigation.png)  
*Figure 1 – PCAP metadata showing capture duration, packet count, timestamps, and file hashes.*

This confirmed:
- Capture spans the reported incident timeframe
- No packet loss indicators
- Sufficient data for investigation

---

## Step 2 Protocol Hierarchy Review

A protocol hierarchy review was performed to quickly identify dominant traffic types.

![Protocol Hierarchy](screenshots/02-protocol-hierachy.png)  
*Figure 2 – Protocol hierarchy showing significant TCP and TLS traffic.*

Key observations:
- TLS dominates the capture
- Limited HTTP traffic (suggesting initial access)
- DNS activity present prior to encrypted sessions

---

## Step 3 Identify Top Talkers (Conversation Analysis)

IPv4 conversations were reviewed to identify the most active external communication.

![Top Talkers](screenshots/03-top-talkers.png)  
*Figure 3 – IPv4 conversation statistics highlighting repeated communication between the victim host and external IPs.*

This revealed:
- Internal host `10.12.15.101` as the primary initiator
- Repeated communication with multiple external IPs

---

## Step 4 DNS Query Analysis

DNS queries were examined to identify suspicious domain lookups.

![DNS Queries](screenshots/04-dns-queries.png)  
*Figure 4 – DNS queries showing lookups for suspicious domains and unusual `.dat` entries.*

Red flags:
- Multiple suspicious domains queried in rapid succession
- Numeric `.dat` pseudo-domains (not normal DNS behavior)

---

## Step 5 DNS Resolution (Domain → IP Mapping)

DNS responses were analyzed to map suspicious domains to IP addresses.

![DNS IP Resolutions](screenshots/05-dns-ip-resolutions.png)  
*Figure 5 – DNS responses resolving malicious domains to external IP addresses.*

This allowed correlation between:
- Domains
- Resolved IPs
- Subsequent network traffic

---

## Step 6 DNS Pivot to Timeline Context

DNS resolution timing was correlated with the incident timeline.

![DNS Timeline Pivot](screenshots/06-dns-ip-pivot.png)  
*Figure 6 – DNS resolutions aligned with timestamps near the reported click event.*

This confirmed:
- DNS activity occurred immediately after the reported user action
- DNS preceded HTTP and TLS traffic

---

## Step 7 HTTP Traffic Analysis (Initial Access)

HTTP requests were filtered to suspicious domains to identify initial access behavior.

![HTTP Requests](screenshots/07-http-requests-narrowed-down.png)  
*Figure 7 – HTTP GET requests to a malicious domain with suspicious URI parameters.*

Findings:
- Malicious domain accessed
- Randomized URI parameters
- Activity consistent with traffic broker infrastructure

---

## Step 8 TLS Session Analysis

TLS traffic was reviewed to identify encrypted follow-on activity.

![TLS Sessions](screenshots/08-tls-sessions.png)  
*Figure 8 – TLS handshake activity showing outbound encrypted connections from the victim host.*

Key indicators:
- TLS initiated by the internal host
- Multiple external destinations
- Encrypted communication following HTTP access

---

## Step 9 Count Repeated TLS Connections

TLS destination IPs were counted to identify repeat communication patterns.

![TLS Destination Frequency](screenshots/09-count-tls-attacker-to-victim.png)  
*Figure 9 – Frequency count showing multiple external IPs contacted exactly 15 times.*

This uniformity strongly suggests:
- Automation
- Beaconing behavior

---

## Step 10 Beacon Timing Analysis

TLS Client Hello timestamps were analyzed to confirm periodic communication.

![Beacon Timing](screenshots/10-ip-time-pattern.png)  
*Figure 10 – TLS Client Hello timestamps showing consistent ~22-minute intervals.*

This timing pattern is characteristic of **command-and-control beaconing** rather than user activity.

---

## Step 11 OSINT Validation of Network Indicators

After identifying suspicious domains and IP addresses through PCAP analysis, open-source intelligence (OSINT) was used to **validate and contextualize** the observed indicators.

> OSINT was used to support attribution and infrastructure analysis only.  
> All conclusions remain grounded in the network behavior observed in the PCAP.

---

### 🔍 Domain Reputation Analysis

#### baumbachers[.]com

*VirusTotal Community & Detection Context*

![VirusTotal – baumbachers.com](screenshots/11-virustotal-baumbachers.png)

- Flagged by **12/93 security vendors**
- Community comments explicitly reference **#Pikabot** and **#TA577**
- Domain reputation aligns with previously reported Pikabot delivery campaigns

This domain was observed in DNS queries and TLS SNI fields during the investigation, directly correlating OSINT data with PCAP evidence.

---

#### ionister[.]com

*VirusTotal Detection & Community Context*

![VirusTotal – ionister.com](screenshots/12-virustotal-ionister.png)

- Flagged by **11/93 vendors** as malicious or phishing-related
- Community comments reference **Pikabot-associated activity**
- Matches domains observed during encrypted TLS communication

---

### IP Reputation Analysis

#### 207.246.75.243 — Encrypted Communication Endpoint

*AbuseIPDB*

![AbuseIPDB – 207.246.75.243](screenshots/13-abuseipdb-207.246.75.243.png)

- Hosted on **Vultr (commodity cloud infrastructure)**
- No direct abuse reports at time of lookup

*VirusTotal IP Reputation*

![VirusTotal – 207.246.75.243](screenshots/14-virustotal-ip-207.246.75.243.png)

- Flagged by **1 vendor** as malicious
- Low detection rate is consistent with **fast-rotating C2 infrastructure**
- Commodity hosting and low reputation signal are common traits in modern malware C2

Importantly, this IP was contacted **repeatedly at regular intervals**, as demonstrated in the TLS beaconing analysis (Step 10).

---

### Correlation to PCAP Evidence

OSINT findings directly correlate with:

- DNS queries observed in **Step 4**
- HTTP access observed in **Step 7**
- TLS SNI values observed in **Step 8**
- Periodic TLS Client Hello timing observed in **Step 10**

While some infrastructure components show **low standalone reputation**, the **combination of network behavior + OSINT context** strongly supports attribution to **TA577 activity associated with Pikabot delivery**.

---

## Final Assessment

Based on:
- Phishing-based initial access
- Malicious ZIP delivery
- DNS, HTTP, and TLS correlation
- Periodic encrypted beaconing

We assess with **high confidence** that the host `10.12.15.101` was compromised and engaged in **TA577-associated command-and-control activity**.

---

## Analyst Takeaway

This investigation demonstrates how **network-only evidence** can be used to:
- Reconstruct attacker behavior
- Identify C2 beaconing
- Support confident incident conclusions without endpoint data
