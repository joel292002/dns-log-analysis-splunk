# DNS Log Analysis Using Splunk SIEM

## Overview

This project demonstrates how DNS log data can be analyzed using Splunk Enterprise to identify anomalous network activity, investigate suspicious domains, and monitor overall DNS behavior. DNS telemetry provides critical visibility into how internal systems communicate with external infrastructure.

The objective of this project was to simulate a real-world SOC workflow using Zeek DNS log data and perform structured security analysis using Splunk’s Search Processing Language (SPL).

---

## Objectives

- Ingest DNS log data into Splunk
- Extract structured fields from raw Zeek DNS logs
- Analyze DNS traffic patterns
- Detect NXDOMAIN anomalies
- Identify high-volume DNS sources (top talkers)
- Investigate suspicious domain activity
- Visualize DNS activity over time

---

## Environment

- Splunk Enterprise
- Zeek DNS log dataset
- Local Splunk instance

Index: `main`  
Sourcetype: `dns_sample`

---

## Dataset Description

The dataset consists of Zeek-generated DNS logs containing network telemetry. Each event includes:

- Source IP address (`id.orig_h`)
- Destination DNS server (`id.resp_h`)
- Queried domain (`query`)
- Query type (`qtype_name`)
- Response code (`rcode_name`)
- Protocol and port information

The logs were uploaded into Splunk using the "Add Data" feature and indexed for analysis.

---

## Methodology

### 1. Data Ingestion

The DNS log file was uploaded into Splunk and verified using:

```spl
index=main sourcetype=dns_sample
```

This step ensured the logs were successfully indexed and available for analysis.

---

### 2. Field Extraction

Since Zeek logs were not automatically parsed into structured fields, custom extraction was performed using a regex-based `rex` command.

```spl
| rex field=_raw "^(?<ts>\S+)\s+(?<uid>\S+)\s+(?<id_orig_h>\S+)\s+(?<id_orig_p>\S+)\s+(?<id_resp_h>\S+)\s+(?<id_resp_p>\S+)\s+(?<proto>\S+)\s+(?<trans_id>\S+)\s+(?<query>\S+)\s+(?<qclass>\S+)\s+(?<qclass_name>\S+)\s+(?<qtype>\S+)\s+(?<qtype_name>\S+)\s+(?<rcode>\S+)\s+(?<rcode_name>\S+)"
```

This enabled structured access to DNS fields for further analysis.

---

### 3. Top Domain Analysis

To establish baseline DNS behavior, the most frequently queried domains were identified.

```spl
| stats count by query
| sort -count
```

This helps distinguish normal traffic patterns from unusual domain activity.

---

### 4. NXDOMAIN Detection

DNS resolution failures were analyzed to detect abnormal patterns.

```spl
| search rcode_name=NXDOMAIN
| stats count by id_orig_h, query
| sort -count
```

High NXDOMAIN activity may indicate automated domain generation or misconfigured systems.

---

### 5. Top Talker Analysis

DNS traffic volume was aggregated by source host to identify systems generating excessive DNS queries.

```spl
| stats count by id_orig_h
| sort -count
```

Hosts with unusually high activity were flagged for further investigation.

---

### 6. Suspicious Domain Investigation

Queries targeting higher-risk TLD domains were filtered.

```spl
| search query="*.xyz" OR query="*.ru" OR query="*.top"
| stats count by query id_orig_h
```

This simulates threat intelligence-driven DNS hunting.

---

### 7. Traffic Trend Visualization

DNS activity patterns were visualized over time.

```spl
| timechart count
```

Time-based visualization helps detect spikes, bursts, or irregular network behavior.

---

## Key Findings

- Certain internal hosts generated significantly higher DNS traffic compared to peers.
- Elevated NXDOMAIN activity was observed from specific systems.
- Queries to high-risk TLD domains were identified.
- DNS traffic visualization revealed periodic spikes in activity.

---

## Skills Demonstrated

- SIEM log ingestion and validation
- Manual field extraction using regex
- SPL query development
- DNS behavioral analysis
- Anomaly detection techniques
- Threat hunting methodology
- Security data visualization

---

## Repository Structure

```
dns-log-analysis-splunk/
├── README.md
├── spl_queries.txt
└── screenshots/
```

The screenshots directory contains visual evidence of each analysis stage.

---

## Conclusion

This project demonstrates how DNS telemetry can be leveraged within a SIEM platform to detect anomalies, investigate suspicious activity, and support proactive threat hunting workflows. It reflects a structured SOC-style process from data ingestion to analysis and visualization.
