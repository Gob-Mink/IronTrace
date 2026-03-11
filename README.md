# Blue Team SOC Analysis — LFI Exploitation & SSH Compromise

> **Capstone Project | IronHack Cybersecurity Bootcamp — January 2026**  
> **Analyst:** Red Wolf  
> **Platform:** TryHackMe (Private Room — Final Scenario)  
> **SIEM:** Splunk  
> **Classification:** Educational / Portfolio

---

## Overview

This repository contains a completed Blue Team SOC (Security Operations Center) analysis report documenting the investigation of a real attack scenario conducted as the final capstone project of the IronHack Cybersecurity Bootcamp.

The investigation was performed entirely within Splunk using provided log data. Starting with no known incident time and no predefined scope, the goal was to independently reconstruct a full attack chain from raw logs — identifying the attacker, the techniques used, the data exposed, and the point of confirmed compromise.

The report demonstrates the following practical skills:

- Splunk log ingestion and sourcetype identification
- Custom field extraction using `rex` when auto-parsing is insufficient
- Progressive investigation methodology — from wide net to targeted queries
- Cross-log correlation between Apache Access Log and Auth Log
- LFI (Local File Inclusion) attack pattern recognition
- IOC identification and documentation
- MITRE ATT&CK framework mapping
- Detection gap analysis
- Professional incident reporting

---

## Scenario

The target environment consisted of a web server that had been compromised by an external threat actor. Two log sources were available for analysis:

| Log Source | Splunk Sourcetype | Purpose |
|------------|-------------------|---------|
| Apache Access Log | `Apache Access Log` | Web server HTTP request logs |
| Auth Log | `Auth Log` | Linux authentication and SSH session logs |

No incident time was known at the start of the investigation. All Time scope was selected intentionally as the correct methodology when no timeframe is established.

---

## Attack Summary

The investigation confirmed a two-phase attack originating from IP address `192.168.178.83`.

### Phase 1 — Local File Inclusion (LFI) Exploitation

The attacker used **FFUF (Fuzz Faster U Fool) v2.0.0-dev**, an automated web fuzzing tool, to enumerate and exploit a Local File Inclusion vulnerability in the web application's `index.php` page parameter.

| Metric | Value |
|--------|-------|
| Total HTTP requests from attacker | 878 |
| Failed LFI attempts (HTTP 500) | 781 |
| Successful LFI reads (HTTP 200) | 97 |

Through the LFI vulnerability, the attacker successfully read 97 files from the server filesystem. Key files accessed included:

| File | Significance |
|------|-------------|
| `/etc/passwd` | Exposed system usernames — `ironhawk` identified |
| `/etc/ssh/sshd_config` | SSH server configuration exposed |
| `/etc/ssh/ssh_config` | SSH client configuration exposed |
| `/etc/ssh/ssh_host_dsa_key.pub` | SSH host public key harvested |

### Phase 2 — SSH Compromise

Using the username `ironhawk` harvested from `/etc/passwd`, the attacker pivoted to a direct SSH attack against the server.

| Metric | Value |
|--------|-------|
| Failed SSH login attempts | 195 |
| Confirmed SSH session | 1 |
| Compromised username | `ironhawk` |
| SSH Process ID (PID) | `51262` |
| Authentication method | PAM unix — password accepted |

The SSH session was opened and subsequently closed, confirmed via Auth Log correlation with the same source IP.

---

## Full Attack Chain

```
[Phase 1 — Apache Access Log]

FFUF Web Fuzzer (192.168.178.83)
        │
        ├── 781 failed LFI attempts (HTTP 500)
        │
        └── 97 successful LFI reads (HTTP 200)
                │
                ├── /etc/passwd ──────────────── username "ironhawk" harvested
                ├── /etc/ssh/sshd_config ──────── SSH server config exposed
                ├── /etc/ssh/ssh_config ───────── SSH client config exposed
                └── /etc/ssh/ssh_host_dsa_key.pub SSH host key harvested

[Phase 2 — Auth Log]

SSH Brute Force (192.168.178.83)
        │
        ├── 195 failed SSH login attempts
        │
        └── SSH session established
                ├── User: ironhawk
                ├── PID: 51262
                ├── Auth: PAM unix — password accepted
                ├── Session: opened
                └── Session: closed
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detected |
|--------|-----------|-----|---------|
| Reconnaissance | Active Scanning | T1595 | ✅ |
| Initial Access | Exploit Public-Facing Application | T1190 | ✅ |
| Credential Access | Unsecured Credentials in Files | T1552.001 | ✅ |
| Discovery | System Information Discovery | T1082 | ✅ |
| Lateral Movement | Remote Services — SSH | T1021.004 | ✅ |
| Execution | Command & Scripting Interpreter | T1059 | ⚠️ Partial |

---

## Splunk Queries Used

All queries used during the investigation are documented in the full report. Key queries included:

**Sourcetype inventory:**
```spl
index=*
| stats count by sourcetype
```

**Attacker activity breakdown:**
```spl
index=* sourcetype="Apache Access Log"
| rex field=_raw "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "HTTP/\d\.\d\"\s(?<status>\d{3})"
| search src_ip="192.168.178.83"
| stats count by status
```

**Confirm /etc/passwd access:**
```spl
index=* sourcetype="Apache Access Log"
| rex field=_raw "^(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "HTTP/\d\.\d\"\s(?<status>\d{3})"
| search src_ip="192.168.178.83" status=200 page="/etc/passwd"
| table _time, page
```

> Full query documentation with results and analysis is available in the report.

---

## Key Skills Demonstrated

**Investigation Methodology**
- Started with unknown incident time — correctly applied All Time scope
- Mapped data landscape before beginning targeted queries
- Identified minimal sourcetype field extraction and adapted using `rex`
- Progressively narrowed from broad to targeted queries

**Log Analysis**
- Apache Access Log — HTTP request analysis, LFI pattern identification, status code analysis
- Auth Log — SSH session lifecycle, PAM authentication events, PID tracking
- Cross-log correlation — linked attacker IP across both sources to confirm the full chain

**Threat Intelligence**
- Identified FFUF tool from User-Agent string
- Recognised LFI attack pattern from page parameter structure
- Identified log poisoning intent from initial proftpd log probe
- Connected credential harvesting to subsequent SSH attack

**Reporting**
- IOC documentation (network, file, authentication)
- MITRE ATT&CK mapping
- Detection gap identification
- Remediation recommendations

---

## Detection Gaps Identified

| Gap | Recommendation |
|-----|---------------|
| Apache sourcetype had no field auto-extraction | Configure proper field extractions for the sourcetype |
| No egress or network flow logs | Ingest firewall logs into Splunk |
| SSH session commands not captured | Enable auditd execve logging |
| No real-time alerting on FFUF activity | Create Splunk alert for known fuzzer user agents |
| No WAF logs available | Deploy ModSecurity and ingest into Splunk |

---

## Repository Contents

| File | Description |
|------|-------------|
| `README.md` | This file — project overview and attack summary |
| `blue-team-soc-report-completed.docx` | Full SOC analysis report with all findings, queries, IOCs, MITRE mapping, and recommendations |

---

## About This Project

This investigation was completed as the final capstone scenario for the **IronHack Cybersecurity Bootcamp (January 2026 cohort)**. The scenario was delivered via a private TryHackMe room requiring students to independently investigate a compromised server environment using Splunk, with no guided steps — replicating a real-world SOC investigation workflow.

---

*Red Wolf | IronHack Cybersecurity Bootcamp — January 2026*
