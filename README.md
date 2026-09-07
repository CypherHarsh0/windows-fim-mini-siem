# Windows File Integrity Monitoring & Mini-SIEM

A progressive Windows security monitoring project built in Python, starting with SHA-256 File Integrity Monitoring (FIM) and evolving into a SOC-style Mini-SIEM with endpoint telemetry, event correlation, detection, investigation, and controlled response.

---

## Project Evolution

This project was developed progressively as new security capabilities were added.

| Version | Main Capability |
|---|---|
| V1 | Basic SHA-256 File Integrity Monitoring |
| V2 | SQLite Database + Web Dashboard |
| V3 | Alert Investigation + Event Search/Filtering |
| V4 | Windows Security Event 4663 Correlation |
| V5 | SOC Triage / Analyst Investigation UI |
| V6 | Sysmon Event ID 11 Correlation |
| V7 | SOC / Mini-SIEM Features, Detection, Scoring, ATT&CK Candidates and Response |

---

## V1 — Basic File Integrity Monitoring

The first version monitors files using SHA-256 hashes.

### Capabilities

- Create a trusted baseline
- Calculate SHA-256 file hashes
- Detect file modifications
- Detect file deletions
- Generate security alerts
- Store alert information in JSONL format

### Security Concept

The baseline represents the known-good state of monitored files.

When the current SHA-256 hash differs from the trusted baseline, the file is considered changed and an alert is generated.

---

## V2 — Database & Dashboard

V2 extended the basic FIM with persistent event storage and a local web dashboard.

### Added

- SQLite database
- Event persistence
- Flask dashboard
- Trusted baseline management
- Security event visibility

This version moved the project from a simple script toward a security monitoring application.

---

## V3 — Investigation & Triage

V3 added analyst-oriented investigation capabilities.

### Added

- Event search
- Event filtering
- Investigation pages
- Alert status
- Analyst notes
- Investigation workflow

This introduced a simplified SOC analyst workflow:

**Alert → Investigate → Document → Resolve**

---

## V4 — Windows Security Event Correlation

V4 introduced Windows Security Event ID 4663 correlation.

The project began correlating FIM activity with Windows audit telemetry to identify:

- User account
- Process
- Process ID
- File access activity
- Windows Security event evidence

This helped answer the SOC question:

> Who or what process caused the file activity?

---

## V5 — SOC Triage Interface

V5 focused on improving the analyst experience.

### Added

- Alert triage
- Investigation status
- Analyst notes
- Alert management
- SOC-style dashboard

The goal was to make the system behave more like an analyst-facing security console rather than only a monitoring script.

---

## V6 — Sysmon Event ID 11

V6 introduced Microsoft Sysmon telemetry.

### Added

- Sysmon Event ID 11 correlation
- Process attribution
- File creation / overwrite telemetry
- Correlation status
- Security event investigation

The workflow became:

**FIM Detection → Sysmon Correlation → Investigation**

---

## V7 — Windows FIM & Mini-SIEM

V7 combines the major capabilities developed throughout the project into a broader SOC-style monitoring platform.

### Detection & Monitoring

- SHA-256 trusted baseline
- Real-time file monitoring
- File creation detection
- File modification detection
- File deletion detection
- File move detection

### Endpoint Telemetry

- Sysmon Event ID 11
- Windows Security Event 4663
- Process information
- User information
- Process ID
- Process GUID
- Target filename

### Detection & Analysis

- Event normalization
- Severity scoring
- Confidence scoring
- Detection rules
- Correlation status
- Analyst-oriented investigation

### Threat Context

- MITRE ATT&CK candidate mapping
- Candidate mappings are presented for analyst validation rather than treated as proof of malicious activity

### SOC Workflow

- Alert investigation
- Alert status management
- Analyst notes
- Controlled response workflow
- Quarantine capability
- Response audit logging

### Data & Integration

- SQLite event storage
- JSON export
- CSV export
- REST API
- Local Flask dashboard

---

## Architecture

```text
                    WINDOWS FILE ACTIVITY
                             |
                             v
                    +------------------+
                    |   Python FIM     |
                    |     Engine       |
                    +------------------+
                             |
               +-------------+-------------+
               |                           |
               v                           v
        SHA-256 Baseline           Endpoint Telemetry
                                            |
                              +-------------+-------------+
                              |                           |
                              v                           v
                       Sysmon Event 11        Windows Security 4663
                              |                           |
                              +-------------+-------------+
                                            |
                                            v
                                   Event Correlation
                                            |
                                            v
                                    Detection / Scoring
                                            |
                                            v
                                  ATT&CK Candidate Context
                                            |
                                            v
                                      SOC Investigation
                                            |
                                            v
                                     Controlled Response
                                            |
                                            v
                                   SQLite + Audit Log
                                            |
                                            v
                                  Web Dashboard / API
---

## Screenshots

### V1 — Basic FIM

![V1 Baseline](screenshots/v1-baseline.png)

![V1 File Modified](screenshots/v1-file-modified.png)

### V2 — Dashboard

![V2 Dashboard](screenshots/v2-dashboard.png)

### V3 — Investigation

![V3 Dashboard](screenshots/v3-dashboard.png)

![V3 Investigation](screenshots/v3-investigation.png)

### V4 — Windows Event 4663

![V4 Investigation](screenshots/v4-4663-investigation.png)

### V5 — SOC Triage

![V5 Analyst Triage](screenshots/v5-analyst-triage.png)

![V5 SOC Triage](screenshots/v5-soc-triage.png)

### V6 — Sysmon Event 11

![V6 Baseline](screenshots/v6-baseline.png)

![V6 Dashboard](screenshots/v6-dashboard-sysmon.png)

![V6 Event 11 Modification](screenshots/v6-event11-modification.png)

![V6 Investigation](screenshots/v6-investigation-sysmon.png)

### V7 — Mini-SIEM

![V7 Baseline](screenshots/v7-baseline.png)

![V7 Dashboard](screenshots/v7-dashboard.png)

![V7 Investigation Analysis](screenshots/v7-investigation-analysis.png)

![V7 Response Playbook](screenshots/v7-response-playbook.png)