\# Windows File Integrity Monitoring \& Mini-SIEM



A progressive Windows security monitoring project built in Python, starting with SHA-256 File Integrity Monitoring (FIM) and evolving into a SOC-style Mini-SIEM with endpoint telemetry, event correlation, detection, investigation, and controlled response.



\---



\## Project Evolution



This project was developed progressively as new security capabilities were added.



| Version | Main Capability |

|---|---|

| V1 | Basic SHA-256 File Integrity Monitoring |

| V2 | SQLite Database + Web Dashboard |

| V3 | Alert Investigation + Event Search/Filtering |

| V4 | Windows Security Event 4663 Correlation |

| V5 | SOC Triage / Analyst Investigation UI |

| V6 | Sysmon Event ID 11 Correlation |

| V7 | SOC / Mini-SIEM Features, Detection, Scoring, ATT\&CK Candidates and Response |



\---



\## V1 — Basic File Integrity Monitoring



The first version monitors files using SHA-256 hashes.



\### Capabilities

\- Create a trusted baseline

\- Calculate SHA-256 file hashes

\- Detect file modifications

\- Detect file deletions

\- Generate security alerts

\- Store alert information in JSONL format



\### Security Concept



The baseline represents the known-good state of monitored files.



When the current SHA-256 hash differs from the trusted baseline, the file is considered changed and an alert is generated.



\---



\## V2 — Database \& Dashboard



V2 extended the basic FIM with persistent event storage and a local web dashboard.



\### Added

\- SQLite database

\- Event persistence

\- Flask dashboard

\- Trusted baseline management

\- Security event visibility



This version moved the project from a simple script toward a security monitoring application.



\---



\## V3 — Investigation \& Triage



V3 added analyst-oriented investigation capabilities.



\### Added

\- Event search

\- Event filtering

\- Investigation pages

\- Alert status

\- Analyst notes

\- Investigation workflow



This introduced a simplified SOC analyst workflow:



\*\*Alert → Investigate → Document → Resolve\*\*



\---



\## V4 — Windows Security Event Correlation



V4 introduced Windows Security Event ID 4663 correlation.



The project began correlating FIM activity with Windows audit telemetry to identify:



\- User account

\- Process

\- Process ID

\- File access activity

\- Windows Security event evidence



This helped answer the SOC question:



> Who or what process caused the file activity?



\---



\## V5 — SOC Triage Interface



V5 focused on improving the analyst experience.



\### Added

\- Alert triage

\- Investigation status

\- Analyst notes

\- Alert management

\- SOC-style dashboard



The goal was to make the system behave more like an analyst-facing security console rather than only a monitoring script.



\---



\## V6 — Sysmon Event ID 11



V6 introduced Microsoft Sysmon telemetry.



\### Added

\- Sysmon Event ID 11 correlation

\- Process attribution

\- File creation / overwrite telemetry

\- Correlation status

\- Security event investigation



The workflow became:



\*\*FIM Detection → Sysmon Correlation → Investigation\*\*



\---



\## V7 — Windows FIM \& Mini-SIEM



V7 combines the major capabilities developed throughout the project into a broader SOC-style monitoring platform.



\### Detection \& Monitoring

\- SHA-256 trusted baseline

\- Real-time file monitoring

\- File creation detection

\- File modification detection

\- File deletion detection

\- File move detection



\### Endpoint Telemetry

\- Sysmon Event ID 11

\- Windows Security Event 4663

\- Process information

\- User information

\- Process ID

\- Process GUID

\- Target filename



\### Detection \& Analysis

\- Event normalization

\- Severity scoring

\- Confidence scoring

\- Detection rules

\- Correlation status

\- Analyst-oriented investigation



\### Threat Context

\- MITRE ATT\&CK candidate mapping

\- Candidate mappings are presented for analyst validation rather than treated as proof of malicious activity



\### SOC Workflow

\- Alert investigation

\- Alert status management

\- Analyst notes

\- Controlled response workflow

\- Quarantine capability

\- Response audit logging



\### Data \& Integration

\- SQLite event storage

\- JSON export

\- CSV export

\- REST API

\- Local Flask dashboard



\---



\# Architecture



```text

&#x20;               WINDOWS FILE ACTIVITY

&#x20;                        |

&#x20;                        v

&#x20;              +--------------------+

&#x20;              | Python FIM Engine  |

&#x20;              +--------------------+

&#x20;                        |

&#x20;             +----------+----------+

&#x20;             |                     |

&#x20;             v                     v

&#x20;      SHA-256 Baseline       Endpoint Telemetry

&#x20;                                  |

&#x20;                   +--------------+--------------+

&#x20;                   |                             |

&#x20;                   v                             v

&#x20;            Sysmon Event 11            Windows Security 4663

&#x20;                   |                             |

&#x20;                   +--------------+--------------+

&#x20;                                  |

&#x20;                                  v

&#x20;                        Event Correlation

&#x20;                                  |

&#x20;                                  v

&#x20;                      Detection / Scoring

&#x20;                                  |

&#x20;                                  v

&#x20;                   MITRE ATT\&CK Candidate Context

&#x20;                                  |

&#x20;                                  v

&#x20;                        SOC Investigation

&#x20;                                  |

&#x20;                                  v

&#x20;                      Controlled Response

&#x20;                                  |

&#x20;                                  v

&#x20;                      SQLite + Audit Log

&#x20;                                  |

&#x20;                                  v

&#x20;                        Web Dashboard / API

