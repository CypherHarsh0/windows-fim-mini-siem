"""
FIM V7 - Single-file SOC / Mini-SIEM Lab

Includes:
- SHA-256 trusted baseline
- Real-time FIM (created/modified/deleted/moved)
- Sysmon Event 11 correlation
- Windows Security 4663 correlation
- Event normalization and severity scoring
- Detection rules
- MITRE ATT&CK technique candidates
- SQLite event store
- SOC dashboard
- Alert investigation
- Analyst notes/status
- Response playbooks (SAFE LAB SCOPE ONLY)
- JSON/CSV export
- REST API

IMPORTANT:
This is a defensive local lab application.
Automated response is disabled by default and is restricted to the
configured SOC-Lab/Monitored directory.
"""

import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    url_for,
)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MONITORED_DIR = BASE_DIR / "SOC-Lab" / "Monitored"
BASELINE_FILE = BASE_DIR / "baseline_v7.json"
DATABASE_FILE = BASE_DIR / "fim_v7.db"
QUARANTINE_DIR = BASE_DIR / "SOC-Lab" / "Quarantine"

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

HOST = "127.0.0.1"
PORT = 5000

SYSMON_WINDOW_SECONDS = 30
RETRY_INTERVAL_SECONDS = 2
MAX_RETRIES = 8

# Safety switch: response actions are manual by default.
AUTO_RESPONSE_ENABLED = False

RISKY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd",
    ".vbs", ".js", ".hta", ".scr"
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

app = Flask(__name__)


# ============================================================
# COMMON
# ============================================================

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def username():
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME", "UNKNOWN")


def normalize(path):
    return str(Path(path).resolve()).lower()


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def safe_lab_path(path):
    """
    Returns True only when the target resolves inside the monitored lab
    directory. This guard is used by response actions.
    """
    try:
        target = Path(path).resolve()
        root = MONITORED_DIR.resolve()
        target.relative_to(root)
        return True
    except (ValueError, OSError):
        return False


def process_basename(process_name):
    if not process_name:
        return ""
    return Path(str(process_name)).name.lower()


# ============================================================
# BASELINE
# ============================================================

def load_baseline():
    if not BASELINE_FILE.exists():
        return {}
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_baseline(baseline):
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)


def create_baseline():
    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

    baseline = {}

    for path in MONITORED_DIR.rglob("*"):
        if not path.is_file():
            continue

        digest = sha256_file(path)
        if not digest:
            continue

        baseline[normalize(path)] = {
            "hash": digest,
            "algorithm": "SHA-256",
            "created_at": now_text(),
        }

    save_baseline(baseline)
    return len(baseline)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER DEFAULT 0,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            username TEXT,
            process_name TEXT,
            process_id TEXT,
            process_guid TEXT,
            target_filename TEXT,
            windows_event_id INTEGER,
            windows_access TEXT,
            correlation_status TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            mitre_description TEXT,
            detection_rule TEXT,
            status TEXT DEFAULT 'NEW',
            analyst_notes TEXT,
            response_action TEXT,
            response_status TEXT,
            details TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            event_id INTEGER,
            target TEXT,
            result TEXT,
            details TEXT
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_time
        ON events(timestamp)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_severity
        ON events(severity)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_status
        ON events(status)
    """)

    conn.commit()
    conn.close()


# ============================================================
# SEVERITY / DETECTION / MITRE
# ============================================================

def detection_context(event_type, file_path, process_name=None, sysmon_found=False):
    ext = Path(str(file_path)).suffix.lower()
    process = process_basename(process_name)

    score = 0
    reasons = []

    if event_type == "FILE_DELETED":
        score += 50
        reasons.append("Protected file deletion")

    elif event_type == "FILE_MODIFIED":
        score += 30
        reasons.append("Trusted file hash changed")

    elif event_type == "FILE_CREATED":
        score += 15
        reasons.append("New file appeared in monitored folder")

    elif event_type == "FILE_MOVED":
        score += 25
        reasons.append("File moved/renamed")

    if ext in RISKY_EXTENSIONS:
        score += 30
        reasons.append(f"High-risk extension: {ext}")

    if process in SUSPICIOUS_PROCESSES:
        score += 25
        reasons.append(f"Script/interpreter process: {process}")

    if sysmon_found:
        score += 15
        reasons.append("Sysmon Event 11 correlated")

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 55:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return severity, min(score, 100), reasons


def mitre_candidate(event_type, file_path, process_name=None):
    """
    ATT&CK mapping is expressed as a candidate, not a claim that an
    adversary definitely used the technique.
    """
    process = process_basename(process_name)

    if event_type == "FILE_DELETED":
        return (
            "Defense Evasion",
            "T1070.004",
            "File and Directory Discovery/Deletion context; "
            "use T1070.004 as a candidate for file deletion."
        )

    if process == "powershell.exe" or process == "pwsh.exe":
        return (
            "Execution",
            "T1059.001",
            "PowerShell execution candidate."
        )

    if process == "cmd.exe":
        return (
            "Execution",
            "T1059.003",
            "Windows Command Shell execution candidate."
        )

    if process in {"wscript.exe", "cscript.exe"}:
        return (
            "Execution",
            "T1059.005",
            "Visual Basic execution through Windows Script Host candidate."
        )

    if process == "mshta.exe":
        return (
            "Execution",
            "T1218.005",
            "Mshta proxy execution candidate."
        )

    if process == "rundll32.exe":
        return (
            "Defense Evasion",
            "T1218.011",
            "Rundll32 signed binary proxy execution candidate."
        )

    if process == "regsvr32.exe":
        return (
            "Defense Evasion",
            "T1218.010",
            "Regsvr32 signed binary proxy execution candidate."
        )

    if Path(str(file_path)).suffix.lower() in RISKY_EXTENSIONS:
        return (
            "Defense Evasion",
            "T1036",
            "Masquerading-related candidate; requires analyst validation."
        )

    return (
        "Impact / Defense Evasion",
        "T1485",
        "No definitive ATT&CK technique inferred; analyst validation required."
    )


# ============================================================
# POWERSHELL
# ============================================================

def run_powershell(script, timeout=10):
    try:
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError,
    ):
        return ""


# ============================================================
# SYSMON EVENT 11
# ============================================================

def query_sysmon_event_11(file_path):
    exact = str(Path(file_path).resolve()).replace("'", "''")

    script = f"""
$events = Get-WinEvent `
    -FilterHashtable @{{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=11
        StartTime=(Get-Date).AddSeconds(-{SYSMON_WINDOW_SECONDS})
    }} `
    -MaxEvents 500 `
    -ErrorAction SilentlyContinue

$result = foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = @{{}}

    foreach ($item in $xml.Event.EventData.Data) {{
        $data[$item.Name] = [string]$item.'#text'
    }}

    if ($data.TargetFilename -ieq '{exact}') {{
        [PSCustomObject]@{{
            TimeCreated = $event.TimeCreated.ToString('o')
            EventId = $event.Id
            ProcessGuid = $data.ProcessGuid
            ProcessId = $data.ProcessId
            Image = $data.Image
            TargetFilename = $data.TargetFilename
            User = $data.User
        }}
    }}
}}

$result | ConvertTo-Json -Compress
"""

    output = run_powershell(script)

    if not output:
        return []

    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        return []


def find_sysmon_11(file_path):
    for attempt in range(MAX_RETRIES):
        events = query_sysmon_event_11(file_path)

        if events:
            events.sort(
                key=lambda x: x.get("TimeCreated", ""),
                reverse=True
            )
            return events[0]

        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_INTERVAL_SECONDS)

    return None


# ============================================================
# WINDOWS 4663
# ============================================================

def query_windows_4663(file_path):
    exact = str(Path(file_path).resolve()).replace("'", "''")

    script = f"""
$events = Get-WinEvent `
    -FilterHashtable @{{
        LogName='Security'
        Id=4663
        StartTime=(Get-Date).AddSeconds(-{SYSMON_WINDOW_SECONDS})
    }} `
    -MaxEvents 500 `
    -ErrorAction SilentlyContinue

$result = foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = @{{}}

    foreach ($item in $xml.Event.EventData.Data) {{
        $data[$item.Name] = [string]$item.'#text'
    }}

    if ($data.ObjectName -ieq '{exact}') {{
        [PSCustomObject]@{{
            TimeCreated = $event.TimeCreated.ToString('o')
            EventId = $event.Id
            AccountName = $data.SubjectUserName
            ProcessId = $data.ProcessId
            ProcessName = $data.ProcessName
            ObjectName = $data.ObjectName
            AccessList = $data.AccessList
            AccessMask = $data.AccessMask
        }}
    }}
}}

$result | ConvertTo-Json -Compress
"""

    output = run_powershell(script)

    if not output:
        return []

    try:
        data = json.loads(output)
        return [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        return []


def find_relevant_4663(file_path):
    events = query_windows_4663(file_path)

    best = None
    best_score = -1

    for event in events:
        access = (event.get("AccessList") or "").lower()

        # Prefer actual write/delete access; ignore read-only noise.
        if "delete" in access:
            score = 100
        elif "write" in access:
            score = 95
        elif "append" in access:
            score = 90
        else:
            score = -1

        if score > best_score:
            best_score = score
            best = event

    return best


# ============================================================
# EVENT PIPELINE
# ============================================================

def store_security_event(event_type, file_path, old_hash=None, new_hash=None):
    path = str(Path(file_path).resolve())

    sysmon = find_sysmon_11(path)
    windows = find_relevant_4663(path)

    process_name = None
    process_id = None
    process_guid = None
    process_user = None
    target_filename = None
    windows_event_id = None
    windows_access = None

    if sysmon:
        process_name = sysmon.get("Image")
        process_id = str(sysmon.get("ProcessId") or "")
        process_guid = sysmon.get("ProcessGuid")
        process_user = sysmon.get("User")
        target_filename = sysmon.get("TargetFilename")

    if windows:
        windows_event_id = windows.get("EventId")
        windows_access = windows.get("AccessList")

        if not process_name:
            process_name = windows.get("ProcessName")

        if not process_id:
            process_id = str(windows.get("ProcessId") or "")

    severity, confidence, reasons = detection_context(
        event_type,
        path,
        process_name,
        sysmon_found=bool(sysmon),
    )

    mitre_tactic, mitre_technique, mitre_description = mitre_candidate(
        event_type,
        path,
        process_name
    )

    if sysmon and windows:
        correlation_status = "FULL_CORRELATION"
    elif sysmon:
        correlation_status = "SYSMON_EVENT_11"
    elif windows:
        correlation_status = "WINDOWS_4663"
    else:
        correlation_status = "FIM_ONLY"

    detection_rule = "; ".join(reasons) if reasons else "FIM integrity event"

    details = (
        f"Confidence={confidence}/100. "
        f"Sources: FIM"
        f"{' + Sysmon11' if sysmon else ''}"
        f"{' + Windows4663' if windows else ''}. "
        f"ATT&CK is a candidate mapping and requires analyst validation."
    )

    conn = get_db()

    cur = conn.execute("""
        INSERT INTO events (
            timestamp,
            source,
            event_type,
            severity,
            confidence,
            file_path,
            old_hash,
            new_hash,
            username,
            process_name,
            process_id,
            process_guid,
            target_filename,
            windows_event_id,
            windows_access,
            correlation_status,
            mitre_tactic,
            mitre_technique,
            mitre_description,
            detection_rule,
            status,
            details
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (
        now_text(),
        "FIM",
        event_type,
        severity,
        confidence,
        path,
        old_hash,
        new_hash,
        username(),
        process_name,
        process_id,
        process_guid,
        target_filename,
        windows_event_id,
        windows_access,
        correlation_status,
        mitre_tactic,
        mitre_technique,
        mitre_description,
        detection_rule,
        "NEW",
        details,
    ))

    event_id = cur.lastrowid

    conn.commit()
    conn.close()

    return {
        "id": event_id,
        "severity": severity,
        "confidence": confidence,
        "sysmon": sysmon,
        "windows": windows,
        "process_name": process_name,
        "process_id": process_id,
        "process_guid": process_guid,
        "process_user": process_user,
        "correlation": correlation_status,
        "mitre": mitre_technique,
        "reasons": reasons,
    }


# ============================================================
# SAFE RESPONSE
# ============================================================

def audit(action, event_id, target, result, details=""):
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_log (
            timestamp,
            username,
            action,
            event_id,
            target,
            result,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        now_text(),
        username(),
        action,
        event_id,
        str(target),
        result,
        details,
    ))
    conn.commit()
    conn.close()


def quarantine_file(event_id):
    conn = get_db()

    event = conn.execute(
        "SELECT * FROM events WHERE id=?",
        (event_id,)
    ).fetchone()

    conn.close()

    if event is None:
        return False, "Event not found."

    target = Path(event["file_path"])

    if not target.exists():
        return False, "File no longer exists."

    if not safe_lab_path(target):
        return False, "Response blocked: target is outside the lab folder."

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    destination = QUARANTINE_DIR / f"{target.name}.{stamp}.quarantine"

    try:
        shutil.move(str(target), str(destination))

        conn = get_db()
        conn.execute("""
            UPDATE events
            SET response_action=?,
                response_status=?,
                status='INVESTIGATING'
            WHERE id=?
        """, (
            "QUARANTINE",
            "SUCCESS",
            event_id,
        ))
        conn.commit()
        conn.close()

        audit(
            "QUARANTINE",
            event_id,
            target,
            "SUCCESS",
            f"Moved to {destination}"
        )

        return True, f"Quarantined to {destination}"

    except (OSError, shutil.Error) as exc:
        audit(
            "QUARANTINE",
            event_id,
            target,
            "FAILED",
            str(exc)
        )
        return False, f"Quarantine failed: {exc}"


def restore_quarantined(quarantine_name, event_id):
    source = QUARANTINE_DIR / Path(quarantine_name).name

    if not source.exists():
        return False, "Quarantine file not found."

    if not safe_lab_path(source.parent):
        return False, "Invalid quarantine path."

    conn = get_db()
    event = conn.execute(
        "SELECT * FROM events WHERE id=?",
        (event_id,)
    ).fetchone()
    conn.close()

    if event is None:
        return False, "Event not found."

    target = Path(event["file_path"])

    if not safe_lab_path(target):
        return False, "Restore blocked."

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(target))

        audit(
            "RESTORE",
            event_id,
            target,
            "SUCCESS",
            f"Restored from {source}"
        )

        conn = get_db()
        conn.execute("""
            UPDATE events
            SET response_action='RESTORE',
                response_status='SUCCESS'
            WHERE id=?
        """, (event_id,))
        conn.commit()
        conn.close()

        return True, f"Restored to {target}"

    except (OSError, shutil.Error) as exc:
        audit(
            "RESTORE",
            event_id,
            target,
            "FAILED",
            str(exc)
        )
        return False, f"Restore failed: {exc}"


# ============================================================
# ANALYST WORKFLOW
# ============================================================

VALID_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE POSITIVE",
}


def set_status(event_id, status):
    if status not in VALID_STATUSES:
        return False

    conn = get_db()
    conn.execute(
        "UPDATE events SET status=? WHERE id=?",
        (status, event_id)
    )
    conn.commit()
    conn.close()

    audit(
        "STATUS_CHANGE",
        event_id,
        "",
        "SUCCESS",
        status
    )

    return True


def save_notes(event_id, notes):
    conn = get_db()
    conn.execute(
        "UPDATE events SET analyst_notes=? WHERE id=?",
        (notes, event_id)
    )
    conn.commit()
    conn.close()

    audit(
        "SAVE_NOTES",
        event_id,
        "",
        "SUCCESS"
    )


# ============================================================
# FILE MONITOR
# ============================================================

class FIMHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.baseline = load_baseline()
        self.last_seen = {}

    def debounce(self, path):
        key = normalize(path)
        current = time.time()
        previous = self.last_seen.get(key, 0)

        if current - previous < 1.0:
            return False

        self.last_seen[key] = current
        return True

    def process(self, event_type, path, old_hash=None, new_hash=None):
        result = store_security_event(
            event_type,
            path,
            old_hash,
            new_hash
        )

        print("\n" + "=" * 95)
        print("                         FIM V7 SECURITY ALERT")
        print("=" * 95)
        print(f"Event ID          : {result['id']}")
        print(f"Event             : {event_type}")
        print(f"Severity          : {result['severity']}")
        print(f"Confidence        : {result['confidence']}/100")
        print(f"File              : {path}")
        print(f"User              : {username()}")
        print(f"Process           : {result['process_name'] or 'N/A'}")
        print(f"PID               : {result['process_id'] or 'N/A'}")
        print(f"Correlation       : {result['correlation']}")
        print(f"MITRE Candidate   : {result['mitre']}")
        print("=" * 95)

    def on_created(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        time.sleep(0.3)

        digest = sha256_file(path)
        if not digest:
            return

        key = normalize(path)

        if key in self.baseline:
            old_hash = self.baseline[key]["hash"]

            if old_hash == digest:
                return

            self.process(
                "FILE_MODIFIED",
                path,
                old_hash,
                digest
            )
        else:
            self.process(
                "FILE_CREATED",
                path,
                None,
                digest
            )

    def on_modified(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        time.sleep(0.2)

        digest = sha256_file(path)
        if not digest:
            return

        key = normalize(path)

        if key not in self.baseline:
            return

        old_hash = self.baseline[key]["hash"]

        if old_hash == digest:
            return

        self.process(
            "FILE_MODIFIED",
            path,
            old_hash,
            digest
        )

    def on_deleted(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        key = normalize(path)

        old_hash = None

        if key in self.baseline:
            old_hash = self.baseline[key]["hash"]

        self.process(
            "FILE_DELETED",
            path,
            old_hash,
            None
        )

    def on_moved(self, event):
        if event.is_directory:
            return

        path = f"{event.src_path} -> {event.dest_path}"

        self.process(
            "FILE_MOVED",
            path,
            None,
            None
        )


# ============================================================
# HTML
# ============================================================

BASE_STYLE = """
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    padding: 28px;
    background: #0b1220;
    color: #f8fafc;
    font-family: Arial, sans-serif;
}

h1 { margin: 0; }
h2 { margin-top: 0; }

.subtitle {
    color: #94a3b8;
    margin: 7px 0 25px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 15px;
    margin-bottom: 22px;
}

.card, .panel {
    background: #182338;
    border: 1px solid #2a3b5e;
    border-radius: 14px;
    padding: 19px;
}

.card h2 {
    font-size: 30px;
    margin: 0;
}

.label {
    display: block;
    color: #94a3b8;
    font-size: 12px;
    margin-bottom: 6px;
}

.value {
    word-break: break-word;
}

.critical { color: #ff5252; font-weight: bold; }
.high { color: #ffb020; font-weight: bold; }
.medium { color: #facc15; font-weight: bold; }
.low { color: #38bdf8; font-weight: bold; }

.good { color: #4ade80; font-weight: bold; }
.warn { color: #fb923c; font-weight: bold; }

button, input, select, textarea {
    border: 1px solid #334155;
    background: #0f172a;
    color: white;
    padding: 9px;
    border-radius: 7px;
}

button { cursor: pointer; }

textarea {
    width: 100%;
    min-height: 140px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    padding: 11px;
    border-bottom: 1px solid #2a3b5e;
    text-align: left;
    vertical-align: top;
}

th { background: #223250; }

tr:hover { background: #202e47; }

.file, .process, .hash {
    max-width: 330px;
    word-break: break-all;
}

a {
    color: #60a5fa;
    text-decoration: none;
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.evidence-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 12px;
}

.evidence {
    background: #0f172a;
    padding: 13px;
    border-radius: 9px;
    border: 1px solid #233450;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    background: #0f172a;
    padding: 13px;
    border-radius: 9px;
}
</style>
"""


DASHBOARD_HTML = BASE_STYLE + r"""
<!DOCTYPE html>
<html>
<head>
<title>FIM V7 SOC</title>
<meta http-equiv="refresh" content="12">
</head>

<body>

<h1>🛡 FIM V7 — SOC / Mini-SIEM Console</h1>

<div class="subtitle">
FIM + Sysmon Event 11 + Windows 4663 + Detection Rules + ATT&CK + Response
</div>


<div class="grid">

<div class="card">
<h2>{{ total }}</h2>
<span class="label">Total Events</span>
</div>

<div class="card">
<h2 class="critical">{{ critical }}</h2>
<span class="label">Critical</span>
</div>

<div class="card">
<h2 class="high">{{ high }}</h2>
<span class="label">High</span>
</div>

<div class="card">
<h2 class="medium">{{ medium }}</h2>
<span class="label">Medium</span>
</div>

<div class="card">
<h2 class="good">{{ full }}</h2>
<span class="label">Full Correlation</span>
</div>

<div class="card">
<h2 class="warn">{{ open_alerts }}</h2>
<span class="label">Open Alerts</span>
</div>

</div>


<div class="panel">

<h2>Latest Security Event</h2>

{% if latest %}

<div class="evidence-grid">

<div class="evidence">
<span class="label">Event</span>
{{ latest["event_type"] }}
</div>

<div class="evidence">
<span class="label">Severity</span>
<span class="{{ latest["severity"].lower() }}">
{{ latest["severity"] }}
</span>
</div>

<div class="evidence">
<span class="label">Confidence</span>
{{ latest["confidence"] }}/100
</div>

<div class="evidence">
<span class="label">Status</span>
{{ latest["status"] }}
</div>

<div class="evidence">
<span class="label">File</span>
<span class="value">{{ latest["file_path"] }}</span>
</div>

<div class="evidence">
<span class="label">User</span>
{{ latest["username"] }}
</div>

<div class="evidence">
<span class="label">Process</span>
{{ latest["process_name"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">PID</span>
{{ latest["process_id"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">Correlation</span>
{% if latest["correlation_status"] == "FULL_CORRELATION" %}
<span class="good">FULL CORRELATION</span>
{% elif latest["correlation_status"] == "SYSMON_EVENT_11" %}
<span class="good">SYSMON EVENT 11</span>
{% else %}
<span class="warn">{{ latest["correlation_status"] }}</span>
{% endif %}
</div>

<div class="evidence">
<span class="label">ATT&CK Candidate</span>
{{ latest["mitre_technique"] }}
</div>

</div>

<p>
<a href="/event/{{ latest['id'] }}">→ Open full investigation</a>
</p>

{% else %}

<p>No events yet.</p>

{% endif %}

</div>


<br>


<div class="panel">

<h2>Event Explorer</h2>

<form method="GET">

<input
name="search"
placeholder="Search file / process / user"
value="{{ search }}"
>

<select name="severity">

<option value="">All Severity</option>

<option value="CRITICAL"
{% if severity == "CRITICAL" %}selected{% endif %}>
CRITICAL
</option>

<option value="HIGH"
{% if severity == "HIGH" %}selected{% endif %}>
HIGH
</option>

<option value="MEDIUM"
{% if severity == "MEDIUM" %}selected{% endif %}>
MEDIUM
</option>

</select>


<select name="status">

<option value="">All Status</option>

<option value="NEW"
{% if status == "NEW" %}selected{% endif %}>
NEW
</option>

<option value="INVESTIGATING"
{% if status == "INVESTIGATING" %}selected{% endif %}>
INVESTIGATING
</option>

<option value="RESOLVED"
{% if status == "RESOLVED" %}selected{% endif %}>
RESOLVED
</option>

<option value="FALSE POSITIVE"
{% if status == "FALSE POSITIVE" %}selected{% endif %}>
FALSE POSITIVE
</option>

</select>


<button type="submit">Filter</button>

<a href="/">Clear</a>

</form>

</div>


<br>


<div class="panel">

<table>

<tr>
<th>ID</th>
<th>Time</th>
<th>Event</th>
<th>Severity</th>
<th>File</th>
<th>Process</th>
<th>Correlation</th>
<th>ATT&CK</th>
<th>Action</th>
</tr>


{% for event in events %}

<tr>

<td>{{ event["id"] }}</td>

<td>{{ event["timestamp"] }}</td>

<td>{{ event["event_type"] }}</td>

<td class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</td>

<td class="file">
{{ event["file_path"] }}
</td>

<td class="process">
{{ event["process_name"] or "N/A" }}
<br>
PID: {{ event["process_id"] or "N/A" }}
</td>

<td>
{{ event["correlation_status"] }}
</td>

<td>
{{ event["mitre_technique"] }}
</td>

<td>
<a href="/event/{{ event['id'] }}">
Investigate
</a>
</td>

</tr>

{% endfor %}

</table>

</div>


<p>
<a href="/export/events.csv">Export CSV</a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="/export/events.json">Export JSON</a>
&nbsp;&nbsp;|&nbsp;&nbsp;
<a href="/audit">Response Audit Log</a>
</p>


</body>
</html>
"""


INVESTIGATION_HTML = BASE_STYLE + r"""
<!DOCTYPE html>
<html>
<head>
<title>FIM V7 Investigation</title>
</head>

<body>

<a href="/">← Back to SOC Console</a>

<br><br>

<div class="panel">

<h1>🔎 Security Event #{{ event["id"] }}</h1>

<p>
<span class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</span>
—
{{ event["event_type"] }}
</p>

</div>


<br>


<div class="panel">

<h2>1. Integrity Evidence</h2>

<div class="evidence-grid">

<div class="evidence">
<span class="label">Timestamp</span>
{{ event["timestamp"] }}
</div>

<div class="evidence">
<span class="label">File</span>
<span class="value">{{ event["file_path"] }}</span>
</div>

<div class="evidence">
<span class="label">Old SHA-256</span>
<span class="hash">{{ event["old_hash"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">New SHA-256</span>
<span class="hash">{{ event["new_hash"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">Severity</span>
{{ event["severity"] }}
</div>

<div class="evidence">
<span class="label">Confidence</span>
{{ event["confidence"] }}/100
</div>

</div>

</div>


<div class="panel">

<h2>2. Endpoint / Telemetry Evidence</h2>

<div class="evidence-grid">

<div class="evidence">
<span class="label">User</span>
{{ event["username"] }}
</div>

<div class="evidence">
<span class="label">Process</span>
{{ event["process_name"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">PID</span>
{{ event["process_id"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">Process GUID</span>
{{ event["process_guid"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">Process User</span>
{{ event["process_user"] or "N/A" }}
</div>

<div class="evidence">
<span class="label">Target Filename</span>
{{ event["target_filename"] or "N/A" }}
</div>

</div>

</div>


<div class="panel">

<h2>3. Correlation</h2>

<p>
<strong>Status:</strong>
{{ event["correlation_status"] }}
</p>

{% if event["sysmon_event_id"] == 11 %}

<p class="good">
✓ Sysmon Event 11 correlated
</p>

{% else %}

<p class="warn">
⚠ No matching Sysmon Event 11
</p>

{% endif %}

{% if event["windows_event_id"] == 4663 %}

<p class="good">
✓ Windows Security 4663 correlated
</p>

{% endif %}

</div>


<div class="panel">

<h2>4. Detection Rule</h2>

<pre>{{ event["detection_rule"] }}</pre>

<p>
{{ event["details"] }}
</p>

</div>


<div class="panel">

<h2>5. MITRE ATT&CK Candidate</h2>

<div class="evidence-grid">

<div class="evidence">
<span class="label">Tactic</span>
{{ event["mitre_tactic"] }}
</div>

<div class="evidence">
<span class="label">Technique</span>
{{ event["mitre_technique"] }}
</div>

<div class="evidence">
<span class="label">Interpretation</span>
{{ event["mitre_description"] }}
</div>

</div>

<p class="warn">
ATT&CK mapping is a candidate for analyst validation, not proof of adversary behavior.
</p>

</div>


<div class="panel">

<h2>6. Analyst Triage</h2>

<p>
<strong>Current status:</strong>
{{ event["status"] }}
</p>

<div class="actions">

<form method="POST"
action="/event/{{ event['id'] }}/status">

<button name="status" value="NEW">NEW</button>
<button name="status" value="INVESTIGATING">INVESTIGATING</button>
<button name="status" value="RESOLVED">RESOLVED</button>
<button name="status" value="FALSE POSITIVE">FALSE POSITIVE</button>

</form>

</div>

<br>

<form method="POST"
action="/event/{{ event['id'] }}/notes">

<textarea
name="notes"
placeholder="Enter your investigation notes..."
>{{ event["analyst_notes"] or "" }}</textarea>

<br><br>

<button type="submit">Save Analyst Notes</button>

</form>

</div>


<div class="panel">

<h2>7. Response Playbook</h2>

<p>
Response is restricted to your local <code>SOC-Lab/Monitored</code> folder.
Nothing outside the lab folder can be quarantined.
</p>

<div class="actions">

<form method="POST"
action="/event/{{ event['id'] }}/quarantine">

<button type="submit">
Quarantine File
</button>

</form>

</div>

<p>
<strong>Response:</strong>
{{ event["response_action"] or "None" }}
—
{{ event["response_status"] or "Not executed" }}
</p>

</div>


</body>
</html>
"""


AUDIT_HTML = BASE_STYLE + r"""
<!DOCTYPE html>
<html>
<head>
<title>FIM V7 Audit Log</title>
</head>

<body>

<a href="/">← Back</a>

<h1>Response Audit Log</h1>

<div class="panel">

<table>

<tr>
<th>Time</th>
<th>User</th>
<th>Action</th>
<th>Event</th>
<th>Target</th>
<th>Result</th>
<th>Details</th>
</tr>

{% for row in rows %}

<tr>

<td>{{ row["timestamp"] }}</td>
<td>{{ row["username"] }}</td>
<td>{{ row["action"] }}</td>
<td>{{ row["event_id"] }}</td>
<td class="file">{{ row["target"] }}</td>
<td>{{ row["result"] }}</td>
<td>{{ row["details"] }}</td>

</tr>

{% endfor %}

</table>

</div>

</body>
</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def dashboard():

    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()

    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    critical = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='CRITICAL'"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='HIGH'"
    ).fetchone()[0]

    medium = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='MEDIUM'"
    ).fetchone()[0]

    full = conn.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE correlation_status='FULL_CORRELATION'
        """
    ).fetchone()[0]

    open_alerts = conn.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE status IN ('NEW', 'INVESTIGATING')
        """
    ).fetchone()[0]

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if search:
        query += """
            AND (
                file_path LIKE ?
                OR process_name LIKE ?
                OR username LIKE ?
            )
        """
        value = f"%{search}%"
        params.extend([value, value, value])

    if severity:
        query += " AND severity=?"
        params.append(severity)

    if status:
        query += " AND status=?"
        params.append(status)

    query += " ORDER BY id DESC LIMIT 200"

    events = conn.execute(
        query,
        params
    ).fetchall()

    latest = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()

    conn.close()

    return render_template_string(
        DASHBOARD_HTML,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        full=full,
        open_alerts=open_alerts,
        latest=latest,
        events=events,
        search=search,
        severity=severity,
        status=status,
    )


@app.route("/event/<int:event_id>")
def investigate(event_id):

    conn = get_db()

    event = conn.execute(
        "SELECT * FROM events WHERE id=?",
        (event_id,)
    ).fetchone()

    conn.close()

    if event is None:
        return "Event not found", 404

    return render_template_string(
        INVESTIGATION_HTML,
        event=event
    )


@app.route(
    "/event/<int:event_id>/status",
    methods=["POST"]
)
def event_status(event_id):

    status = request.form.get("status", "NEW")

    set_status(event_id, status)

    return redirect(
        url_for(
            "investigate",
            event_id=event_id
        )
    )


@app.route(
    "/event/<int:event_id>/notes",
    methods=["POST"]
)
def event_notes(event_id):

    notes = request.form.get(
        "notes",
        ""
    )

    save_notes(
        event_id,
        notes
    )

    return redirect(
        url_for(
            "investigate",
            event_id=event_id
        )
    )


@app.route(
    "/event/<int:event_id>/quarantine",
    methods=["POST"]
)
def event_quarantine(event_id):

    success, message = quarantine_file(
        event_id
    )

    return redirect(
        url_for(
            "investigate",
            event_id=event_id
        )
    )


@app.route("/audit")
def audit_page():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM audit_log
        ORDER BY id DESC
        LIMIT 200
        """
    ).fetchall()

    conn.close()

    return render_template_string(
        AUDIT_HTML,
        rows=rows
    )


# ============================================================
# EXPORT
# ============================================================

@app.route("/export/events.json")
def export_json():

    conn = get_db()

    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC"
    ).fetchall()

    data = [
        dict(row)
        for row in rows
    ]

    conn.close()

    content = json.dumps(
        data,
        indent=2
    )

    buffer = io.BytesIO(
        content.encode("utf-8")
    )

    return send_file(
        buffer,
        as_attachment=True,
        download_name="fim_v7_events.json",
        mimetype="application/json"
    )


@app.route("/export/events.csv")
def export_csv():

    conn = get_db()

    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC"
    ).fetchall()

    columns = (
        rows[0].keys()
        if rows
        else []
    )

    output = io.StringIO()

    writer = csv.writer(output)

    if columns:
        writer.writerow(columns)

        for row in rows:
            writer.writerow(
                [row[col] for col in columns]
            )

    conn.close()

    buffer = io.BytesIO(
        output.getvalue().encode("utf-8")
    )

    return send_file(
        buffer,
        as_attachment=True,
        download_name="fim_v7_events.csv",
        mimetype="text/csv"
    )


# ============================================================
# API
# ============================================================

@app.route("/api/events")
def api_events():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 200
        """
    ).fetchall()

    conn.close()

    return jsonify([
        dict(row)
        for row in rows
    ])


@app.route("/api/stats")
def api_stats():

    conn = get_db()

    stats = {
        "total": conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0],

        "critical": conn.execute(
            "SELECT COUNT(*) FROM events WHERE severity='CRITICAL'"
        ).fetchone()[0],

        "high": conn.execute(
            "SELECT COUNT(*) FROM events WHERE severity='HIGH'"
        ).fetchone()[0],

        "medium": conn.execute(
            "SELECT COUNT(*) FROM events WHERE severity='MEDIUM'"
        ).fetchone()[0],

        "full_correlation": conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE correlation_status='FULL_CORRELATION'
            """
        ).fetchone()[0],
    }

    conn.close()

    return jsonify(stats)


# ============================================================
# SERVER
# ============================================================

def run_server():
    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False
    )


# ============================================================
# MONITOR
# ============================================================

def start_monitoring():

    baseline = load_baseline()

    if not baseline:
        print("\n[!] Baseline is empty.")
        print("[!] Add trusted files and choose option 1.")
        return

    MONITORED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    QUARANTINE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    handler = FIMHandler()

    observer = Observer()

    observer.schedule(
        handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    web_thread = threading.Thread(
        target=run_server,
        daemon=True
    )

    web_thread.start()

    print("\n" + "=" * 90)
    print("                     FIM V7 SOC / MINI-SIEM")
    print("=" * 90)
    print(f"Monitoring : {MONITORED_DIR}")
    print(f"Baseline   : {BASELINE_FILE}")
    print(f"Database   : {DATABASE_FILE}")
    print(f"Dashboard  : http://{HOST}:{PORT}")
    print("Sources    : FIM + Sysmon Event 11 + Windows 4663")
    print(f"Auto resp. : {'ENABLED' if AUTO_RESPONSE_ENABLED else 'DISABLED'}")
    print("=" * 90)

    print("\n[+] Monitoring started.")
    print("[+] Press CTRL+C to stop.\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping FIM V7...")
        observer.stop()

    observer.join()

    print("[+] FIM V7 stopped.")


# ============================================================
# MENU
# ============================================================

def main():

    MONITORED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    QUARANTINE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    while True:

        print()
        print("=" * 70)
        print("                 FIM V7 — SOC / MINI-SIEM")
        print("=" * 70)

        print("1. Create / Rebuild Trusted Baseline")
        print("2. Start FIM V7")
        print("3. Show Event Count")
        print("4. Show Full Correlations")
        print("5. Exit")

        print("=" * 70)

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":

            count = create_baseline()

            print(
                f"\n[+] Trusted files: {count}"
            )

        elif choice == "2":

            start_monitoring()

        elif choice == "3":

            conn = get_db()

            total = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            conn.close()

            print(
                f"\n[*] Total events: {total}"
            )

        elif choice == "4":

            conn = get_db()

            count = conn.execute(
                """
                SELECT COUNT(*)
                FROM events
                WHERE correlation_status='FULL_CORRELATION'
                """
            ).fetchone()[0]

            conn.close()

            print(
                f"\n[*] Full correlations: {count}"
            )

        elif choice == "5":

            print("[+] Exiting.")
            break

        else:

            print("[!] Invalid option.")


if __name__ == "__main__":
    main()
