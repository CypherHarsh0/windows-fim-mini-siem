import os
import json
import time
import sqlite3
import hashlib
import subprocess
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, request, redirect, url_for, render_template_string, jsonify
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# FIM V6
# SHA-256 FIM + SYSMON EVENT 11 ONLY
# Single-file SOC console
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MONITORED_DIR = BASE_DIR / "SOC-Lab" / "Monitored"
BASELINE_FILE = BASE_DIR / "baseline_v6.json"
DATABASE_FILE = BASE_DIR / "fim_v6.db"

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

HOST = "127.0.0.1"
PORT = 5000

CORRELATION_WINDOW_SECONDS = 30
RETRY_INTERVAL_SECONDS = 2
MAX_RETRIES = 8

app = Flask(__name__)


# ============================================================
# BASIC HELPERS
# ============================================================

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def username():
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME", "UNKNOWN")


def normalized(path):
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

    print("\n" + "=" * 80)
    print("                 FIM V6 TRUSTED BASELINE")
    print("=" * 80)
    print(f"Directory: {MONITORED_DIR}\n")

    for path in MONITORED_DIR.rglob("*"):
        if not path.is_file():
            continue

        file_hash = sha256_file(path)
        if not file_hash:
            continue

        baseline[normalized(path)] = {
            "hash": file_hash,
            "algorithm": "SHA-256",
            "created_at": now_text()
        }

        print(f"[TRUSTED] {path}")

    save_baseline(baseline)

    print(f"\n[+] Trusted files : {len(baseline)}")
    print(f"[+] Baseline      : {BASELINE_FILE}")


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
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,

            username TEXT,

            sysmon_event_id INTEGER,
            sysmon_time TEXT,

            process_guid TEXT,
            process_id TEXT,
            process_name TEXT,
            process_user TEXT,

            target_filename TEXT,

            correlation_status TEXT,
            details TEXT
        )
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_file
        ON events(file_path)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_severity
        ON events(severity)
    """)

    conn.commit()
    conn.close()


# ============================================================
# SEVERITY
# ============================================================

def severity_for(event_type, file_path, process_name=None):
    extension = Path(str(file_path)).suffix.lower()

    high_risk_extensions = {
        ".exe", ".dll", ".sys",
        ".ps1", ".bat", ".cmd",
        ".vbs", ".js"
    }

    suspicious_processes = {
        "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe",
        "regsvr32.exe"
    }

    if event_type == "FILE_DELETED":
        return "CRITICAL"

    if extension in high_risk_extensions:
        return "CRITICAL"

    if process_name:
        process = Path(str(process_name)).name.lower()
        if process in suspicious_processes:
            return "CRITICAL"

    if event_type == "FILE_MODIFIED":
        return "HIGH"

    if event_type == "FILE_CREATED":
        return "MEDIUM"

    if event_type == "FILE_MOVED":
        return "HIGH"

    return "LOW"


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
                script
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError
    ):
        return ""


# ============================================================
# SYSMON EVENT 11
# ============================================================

def query_sysmon_event_11(file_path):
    exact_path = str(Path(file_path).resolve()).replace("'", "''")

    script = f"""
$events = Get-WinEvent `
    -FilterHashtable @{{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=11
        StartTime=(Get-Date).AddSeconds(-{CORRELATION_WINDOW_SECONDS})
    }} `
    -MaxEvents 500 `
    -ErrorAction SilentlyContinue

$result = foreach ($event in $events) {{

    $xml = [xml]$event.ToXml()
    $data = @{{}}

    foreach ($item in $xml.Event.EventData.Data) {{
        $data[$item.Name] = [string]$item.'#text'
    }}

    if ($data.TargetFilename -ieq '{exact_path}') {{

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
        if isinstance(data, dict):
            return [data]
        return data
    except json.JSONDecodeError:
        return []


def correlate_event_11(file_path):
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
# EVENT STORAGE
# ============================================================

def store_event(event_type, file_path, old_hash=None, new_hash=None):
    sysmon = correlate_event_11(file_path)

    process_guid = None
    process_id = None
    process_name = None
    process_user = None
    target_filename = None
    sysmon_event_id = None
    sysmon_time = None

    if sysmon:
        process_guid = sysmon.get("ProcessGuid")
        process_id = str(sysmon.get("ProcessId") or "")
        process_name = sysmon.get("Image")
        process_user = sysmon.get("User")
        target_filename = sysmon.get("TargetFilename")
        sysmon_event_id = sysmon.get("EventId")
        sysmon_time = sysmon.get("TimeCreated")

        correlation_status = "SYSMON_EVENT_11"
        details = (
            "FIM event matched Sysmon Event ID 11 "
            "for the protected file."
        )
    else:
        correlation_status = "FIM_ONLY"
        details = (
            "FIM detected the integrity event, but "
            "no matching Sysmon Event ID 11 was found "
            "inside the correlation window."
        )

    severity = severity_for(
        event_type,
        file_path,
        process_name
    )

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO events (
            timestamp,
            event_type,
            severity,
            file_path,
            old_hash,
            new_hash,
            username,
            sysmon_event_id,
            sysmon_time,
            process_guid,
            process_id,
            process_name,
            process_user,
            target_filename,
            correlation_status,
            details
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (
        now_text(),
        event_type,
        severity,
        str(file_path),
        old_hash,
        new_hash,
        username(),
        sysmon_event_id,
        sysmon_time,
        process_guid,
        process_id,
        process_name,
        process_user,
        target_filename,
        correlation_status,
        details
    ))

    event_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return {
        "id": event_id,
        "severity": severity,
        "correlation": correlation_status,
        "sysmon": sysmon
    }


# ============================================================
# CONSOLE ALERT
# ============================================================

def print_alert(event_type, path, old_hash, new_hash, result):
    print("\n" + "=" * 90)
    print("                    FIM V6 SECURITY ALERT")
    print("=" * 90)

    print(f"Event ID          : {result['id']}")
    print(f"Time              : {now_text()}")
    print(f"Event             : {event_type}")
    print(f"Severity          : {result['severity']}")
    print(f"User              : {username()}")
    print(f"File              : {path}")
    print(f"Correlation       : {result['correlation']}")

    sysmon = result["sysmon"]

    print("\n---- SYSMON EVENT 11 ----")

    if sysmon:
        print(f"Event ID          : {sysmon.get('EventId')}")
        print(f"Time              : {sysmon.get('TimeCreated')}")
        print(f"Process GUID      : {sysmon.get('ProcessGuid')}")
        print(f"Process ID        : {sysmon.get('ProcessId')}")
        print(f"Process           : {sysmon.get('Image')}")
        print(f"User              : {sysmon.get('User')}")
        print(f"Target Filename   : {sysmon.get('TargetFilename')}")
    else:
        print("No matching Sysmon Event 11.")

    print("\n---- SHA-256 ----")
    print(f"Old SHA-256       : {old_hash or 'N/A'}")
    print(f"New SHA-256       : {new_hash or 'N/A'}")
    print("=" * 90)


# ============================================================
# FILE MONITOR
# ============================================================

class FIMHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.baseline = load_baseline()
        self.last_seen = {}

    def debounce(self, path):
        key = normalized(path)
        current = time.time()
        previous = self.last_seen.get(key, 0)

        if current - previous < 1.0:
            return False

        self.last_seen[key] = current
        return True

    def process(self, event_type, path, old_hash=None, new_hash=None):
        result = store_event(
            event_type,
            path,
            old_hash,
            new_hash
        )

        print_alert(
            event_type,
            path,
            old_hash,
            new_hash,
            result
        )

    def on_created(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        time.sleep(0.3)

        new_hash = sha256_file(path)

        if not new_hash:
            return

        key = normalized(path)

        if key in self.baseline:
            old_hash = self.baseline[key]["hash"]

            if old_hash == new_hash:
                return

            self.process(
                "FILE_MODIFIED",
                path,
                old_hash,
                new_hash
            )

        else:
            self.process(
                "FILE_CREATED",
                path,
                None,
                new_hash
            )

    def on_modified(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        time.sleep(0.2)

        new_hash = sha256_file(path)

        if not new_hash:
            return

        key = normalized(path)

        if key not in self.baseline:
            return

        old_hash = self.baseline[key]["hash"]

        if old_hash == new_hash:
            return

        self.process(
            "FILE_MODIFIED",
            path,
            old_hash,
            new_hash
        )

    def on_deleted(self, event):
        if event.is_directory:
            return

        path = Path(event.src_path)

        if not self.debounce(path):
            return

        key = normalized(path)

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
# DASHBOARD TEMPLATE
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta http-equiv="refresh" content="10">

<title>FIM V6 SOC Console</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 28px;
    background: #0b1220;
    color: #f8fafc;
    font-family: Arial, sans-serif;
}

h1 {
    margin: 0;
    font-size: 32px;
}

.subtitle {
    color: #94a3b8;
    margin: 8px 0 28px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(190px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.card {
    background: #182338;
    border: 1px solid #263654;
    border-radius: 14px;
    padding: 20px;
}

.card h2 {
    margin: 0;
    font-size: 32px;
}

.card span {
    color: #94a3b8;
    display: block;
    margin-top: 8px;
}

.latest {
    background: #182338;
    border: 1px solid #263654;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 24px;
}

.latest-title {
    font-size: 20px;
    font-weight: bold;
    margin-bottom: 14px;
}

.latest-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(220px, 1fr));
    gap: 15px;
}

.evidence {
    background: #0f172a;
    border-radius: 10px;
    padding: 14px;
}

.label {
    color: #94a3b8;
    font-size: 13px;
    display: block;
    margin-bottom: 5px;
}

.value {
    word-break: break-word;
}

.alert-high {
    color: #ffb020;
    font-weight: bold;
}

.alert-critical {
    color: #ff5252;
    font-weight: bold;
}

.alert-medium {
    color: #facc15;
    font-weight: bold;
}

.correlation {
    color: #4ade80;
    font-weight: bold;
}

.fim-only {
    color: #fb923c;
    font-weight: bold;
}

.controls {
    background: #182338;
    border: 1px solid #263654;
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 20px;
}

input,
select,
button {
    padding: 10px;
    border-radius: 7px;
    border: 1px solid #334155;
    background: #0f172a;
    color: white;
    margin-right: 7px;
    margin-bottom: 7px;
}

button {
    cursor: pointer;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #182338;
    border-radius: 14px;
    overflow: hidden;
}

th,
td {
    padding: 13px;
    border-bottom: 1px solid #263654;
    text-align: left;
    vertical-align: top;
}

th {
    background: #263654;
}

tr:hover {
    background: #202e47;
}

.file {
    max-width: 330px;
    word-break: break-all;
}

.process {
    max-width: 230px;
    word-break: break-all;
}

a {
    color: #60a5fa;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

.small {
    font-size: 12px;
    color: #94a3b8;
}

</style>

</head>

<body>

<h1>🛡 FIM V6 — SOC Console</h1>

<div class="subtitle">
SHA-256 Integrity Monitoring + Sysmon Event 11
</div>


<div class="grid">

<div class="card">
<h2>{{ total }}</h2>
<span>Total Events</span>
</div>

<div class="card">
<h2 class="alert-critical">{{ critical }}</h2>
<span>Critical</span>
</div>

<div class="card">
<h2 class="alert-high">{{ high }}</h2>
<span>High</span>
</div>

<div class="card">
<h2 class="alert-medium">{{ medium }}</h2>
<span>Medium</span>
</div>

<div class="card">
<h2 class="correlation">{{ correlated }}</h2>
<span>Event 11 Correlated</span>
</div>

<div class="card">
<h2>{{ fim_only }}</h2>
<span>FIM Only</span>
</div>

</div>


{% if latest %}

<div class="latest">

<div class="latest-title">
Latest Security Event — #{{ latest["id"] }}
</div>

<div class="latest-grid">

<div class="evidence">
<span class="label">Event</span>
<span class="value">{{ latest["event_type"] }}</span>
</div>

<div class="evidence">
<span class="label">Severity</span>
<span class="value">{{ latest["severity"] }}</span>
</div>

<div class="evidence">
<span class="label">File</span>
<span class="value">{{ latest["file_path"] }}</span>
</div>

<div class="evidence">
<span class="label">User</span>
<span class="value">{{ latest["process_user"] or latest["username"] }}</span>
</div>

<div class="evidence">
<span class="label">Process</span>
<span class="value">{{ latest["process_name"] or "Not correlated" }}</span>
</div>

<div class="evidence">
<span class="label">PID</span>
<span class="value">{{ latest["process_id"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">Sysmon Event</span>
<span class="value">{{ latest["sysmon_event_id"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">Correlation</span>

{% if latest["correlation_status"] == "SYSMON_EVENT_11" %}

<span class="correlation">SYSMON EVENT 11</span>

{% else %}

<span class="fim-only">FIM ONLY</span>

{% endif %}

</div>

<div class="evidence">
<span class="label">Old SHA-256</span>
<span class="value small">{{ latest["old_hash"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">New SHA-256</span>
<span class="value small">{{ latest["new_hash"] or "N/A" }}</span>
</div>

</div>

<br>

<a href="/event/{{ latest['id'] }}">
View Full Investigation →
</a>

</div>

{% endif %}


<div class="controls">

<form method="GET">

<input
type="text"
name="search"
placeholder="File / process / user"
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


<select name="correlation">

<option value="">All Correlation</option>

<option value="SYSMON_EVENT_11"
{% if correlation == "SYSMON_EVENT_11" %}selected{% endif %}>
SYSMON EVENT 11
</option>

<option value="FIM_ONLY"
{% if correlation == "FIM_ONLY" %}selected{% endif %}>
FIM ONLY
</option>

</select>


<button type="submit">
Filter
</button>

<a href="/">
Clear
</a>

</form>

</div>


<h2>Recent Security Events</h2>

<table>

<tr>
<th>ID</th>
<th>Time</th>
<th>Event</th>
<th>Severity</th>
<th>File</th>
<th>Process</th>
<th>Correlation</th>
<th>Investigation</th>
</tr>


{% for event in events %}

<tr>

<td>
{{ event["id"] }}
</td>

<td>
{{ event["timestamp"] }}
</td>

<td>
{{ event["event_type"] }}
</td>

<td class="alert-{{ event["severity"].lower() }}">
{{ event["severity"] }}
</td>

<td class="file">
{{ event["file_path"] }}
</td>

<td class="process">

{{ event["process_name"] or "Not correlated" }}

<br>

<span class="small">
PID:
{{ event["process_id"] or "N/A" }}
</span>

</td>

<td>

{% if event["correlation_status"] == "SYSMON_EVENT_11" %}

<span class="correlation">
✓ EVENT 11
</span>

{% else %}

<span class="fim-only">
⚠ FIM ONLY
</span>

{% endif %}

</td>

<td>

<a href="/event/{{ event['id'] }}">
Investigate
</a>

</td>

</tr>

{% endfor %}

</table>

</body>

</html>
"""


# ============================================================
# INVESTIGATION TEMPLATE
# ============================================================

INVESTIGATION_HTML = r"""
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<title>FIM V6 Investigation</title>

<style>

body {
    margin: 0;
    padding: 30px;
    background: #0b1220;
    color: white;
    font-family: Arial, sans-serif;
}

.container {
    max-width: 1100px;
    margin: auto;
}

.header {
    background: #182338;
    border: 1px solid #263654;
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 20px;
}

.section {
    background: #182338;
    border: 1px solid #263654;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 18px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(260px, 1fr));
    gap: 14px;
}

.evidence {
    background: #0f172a;
    padding: 15px;
    border-radius: 9px;
}

.label {
    display: block;
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 6px;
}

.value {
    word-break: break-word;
}

.hash {
    font-family: monospace;
    word-break: break-all;
}

.critical {
    color: #ff5252;
    font-weight: bold;
}

.high {
    color: #ffb020;
    font-weight: bold;
}

.medium {
    color: #facc15;
    font-weight: bold;
}

.correlated {
    color: #4ade80;
    font-weight: bold;
}

.fim-only {
    color: #fb923c;
    font-weight: bold;
}

.back {
    color: #60a5fa;
}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>🔎 FIM V6 Investigation #{{ event["id"] }}</h1>

<div>
{{ event["event_type"] }}
—
<span class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</span>
</div>

</div>


<div class="section">

<h2>File Integrity</h2>

<div class="grid">

<div class="evidence">
<span class="label">File</span>
<span class="value">{{ event["file_path"] }}</span>
</div>

<div class="evidence">
<span class="label">Timestamp</span>
<span class="value">{{ event["timestamp"] }}</span>
</div>

<div class="evidence">
<span class="label">Old SHA-256</span>
<span class="hash">{{ event["old_hash"] or "N/A" }}</span>
</div>

<div class="evidence">
<span class="label">New SHA-256</span>
<span class="hash">{{ event["new_hash"] or "N/A" }}</span>
</div>

</div>

</div>


<div class="section">

<h2>Sysmon Event 11</h2>

<div class="grid">

<div class="evidence">
<span class="label">Sysmon Event ID</span>
<span class="value">
{{ event["sysmon_event_id"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">Sysmon Timestamp</span>
<span class="value">
{{ event["sysmon_time"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">Target Filename</span>
<span class="value">
{{ event["target_filename"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">Process</span>
<span class="value">
{{ event["process_name"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">PID</span>
<span class="value">
{{ event["process_id"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">Process GUID</span>
<span class="value">
{{ event["process_guid"] or "Not available" }}
</span>
</div>

<div class="evidence">
<span class="label">User</span>
<span class="value">
{{ event["process_user"] or event["username"] }}
</span>
</div>

</div>

</div>


<div class="section">

<h2>Correlation Result</h2>

{% if event["correlation_status"] == "SYSMON_EVENT_11" %}

<p class="correlated">
✓ FIM event correlated with Sysmon Event 11.
</p>

<p>
The Sysmon event supplied process and file context
for this FIM detection.
</p>

{% else %}

<p class="fim-only">
⚠ FIM detected the integrity event, but Sysmon Event 11
was not available in the correlation window.
</p>

<p>
This does not invalidate the FIM detection. It means
there is no Event 11 evidence to attach to this particular event.
</p>

{% endif %}

</div>


<div class="section">

<h2>Details</h2>

<p>
{{ event["details"] }}
</p>

</div>


<a class="back" href="/">
← Back to SOC Dashboard
</a>

</div>

</body>

</html>
"""


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    correlation = request.args.get("correlation", "").strip()

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

    correlated = conn.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE correlation_status='SYSMON_EVENT_11'
        """
    ).fetchone()[0]

    fim_only = conn.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE correlation_status='FIM_ONLY'
        """
    ).fetchone()[0]

    query = """
        SELECT *
        FROM events
        WHERE 1=1
    """

    params = []

    if search:
        query += """
            AND (
                file_path LIKE ?
                OR process_name LIKE ?
                OR process_user LIKE ?
                OR username LIKE ?
            )
        """

        value = f"%{search}%"

        params.extend([
            value,
            value,
            value,
            value
        ])

    if severity:
        query += " AND severity=?"
        params.append(severity)

    if correlation:
        query += " AND correlation_status=?"
        params.append(correlation)

    query += """
        ORDER BY id DESC
        LIMIT 100
    """

    events = conn.execute(
        query,
        params
    ).fetchall()

    latest = conn.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    conn.close()

    return render_template_string(
        DASHBOARD_HTML,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        correlated=correlated,
        fim_only=fim_only,
        latest=latest,
        events=events,
        search=search,
        severity=severity,
        correlation=correlation
    )


# ============================================================
# INVESTIGATION
# ============================================================

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


# ============================================================
# API
# ============================================================

@app.route("/api/events")
def api_events():

    conn = get_db()

    events = conn.execute(
        """
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    conn.close()

    return jsonify([
        dict(event)
        for event in events
    ])


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    baseline = load_baseline()

    if not baseline:
        print("\n[!] Baseline is empty.")
        print("[!] Add trusted files and choose option 1 first.")
        return

    print()
    print("=" * 90)
    print("                    FIM V6 SOC ENGINE")
    print("=" * 90)

    print(f"Monitoring : {MONITORED_DIR}")
    print(f"Baseline   : {BASELINE_FILE}")
    print(f"Database   : {DATABASE_FILE}")
    print(f"Dashboard  : http://{HOST}:{PORT}")
    print("Telemetry  : Sysmon Event ID 11 ONLY")
    print()

    handler = FIMHandler()

    observer = Observer()

    observer.schedule(
        handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    web_thread = threading.Thread(
        target=lambda: app.run(
            host=HOST,
            port=PORT,
            debug=False,
            use_reloader=False
        ),
        daemon=True
    )

    web_thread.start()

    print("[+] FIM V6 started.")
    print(f"[+] Open: http://{HOST}:{PORT}")
    print("[+] Press CTRL+C to stop.\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping FIM V6...")
        observer.stop()

    observer.join()

    print("[+] FIM V6 stopped.")


# ============================================================
# MENU
# ============================================================

def main():

    MONITORED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    initialize_database()

    while True:

        print()
        print("=" * 70)
        print("                       FIM V6")
        print("=" * 70)

        print("1. Create / Rebuild Trusted Baseline")
        print("2. Start FIM V6")
        print("3. Show Event Count")
        print("4. Show Event 11 Correlations")
        print("5. Exit")

        print("=" * 70)

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":

            create_baseline()

        elif choice == "2":

            start_monitoring()

        elif choice == "3":

            conn = get_db()

            count = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            conn.close()

            print(
                f"\n[*] Total security events: {count}"
            )

        elif choice == "4":

            conn = get_db()

            count = conn.execute(
                """
                SELECT COUNT(*)
                FROM events
                WHERE correlation_status='SYSMON_EVENT_11'
                """
            ).fetchone()[0]

            conn.close()

            print(
                f"\n[*] Sysmon Event 11 correlations: {count}"
            )

        elif choice == "5":

            print("[+] Exiting...")
            break

        else:

            print("[!] Invalid option.")


if __name__ == "__main__":
    main()
