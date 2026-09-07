import os
import re
import time
import json
import hashlib
import sqlite3
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template_string, request
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MONITORED_DIR = BASE_DIR / "SOC-Lab" / "Monitored"
BASELINE_FILE = BASE_DIR / "baseline_v4.json"
DATABASE_FILE = BASE_DIR / "fim_v4.db"

HOST = "127.0.0.1"
PORT = 5000

CORRELATION_WINDOW_SECONDS = 20
CORRELATION_RETRY_SECONDS = 2
CORRELATION_RETRIES = 6

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Accesses that indicate an actual modification/deletion operation.
WRITE_ACCESS_NAMES = (
    "WriteData",
    "AddFile",
    "AppendData",
    "AddSubdirectory",
    "CreatePipeInstance",
    "WriteAttributes",
    "WriteExtendedAttributes",
)

DELETE_ACCESS_NAMES = (
    "Delete",
    "DeleteChild",
)

# Read/control accesses should never be treated as write attribution.
IGNORED_ACCESS_NAMES = (
    "ReadData",
    "ReadAttributes",
    "ReadExtendedAttributes",
    "READ_CONTROL",
    "ReadPermissions",
)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            username TEXT,
            process_name TEXT,
            process_id TEXT,
            windows_access TEXT,
            windows_event_id INTEGER,
            correlation_status TEXT,
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# UTILITY
# ============================================================

def now():
    return datetime.now()


def timestamp():
    return now().strftime("%Y-%m-%d %H:%M:%S")


def username():
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME", "UNKNOWN")


def normalize(path):
    return str(Path(path).resolve()).lower()


def sha256_file(path):
    try:
        hasher = hashlib.sha256()

        with open(path, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                hasher.update(chunk)

        return hasher.hexdigest()

    except (FileNotFoundError, PermissionError, OSError):
        return None


# ============================================================
# BASELINE
# ============================================================

def load_baseline():

    if not BASELINE_FILE.exists():
        return {}

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return {}


def save_baseline(baseline):

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4)


def create_baseline():

    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

    baseline = {}

    print("\n[*] Creating trusted baseline...")
    print(f"[*] Directory: {MONITORED_DIR}\n")

    for path in MONITORED_DIR.rglob("*"):

        if not path.is_file():
            continue

        file_hash = sha256_file(path)

        if file_hash is None:
            continue

        baseline[normalize(path)] = {
            "hash": file_hash,
            "algorithm": "SHA-256",
            "created_at": timestamp()
        }

        print(f"[BASELINE] {path}")

    save_baseline(baseline)

    print()
    print(f"[+] Trusted files: {len(baseline)}")
    print(f"[+] Baseline: {BASELINE_FILE}")


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(event_type, path):

    extension = Path(str(path)).suffix.lower()

    critical_extensions = {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js"
    }

    if event_type == "FILE_DELETED":
        return "CRITICAL"

    if event_type == "FILE_MOVED":
        return "HIGH"

    if event_type == "FILE_MODIFIED":

        if extension in critical_extensions:
            return "CRITICAL"

        return "HIGH"

    if event_type == "FILE_CREATED":

        if extension in critical_extensions:
            return "HIGH"

        return "MEDIUM"

    return "LOW"


# ============================================================
# WINDOWS 4663 PARSING
# ============================================================

def run_powershell(command, timeout=8):

    try:

        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        OSError
    ):
        return ""


def escape_powershell_string(value):
    return value.replace("'", "''")

def get_recent_4663_events(file_path):

    escaped_path = escape_powershell_string(
        str(Path(file_path).resolve())
    )

    command = f"""
$events = Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    Id=4663;
    StartTime=(Get-Date).AddSeconds(-{CORRELATION_WINDOW_SECONDS})
}} -MaxEvents 500 -ErrorAction SilentlyContinue

$events |
Where-Object {{ $_.Message -like '*{escaped_path}*' }} |
ForEach-Object {{
    [PSCustomObject]@{{
        TimeCreated = $_.TimeCreated.ToString('o')
        EventId = $_.Id
        Message = $_.Message
    }}
}} |
ConvertTo-Json -Compress
"""

    output = run_powershell(command)

    if not output.strip():
        return []

    try:

        data = json.loads(output)

        if isinstance(data, dict):
            return [data]

        return data

    except json.JSONDecodeError:
        return []



def extract_field(message, field_name):

    pattern = rf"{re.escape(field_name)}:\s*(.+)"

    match = re.search(
        pattern,
        message,
        re.IGNORECASE
    )

    if match:
        return match.group(1).strip()

    return None


def parse_windows_event(event):

    message = event.get("Message", "")

    process_name = extract_field(
        message,
        "Process Name"
    )

    process_id = extract_field(
        message,
        "Process ID"
    )

    account_name = extract_field(
        message,
        "Account Name"
    )

    object_name = extract_field(
        message,
        "Object Name"
    )

    accesses = []

    access_match = re.search(
        r"Accesses:\s*(.*?)(?:\n\s*Access Mask:|\Z)",
        message,
        re.IGNORECASE | re.DOTALL
    )

    if access_match:

        access_block = access_match.group(1)

        for line in access_block.splitlines():

            line = line.strip()

            if line:
                accesses.append(line)

    return {
        "timestamp": event.get("TimeCreated"),
        "event_id": event.get("EventId"),
        "process_name": process_name,
        "process_id": process_id,
        "account_name": account_name,
        "object_name": object_name,
        "accesses": accesses,
    }


def access_is_write(accesses):

    text = " ".join(accesses).lower()

    for access in WRITE_ACCESS_NAMES:

        if access.lower() in text:
            return True

    return False


def access_is_delete(accesses):

    text = " ".join(accesses).lower()

    for access in DELETE_ACCESS_NAMES:

        if access.lower() in text:
            return True

    return False

def choose_best_windows_event(file_path):

    for attempt in range(CORRELATION_RETRIES):

        raw_events = get_recent_4663_events(file_path)

        parsed_events = [
            parse_windows_event(event)
            for event in raw_events
        ]

        current_user = username().lower()

        candidates = []

        for event in parsed_events:

            event_user = (
                event.get("account_name") or ""
            ).lower()

            # Make sure the Windows event belongs
            # to the same account running the FIM.
            if event_user and event_user != current_user:
                continue

            accesses = event.get("accesses", [])

            # Delete is strongest evidence.
            if access_is_delete(accesses):

                candidates.append(
                    (100, event)
                )

            # Write access is next strongest.
            elif access_is_write(accesses):

                candidates.append(
                    (90, event)
                )

        if candidates:

            candidates.sort(
                key=lambda item: item[0],
                reverse=True
            )

            return candidates[0][1]

        # Windows may take a moment to write Security events.
        if attempt < CORRELATION_RETRIES - 1:
            time.sleep(CORRELATION_RETRY_SECONDS)

    return None

# ============================================================
# EVENT DATABASE STORAGE
# ============================================================

def save_event(
    event_type,
    severity,
    path,
    old_hash=None,
    new_hash=None,
    windows_event=None,
    correlation_status="NOT_CORRELATED",
    details=None
):

    process_name = None
    process_id = None
    windows_access = None
    windows_event_id = None

    if windows_event:

        process_name = windows_event.get(
            "process_name"
        )

        process_id = windows_event.get(
            "process_id"
        )

        windows_access = "; ".join(
            windows_event.get("accesses", [])
        )

        windows_event_id = windows_event.get(
            "event_id"
        )

    connection = get_db()

    cursor = connection.execute("""
        INSERT INTO events (
            timestamp,
            event_type,
            severity,
            file_path,
            old_hash,
            new_hash,
            username,
            process_name,
            process_id,
            windows_access,
            windows_event_id,
            correlation_status,
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp(),
        event_type,
        severity,
        str(path),
        old_hash,
        new_hash,
        username(),
        process_name,
        process_id,
        windows_access,
        windows_event_id,
        correlation_status,
        details
    ))

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return event_id


# ============================================================
# SECURITY EVENT
# ============================================================

def generate_event(
    event_type,
    path,
    old_hash=None,
    new_hash=None
):

    severity = determine_severity(
        event_type,
        path
    )

    windows_event = choose_best_windows_event(
        path
    )

    if windows_event:

        correlation_status = (
            "CORRELATED_WRITE_OR_DELETE"
        )

        details = (
            "Matched Windows Security 4663 "
            "event containing write/delete access."
        )

    else:

        correlation_status = "NOT_CORRELATED"

        details = (
            "FIM detected the integrity event, "
            "but no matching write/delete Windows "
            "4663 event was found in the correlation window."
        )

    event_id = save_event(
        event_type=event_type,
        severity=severity,
        path=path,
        old_hash=old_hash,
        new_hash=new_hash,
        windows_event=windows_event,
        correlation_status=correlation_status,
        details=details
    )

    print("\n" + "=" * 85)
    print("                      FIM V4 SECURITY EVENT")
    print("=" * 85)

    print(f"Event ID          : {event_id}")
    print(f"Time              : {timestamp()}")
    print(f"Event             : {event_type}")
    print(f"Severity          : {severity}")
    print(f"User              : {username()}")
    print(f"File              : {path}")
    print(f"Correlation       : {correlation_status}")

    if windows_event:

        print(
            f"Process           : "
            f"{windows_event.get('process_name') or 'Unknown'}"
        )

        print(
            f"PID               : "
            f"{windows_event.get('process_id') or 'Unknown'}"
        )

        print(
            f"Windows Event     : "
            f"{windows_event.get('event_id') or 'Unknown'}"
        )

        print(
            f"Access            : "
            f"{'; '.join(windows_event.get('accesses', []))}"
        )

    else:

        print("Process           : NOT CORRELATED")
        print("PID               : NOT CORRELATED")
        print("Windows Event     : NOT CORRELATED")

    if old_hash:
        print(f"Old SHA-256       : {old_hash}")

    if new_hash:
        print(f"New SHA-256       : {new_hash}")

    print("=" * 85)


# ============================================================
# FIM FILE HANDLER
# ============================================================

class FIMHandler(FileSystemEventHandler):

    def __init__(self):

        super().__init__()

        self.baseline = load_baseline()

    def on_created(self, event):

        if event.is_directory:
            return

        path = Path(event.src_path)

        time.sleep(0.3)

        new_hash = sha256_file(path)

        if new_hash is None:
            return

        normalized = normalize(path)

        if normalized in self.baseline:

            old_hash = self.baseline[normalized]["hash"]

            if old_hash != new_hash:

                generate_event(
                    "FILE_MODIFIED",
                    path,
                    old_hash,
                    new_hash
                )

        else:

            generate_event(
                "FILE_CREATED",
                path,
                None,
                new_hash
            )

    def on_modified(self, event):

        if event.is_directory:
            return

        path = Path(event.src_path)

        time.sleep(0.2)

        new_hash = sha256_file(path)

        if new_hash is None:
            return

        normalized = normalize(path)

        if normalized not in self.baseline:
            return

        old_hash = self.baseline[normalized]["hash"]

        if old_hash == new_hash:
            return

        generate_event(
            "FILE_MODIFIED",
            path,
            old_hash,
            new_hash
        )

    def on_deleted(self, event):

        if event.is_directory:
            return

        path = Path(event.src_path)

        normalized = normalize(path)

        old_hash = None

        if normalized in self.baseline:
            old_hash = self.baseline[normalized]["hash"]

        generate_event(
            "FILE_DELETED",
            path,
            old_hash,
            None
        )

    def on_moved(self, event):

        if event.is_directory:
            return

        old_path = Path(event.src_path)
        new_path = Path(event.dest_path)

        generate_event(
            "FILE_MOVED",
            f"{old_path} -> {new_path}"
        )


# ============================================================
# DASHBOARD
# ============================================================

app = Flask(__name__)


DASHBOARD_HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta http-equiv="refresh" content="10">

<title>FIM V4 SOC Dashboard</title>

<style>

body {
    margin: 0;
    padding: 30px;
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: #f8fafc;
}

h1 {
    margin-bottom: 5px;
}

.subtitle {
    color: #94a3b8;
    margin-bottom: 25px;
}

.cards {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));

    gap: 16px;

    margin-bottom: 25px;
}

.card {
    background: #1e293b;
    border-radius: 12px;
    padding: 20px;
}

.card h2 {
    margin: 0;
    font-size: 32px;
}

.card p {
    margin-top: 8px;
    color: #94a3b8;
}

.controls {
    background: #1e293b;
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 20px;
}

input,
select,
button {
    padding: 9px;
    border-radius: 6px;
    border: none;
    margin-right: 8px;
}

button {
    cursor: pointer;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #1e293b;
}

th,
td {
    padding: 11px;
    border-bottom: 1px solid #334155;
    text-align: left;
    vertical-align: top;
}

th {
    background: #334155;
}

tr:hover {
    background: #273449;
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

.low {
    color: #38bdf8;
    font-weight: bold;
}

.correlated {
    color: #4ade80;
    font-weight: bold;
}

.notcorrelated {
    color: #fb923c;
    font-weight: bold;
}

.path {
    max-width: 320px;
    word-break: break-all;
}

.process {
    max-width: 260px;
    word-break: break-all;
}

a {
    color: #60a5fa;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

</style>

</head>

<body>

<h1>🛡 FIM V4 — SOC Dashboard</h1>

<div class="subtitle">
File integrity + Windows Security Event correlation
</div>


<div class="cards">

<div class="card">
<h2>{{ total }}</h2>
<p>Total Events</p>
</div>

<div class="card">
<h2 class="critical">
{{ critical }}
</h2>
<p>Critical</p>
</div>

<div class="card">
<h2 class="high">
{{ high }}
</h2>
<p>High</p>
</div>

<div class="card">
<h2 class="medium">
{{ medium }}
</h2>
<p>Medium</p>
</div>

</div>


<div class="controls">

<form method="GET">

<input
type="text"
name="search"
placeholder="Search file or process..."
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


<select name="event_type">

<option value="">All Events</option>

<option value="FILE_CREATED"
{% if event_type == "FILE_CREATED" %}selected{% endif %}>
FILE_CREATED
</option>

<option value="FILE_MODIFIED"
{% if event_type == "FILE_MODIFIED" %}selected{% endif %}>
FILE_MODIFIED
</option>

<option value="FILE_DELETED"
{% if event_type == "FILE_DELETED" %}selected{% endif %}>
FILE_DELETED
</option>

<option value="FILE_MOVED"
{% if event_type == "FILE_MOVED" %}selected{% endif %}>
FILE_MOVED
</option>

</select>


<select name="correlation">

<option value="">All Correlation</option>

<option value="CORRELATED_WRITE_OR_DELETE"
{% if correlation == "CORRELATED_WRITE_OR_DELETE" %}selected{% endif %}>
CORRELATED
</option>

<option value="NOT_CORRELATED"
{% if correlation == "NOT_CORRELATED" %}selected{% endif %}>
NOT CORRELATED
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


<table>

<tr>

<th>ID</th>
<th>Time</th>
<th>Event</th>
<th>Severity</th>
<th>File</th>
<th>User</th>
<th>Process</th>
<th>Correlation</th>
<th>Investigation</th>

</tr>


{% for event in events %}

<tr>

<td>{{ event["id"] }}</td>

<td>{{ event["timestamp"] }}</td>

<td>{{ event["event_type"] }}</td>

<td class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</td>

<td class="path">
{{ event["file_path"] }}
</td>

<td>
{{ event["username"] }}
</td>

<td class="process">
{{ event["process_name"] or "Not correlated" }}
<br>
<small>
PID: {{ event["process_id"] or "N/A" }}
</small>
</td>

<td>

{% if event["correlation_status"] ==
"CORRELATED_WRITE_OR_DELETE" %}

<span class="correlated">
CORRELATED
</span>

{% else %}

<span class="notcorrelated">
NOT CORRELATED
</span>

{% endif %}

</td>

<td>

<a href="/event/{{ event["id"] }}">
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
# INVESTIGATION PAGE
# ============================================================

INVESTIGATION_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>FIM Event Investigation</title>

<style>

body {
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
    padding: 30px;
}

.container {
    max-width: 1000px;
    margin: auto;
}

.card {
    background: #1e293b;
    padding: 25px;
    border-radius: 12px;
}

.row {
    padding: 14px 0;
    border-bottom: 1px solid #334155;
}

.label {
    display: inline-block;
    width: 190px;
    color: #94a3b8;
    vertical-align: top;
}

.hash,
.path,
.details {
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

.notcorrelated {
    color: #fb923c;
    font-weight: bold;
}

a {
    color: #60a5fa;
}

</style>

</head>


<body>

<div class="container">

<h1>🔎 FIM Security Event Investigation</h1>

<div class="card">

<div class="row">
<span class="label">Event ID</span>
{{ event["id"] }}
</div>

<div class="row">
<span class="label">Timestamp</span>
{{ event["timestamp"] }}
</div>

<div class="row">
<span class="label">Event Type</span>
{{ event["event_type"] }}
</div>

<div class="row">
<span class="label">Severity</span>

<span class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</span>

</div>

<div class="row">
<span class="label">Username</span>
{{ event["username"] }}
</div>

<div class="row">
<span class="label">File</span>
<span class="path">
{{ event["file_path"] }}
</span>
</div>

<div class="row">
<span class="label">Process</span>
{{ event["process_name"] or "Not correlated" }}
</div>

<div class="row">
<span class="label">Process ID</span>
{{ event["process_id"] or "Not correlated" }}
</div>

<div class="row">
<span class="label">Windows Event ID</span>
{{ event["windows_event_id"] or "N/A" }}
</div>

<div class="row">
<span class="label">Windows Access</span>
{{ event["windows_access"] or "N/A" }}
</div>

<div class="row">
<span class="label">Correlation</span>

{% if event["correlation_status"] ==
"CORRELATED_WRITE_OR_DELETE" %}

<span class="correlated">
CORRELATED WRITE/DELETE
</span>

{% else %}

<span class="notcorrelated">
NOT CORRELATED
</span>

{% endif %}

</div>

<div class="row">
<span class="label">Old SHA-256</span>

<span class="hash">
{{ event["old_hash"] or "N/A" }}
</span>

</div>

<div class="row">
<span class="label">New SHA-256</span>

<span class="hash">
{{ event["new_hash"] or "N/A" }}
</span>

</div>

<div class="row">
<span class="label">Details</span>

<span class="details">
{{ event["details"] or "N/A" }}
</span>

</div>

</div>

<br>

<a href="/">
← Back to Dashboard
</a>

</div>

</body>

</html>

"""


# ============================================================
# DASHBOARD ROUTE
# ============================================================

@app.route("/")
def dashboard():

    search = request.args.get(
        "search",
        ""
    ).strip()

    severity = request.args.get(
        "severity",
        ""
    ).strip()

    event_type = request.args.get(
        "event_type",
        ""
    ).strip()

    correlation = request.args.get(
        "correlation",
        ""
    ).strip()


    connection = get_db()


    total = connection.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]


    critical = connection.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE severity='CRITICAL'"
    ).fetchone()[0]


    high = connection.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE severity='HIGH'"
    ).fetchone()[0]


    medium = connection.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE severity='MEDIUM'"
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
            )
        """

        search_value = f"%{search}%"

        params.extend([
            search_value,
            search_value
        ])


    if severity:

        query += """
            AND severity=?
        """

        params.append(severity)


    if event_type:

        query += """
            AND event_type=?
        """

        params.append(event_type)


    if correlation:

        query += """
            AND correlation_status=?
        """

        params.append(correlation)


    query += """
        ORDER BY id DESC
        LIMIT 100
    """


    events = connection.execute(
        query,
        params
    ).fetchall()


    connection.close()


    return render_template_string(

        DASHBOARD_HTML,

        total=total,
        critical=critical,
        high=high,
        medium=medium,

        events=events,

        search=search,
        severity=severity,
        event_type=event_type,
        correlation=correlation

    )


# ============================================================
# INVESTIGATION ROUTE
# ============================================================

@app.route("/event/<int:event_id>")
def investigate(event_id):

    connection = get_db()

    event = connection.execute(
        "SELECT * FROM events WHERE id=?",
        (event_id,)
    ).fetchone()

    connection.close()


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

    connection = get_db()

    events = connection.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    connection.close()

    return jsonify([
        dict(event)
        for event in events
    ])


# ============================================================
# WEB SERVER
# ============================================================

def run_dashboard():

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False
    )


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    baseline = load_baseline()

    if not baseline:

        print("\n[!] Trusted baseline is empty.")
        print("[!] Put trusted files in Monitored.")
        print("[!] Create/rebuild the baseline first.")

        return


    print("\n")
    print("=" * 85)
    print("              FILE INTEGRITY MONITORING SYSTEM V4")
    print("=" * 85)

    print(f"Monitoring : {MONITORED_DIR}")
    print(f"Baseline   : {BASELINE_FILE}")
    print(f"Database   : {DATABASE_FILE}")
    print(f"Dashboard  : http://{HOST}:{PORT}")
    print(f"Windows    : Security Event 4663")
    print(f"Correlation: {CORRELATION_WINDOW_SECONDS} seconds")

    print("\n[*] FIM V4 started.")
    print("[*] Dashboard:")
    print(f"    http://{HOST}:{PORT}")

    print("\n[*] Press CTRL+C to stop.\n")


    handler = FIMHandler()

    observer = Observer()

    observer.schedule(
        handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()


    dashboard_thread = threading.Thread(
        target=run_dashboard,
        daemon=True
    )

    dashboard_thread.start()


    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        print("\n[*] Stopping FIM V4...")

        observer.stop()


    observer.join()

    print("[+] FIM V4 stopped.")


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

        print("\n")
        print("=" * 65)
        print("                 PYTHON FIM — SOC LAB V4")
        print("=" * 65)

        print("1. Create / Rebuild Trusted Baseline")
        print("2. Start FIM Monitoring")
        print("3. Show Event Count")
        print("4. Show Correlated Events")
        print("5. Exit")

        print("=" * 65)


        choice = input(
            "Select an option: "
        ).strip()


        if choice == "1":

            create_baseline()


        elif choice == "2":

            start_monitoring()


        elif choice == "3":

            connection = get_db()

            total = connection.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            connection.close()

            print(
                f"\n[*] Total security events: {total}"
            )


        elif choice == "4":

            connection = get_db()

            total = connection.execute("""
                SELECT COUNT(*)
                FROM events
                WHERE correlation_status=
                'CORRELATED_WRITE_OR_DELETE'
            """).fetchone()[0]

            connection.close()

            print(
                f"\n[*] Correlated write/delete events: {total}"
            )


        elif choice == "5":

            print("[+] Exiting FIM V4...")
            break


        else:

            print("[!] Invalid option.")


if __name__ == "__main__":
    main()