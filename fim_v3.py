
import os
import time
import json
import hashlib
import sqlite3
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MONITORED_DIR = BASE_DIR / "SOC-Lab" / "Monitored"
BASELINE_FILE = BASE_DIR / "baseline_v3.json"
DATABASE_FILE = BASE_DIR / "fim_v3.db"

HOST = "127.0.0.1"
PORT = 5000

HASH_ALGORITHM = "SHA-256"


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
            details TEXT
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# UTILITY
# ============================================================

def now():
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

    except Exception:
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
            "algorithm": HASH_ALGORITHM,
            "created_at": now()
        }

        print(f"[BASELINE] {path}")

    save_baseline(baseline)

    print()
    print(f"[+] Baseline created.")
    print(f"[+] Trusted files: {len(baseline)}")


# ============================================================
# SEVERITY ENGINE
# ============================================================

def determine_severity(event_type, path):

    if event_type == "FILE_DELETED":
        return "CRITICAL"

    if event_type == "FILE_MOVED":
        return "HIGH"

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
# EVENT STORAGE
# ============================================================

def save_event(
    event_type,
    severity,
    path,
    old_hash=None,
    new_hash=None,
    details=None
):

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
            details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now(),
        event_type,
        severity,
        str(path),
        old_hash,
        new_hash,
        username(),
        details
    ))

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return event_id


def generate_event(event_type, path, old_hash=None, new_hash=None):

    severity = determine_severity(event_type, path)

    event_id = save_event(
        event_type=event_type,
        severity=severity,
        path=path,
        old_hash=old_hash,
        new_hash=new_hash
    )

    print("\n" + "=" * 80)
    print("                    SECURITY EVENT")
    print("=" * 80)

    print(f"Event ID  : {event_id}")
    print(f"Time      : {now()}")
    print(f"Event     : {event_type}")
    print(f"Severity  : {severity}")
    print(f"User      : {username()}")
    print(f"File      : {path}")

    if old_hash:
        print(f"Old Hash  : {old_hash}")

    if new_hash:
        print(f"New Hash  : {new_hash}")

    print("=" * 80)


# ============================================================
# FILE MONITOR
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

        normalized_path = normalize(path)

        if normalized_path in self.baseline:

            old_hash = self.baseline[normalized_path]["hash"]

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

        normalized_path = normalize(path)

        if normalized_path not in self.baseline:
            return

        old_hash = self.baseline[normalized_path]["hash"]

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

        normalized_path = normalize(path)

        old_hash = None

        if normalized_path in self.baseline:
            old_hash = self.baseline[normalized_path]["hash"]

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
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# DASHBOARD HTML
# ============================================================

DASHBOARD = """
<!DOCTYPE html>

<html>

<head>

<title>FIM SOC Dashboard</title>

<meta http-equiv="refresh" content="10">

<style>

body {
    margin: 0;
    padding: 30px;
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: white;
}

h1 {
    margin-bottom: 5px;
}

.subtitle {
    color: #94a3b8;
    margin-bottom: 30px;
}

.cards {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));

    gap: 20px;

    margin-bottom: 30px;
}

.card {
    background: #1e293b;
    border-radius: 12px;
    padding: 20px;
}

.card h2 {
    font-size: 34px;
    margin: 0 0 8px;
}

.card p {
    color: #94a3b8;
    margin: 0;
}

.controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 20px;
}

select,
input {
    padding: 10px;
    border-radius: 6px;
    border: none;
    background: #334155;
    color: white;
}

button {
    padding: 10px 16px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #1e293b;
}

th {
    background: #334155;
}

th,
td {
    padding: 12px;
    border-bottom: 1px solid #334155;
    text-align: left;
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

.path {
    max-width: 350px;
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

<h1>🛡 File Integrity Monitoring</h1>

<div class="subtitle">
SOC Security Operations Dashboard
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
placeholder="Search file..."
value="{{ search }}"
>


<select name="severity">

<option value="">
All Severity
</option>

<option
value="CRITICAL"
{% if severity == "CRITICAL" %}selected{% endif %}
>
CRITICAL
</option>

<option
value="HIGH"
{% if severity == "HIGH" %}selected{% endif %}
>
HIGH
</option>

<option
value="MEDIUM"
{% if severity == "MEDIUM" %}selected{% endif %}
>
MEDIUM
</option>

<option
value="LOW"
{% if severity == "LOW" %}selected{% endif %}
>
LOW
</option>

</select>


<select name="event_type">

<option value="">
All Events
</option>

<option
value="FILE_CREATED"
{% if event_type == "FILE_CREATED" %}selected{% endif %}
>
FILE CREATED
</option>

<option
value="FILE_MODIFIED"
{% if event_type == "FILE_MODIFIED" %}selected{% endif %}
>
FILE MODIFIED
</option>

<option
value="FILE_DELETED"
{% if event_type == "FILE_DELETED" %}selected{% endif %}
>
FILE DELETED
</option>

<option
value="FILE_MOVED"
{% if event_type == "FILE_MOVED" %}selected{% endif %}
>
FILE MOVED
</option>

</select>


<button type="submit">
Filter
</button>

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

<td class="{{ event["severity"].lower() }}">
{{ event["severity"] }}
</td>

<td class="path">
{{ event["file_path"] }}
</td>

<td>
{{ event["username"] }}
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
# INVESTIGATION HTML
# ============================================================

INVESTIGATION = """

<!DOCTYPE html>

<html>

<head>

<title>Event Investigation</title>

<style>

body {

    background: #0f172a;
    color: white;

    font-family: Arial;

    padding: 40px;

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

    padding: 12px 0;

    border-bottom: 1px solid #334155;

}

.label {

    display: inline-block;

    width: 160px;

    color: #94a3b8;

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

a {

    color: #60a5fa;

}

</style>

</head>


<body>

<div class="container">

<h1>🔎 Security Event Investigation</h1>

<br>

<div class="card">

<div class="row">

<span class="label">
Event ID
</span>

{{ event["id"] }}

</div>


<div class="row">

<span class="label">
Timestamp
</span>

{{ event["timestamp"] }}

</div>


<div class="row">

<span class="label">
Event Type
</span>

{{ event["event_type"] }}

</div>


<div class="row">

<span class="label">
Severity
</span>

<span class="{{ event["severity"].lower() }}">

{{ event["severity"] }}

</span>

</div>


<div class="row">

<span class="label">
Username
</span>

{{ event["username"] }}

</div>


<div class="row">

<span class="label">
File
</span>

{{ event["file_path"] }}

</div>


<div class="row">

<span class="label">
Old SHA-256
</span>

<div class="hash">

{{ event["old_hash"] or "N/A" }}

</div>

</div>


<div class="row">

<span class="label">
New SHA-256
</span>

<div class="hash">

{{ event["new_hash"] or "N/A" }}

</div>

</div>


<div class="row">

<span class="label">
Details
</span>

{{ event["details"] or "No additional details" }}

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


    connection = get_db()


    total = connection.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]


    critical = connection.execute(
        "SELECT COUNT(*) FROM events WHERE severity='CRITICAL'"
    ).fetchone()[0]


    high = connection.execute(
        "SELECT COUNT(*) FROM events WHERE severity='HIGH'"
    ).fetchone()[0]


    medium = connection.execute(
        "SELECT COUNT(*) FROM events WHERE severity='MEDIUM'"
    ).fetchone()[0]


    query = """
        SELECT *
        FROM events
        WHERE 1=1
    """

    parameters = []


    if search:

        query += """
            AND file_path LIKE ?
        """

        parameters.append(
            f"%{search}%"
        )


    if severity:

        query += """
            AND severity = ?
        """

        parameters.append(
            severity
        )


    if event_type:

        query += """
            AND event_type = ?
        """

        parameters.append(
            event_type
        )


    query += """
        ORDER BY id DESC
        LIMIT 100
    """


    events = connection.execute(
        query,
        parameters
    ).fetchall()


    connection.close()


    return render_template_string(

        DASHBOARD,

        total=total,

        critical=critical,

        high=high,

        medium=medium,

        events=events,

        search=search,

        severity=severity,

        event_type=event_type

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
        INVESTIGATION,
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
# DASHBOARD SERVER
# ============================================================

def run_dashboard():

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False
    )


# ============================================================
# START FIM
# ============================================================

def start_monitoring():

    if not BASELINE_FILE.exists():

        print("\n[!] Baseline does not exist.")
        print("[!] Create the baseline first.")

        return


    baseline = load_baseline()


    if not baseline:

        print("\n[!] Baseline is empty.")
        print("[!] Put trusted files in Monitored.")
        print("[!] Rebuild the baseline.")

        return


    print("\n")
    print("=" * 80)
    print("             FILE INTEGRITY MONITORING SYSTEM V3")
    print("=" * 80)

    print(f"Monitoring : {MONITORED_DIR}")
    print(f"Baseline   : {BASELINE_FILE}")
    print(f"Database   : {DATABASE_FILE}")
    print(f"Dashboard  : http://{HOST}:{PORT}")
    print(f"Hash       : {HASH_ALGORITHM}")

    print("\n[*] FIM monitoring started.")
    print("[*] Dashboard running at:")
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

        print("\n[*] Stopping FIM...")

        observer.stop()


    observer.join()

    print("[+] FIM stopped.")


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
        print("=" * 60)
        print("             PYTHON FIM — SOC LAB V3")
        print("=" * 60)

        print("1. Create / Rebuild Trusted Baseline")
        print("2. Start FIM Monitoring")
        print("3. Show Event Count")
        print("4. Exit")

        print("=" * 60)


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

            print("[+] Exiting...")

            break


        else:

            print("[!] Invalid option.")


if __name__ == "__main__":

    main()
