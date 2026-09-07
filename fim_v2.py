
import os
import json
import time
import hashlib
import sqlite3
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, render_template_string
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MONITORED_DIR = BASE_DIR / "SOC-Lab" / "Monitored"
BASELINE_FILE = BASE_DIR / "baseline_v2.json"
DATABASE_FILE = BASE_DIR / "fim.db"

HOST = "127.0.0.1"
PORT = 5000

HASH_ALGORITHM = "sha256"


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_db_connection()

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
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_username():
    return os.getlogin()


def normalize_path(path):
    return str(Path(path).resolve()).lower()


def calculate_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    """
    try:
        hasher = hashlib.sha256()

        with open(file_path, "rb") as file:
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
    """
    Build a trusted baseline.
    Existing baseline is replaced only when the user
    explicitly chooses to rebuild it.
    """

    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

    baseline = {}

    print("\n[*] Creating trusted baseline...")
    print(f"[*] Monitoring directory: {MONITORED_DIR}")

    for file_path in MONITORED_DIR.rglob("*"):

        if not file_path.is_file():
            continue

        file_hash = calculate_hash(file_path)

        if file_hash is None:
            continue

        baseline[normalize_path(file_path)] = {
            "hash": file_hash,
            "algorithm": HASH_ALGORITHM,
            "created": current_timestamp()
        }

        print(f"[BASELINE] {file_path}")

    save_baseline(baseline)

    print()
    print(f"[+] Baseline created successfully.")
    print(f"[+] Files trusted: {len(baseline)}")
    print(f"[+] Baseline file: {BASELINE_FILE}")


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(event_type, file_path):
    file_name = Path(file_path).name.lower()
    extension = Path(file_path).suffix.lower()

    critical_extensions = {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".cmd",
        ".ps1"
    }

    critical_names = {
        "sam",
        "security",
        "system",
        "ntuser.dat",
        "win.ini",
        "hosts"
    }

    if event_type == "FILE_DELETED":
        return "CRITICAL"

    if event_type == "FILE_MODIFIED":
        if extension in critical_extensions:
            return "CRITICAL"

        if file_name in critical_names:
            return "CRITICAL"

        return "HIGH"

    if event_type == "FILE_CREATED":
        if extension in critical_extensions:
            return "HIGH"

        return "MEDIUM"

    if event_type == "FILE_MOVED":
        return "HIGH"

    return "LOW"


# ============================================================
# EVENT STORAGE
# ============================================================

def store_event(
    event_type,
    severity,
    file_path,
    old_hash=None,
    new_hash=None,
    details=None
):

    conn = get_db_connection()

    conn.execute("""
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
        current_timestamp(),
        event_type,
        severity,
        str(file_path),
        old_hash,
        new_hash,
        get_username(),
        details
    ))

    conn.commit()
    conn.close()


def print_alert(
    event_type,
    severity,
    file_path,
    old_hash=None,
    new_hash=None
):

    print("\n" + "=" * 75)
    print("                 FILE INTEGRITY ALERT")
    print("=" * 75)

    print(f"Time      : {current_timestamp()}")
    print(f"Event     : {event_type}")
    print(f"Severity  : {severity}")
    print(f"User      : {get_username()}")
    print(f"File      : {file_path}")

    if old_hash:
        print(f"Old Hash  : {old_hash}")

    if new_hash:
        print(f"New Hash  : {new_hash}")

    print("=" * 75)


# ============================================================
# EVENT PROCESSING
# ============================================================

def process_event(
    event_type,
    file_path,
    old_hash=None,
    new_hash=None
):

    severity = determine_severity(
        event_type,
        file_path
    )

    store_event(
        event_type=event_type,
        severity=severity,
        file_path=file_path,
        old_hash=old_hash,
        new_hash=new_hash
    )

    print_alert(
        event_type=event_type,
        severity=severity,
        file_path=file_path,
        old_hash=old_hash,
        new_hash=new_hash
    )


# ============================================================
# FILE SYSTEM MONITOR
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

        new_hash = calculate_hash(path)

        if new_hash is None:
            return

        normalized = normalize_path(path)

        # If it already existed in baseline, treat it as modified.
        if normalized in self.baseline:

            old_hash = self.baseline[normalized]["hash"]

            if old_hash == new_hash:
                return

            process_event(
                "FILE_MODIFIED",
                path,
                old_hash,
                new_hash
            )

        else:

            process_event(
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

        new_hash = calculate_hash(path)

        if new_hash is None:
            return

        normalized = normalize_path(path)

        if normalized not in self.baseline:
            return

        old_hash = self.baseline[normalized]["hash"]

        if old_hash == new_hash:
            return

        process_event(
            "FILE_MODIFIED",
            path,
            old_hash,
            new_hash
        )

    def on_deleted(self, event):

        if event.is_directory:
            return

        path = Path(event.src_path)

        normalized = normalize_path(path)

        old_hash = None

        if normalized in self.baseline:
            old_hash = self.baseline[normalized]["hash"]

        process_event(
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

        process_event(
            "FILE_MOVED",
            f"{old_path} -> {new_path}",
            None,
            None
        )


# ============================================================
# FLASK DASHBOARD
# ============================================================

app = Flask(__name__)


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>

<title>FIM SOC Dashboard</title>

<meta http-equiv="refresh" content="5">

<style>

body {
    font-family: Arial, sans-serif;
    background: #111827;
    color: white;
    margin: 0;
    padding: 30px;
}

h1 {
    margin-bottom: 5px;
}

.subtitle {
    color: #9ca3af;
    margin-bottom: 30px;
}

.cards {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 30px;
}

.card {
    background: #1f2937;
    padding: 20px;
    border-radius: 12px;
    min-width: 170px;
}

.card h2 {
    margin: 0;
    font-size: 32px;
}

.card p {
    color: #9ca3af;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #1f2937;
}

th, td {
    padding: 12px;
    border-bottom: 1px solid #374151;
    text-align: left;
}

th {
    background: #374151;
}

.critical {
    color: #ff4d4d;
    font-weight: bold;
}

.high {
    color: #ff9900;
    font-weight: bold;
}

.medium {
    color: #ffd11a;
    font-weight: bold;
}

.low {
    color: #66ccff;
    font-weight: bold;
}

.path {
    max-width: 400px;
    word-break: break-all;
}

</style>

</head>

<body>

<h1>File Integrity Monitoring — SOC Dashboard</h1>

<div class="subtitle">
    Real-time security event monitoring
</div>

<div class="cards">

<div class="card">
<h2>{{ total }}</h2>
<p>Total Events</p>
</div>

<div class="card">
<h2>{{ critical }}</h2>
<p>Critical</p>
</div>

<div class="card">
<h2>{{ high }}</h2>
<p>High</p>
</div>

<div class="card">
<h2>{{ medium }}</h2>
<p>Medium</p>
</div>

</div>

<h2>Recent Security Events</h2>

<table>

<tr>
<th>Time</th>
<th>Event</th>
<th>Severity</th>
<th>File</th>
<th>User</th>
</tr>

{% for event in events %}

<tr>

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

</tr>

{% endfor %}

</table>

</body>
</html>
"""


@app.route("/")
def dashboard():

    conn = get_db_connection()

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

    events = conn.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return render_template_string(
        DASHBOARD_HTML,
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        events=events
    )


@app.route("/api/events")
def api_events():

    conn = get_db_connection()

    events = conn.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    conn.close()

    return jsonify([
        dict(event)
        for event in events
    ])


# ============================================================
# START DASHBOARD
# ============================================================

def start_dashboard():

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
        print("\n[!] Trusted baseline does not exist.")
        print("[!] Create the baseline first.")
        return

    baseline = load_baseline()

    print("\n" + "=" * 75)
    print("              FILE INTEGRITY MONITORING SYSTEM V2")
    print("=" * 75)

    print(f"Monitoring : {MONITORED_DIR}")
    print(f"Baseline   : {BASELINE_FILE}")
    print(f"Database   : {DATABASE_FILE}")
    print(f"Dashboard  : http://{HOST}:{PORT}")
    print(f"Algorithm  : {HASH_ALGORITHM.upper()}")

    print("\n[*] Monitoring started.")
    print("[*] Dashboard: http://127.0.0.1:5000")
    print("[*] Press CTRL+C to stop.\n")

    handler = FIMHandler()

    observer = Observer()

    observer.schedule(
        handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    dashboard_thread = threading.Thread(
        target=start_dashboard,
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
        print("=" * 55)
        print("          PYTHON FIM — SOC LAB V2")
        print("=" * 55)

        print("1. Create / Rebuild Trusted Baseline")
        print("2. Start FIM Monitoring")
        print("3. Show Database Event Count")
        print("4. Exit")

        print("=" * 55)

        choice = input("Select an option: ").strip()

        if choice == "1":

            create_baseline()

        elif choice == "2":

            baseline = load_baseline()

            if not baseline:
                print("\n[!] Baseline is empty.")
                print("[!] Put trusted files in Monitored first.")
                print("[!] Then choose option 1.\n")
                continue

            start_monitoring()

        elif choice == "3":

            conn = get_db_connection()

            count = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            conn.close()

            print(f"\n[*] Total security events: {count}")

        elif choice == "4":

            print("[+] Exiting FIM...")
            break

        else:

            print("[!] Invalid option.")


if __name__ == "__main__":
    main()