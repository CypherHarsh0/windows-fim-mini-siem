import os
import sqlite3
from pathlib import Path
from datetime import datetime

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    jsonify
)


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "fim_v4.db"

HOST = "127.0.0.1"
PORT = 5000


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_v5_columns():

    conn = get_db()

    columns = {
        "status": "TEXT DEFAULT 'NEW'",
        "analyst_notes": "TEXT",
        "acknowledged_by": "TEXT",
        "acknowledged_at": "TEXT",
        "resolved_at": "TEXT"
    }

    existing = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(events)"
        ).fetchall()
    }

    for column, definition in columns.items():

        if column not in existing:
            conn.execute(
                f"ALTER TABLE events ADD COLUMN {column} {definition}"
            )

    conn.execute("""
        UPDATE events
        SET status='NEW'
        WHERE status IS NULL
    """)

    conn.commit()
    conn.close()


# ============================================================
# UTILITY
# ============================================================

def timestamp():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def username():

    try:
        return os.getlogin()

    except Exception:
        return os.environ.get(
            "USERNAME",
            "UNKNOWN"
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta http-equiv="refresh" content="15">

<title>FIM V5 SOC Dashboard</title>

<style>

body {
    margin: 0;
    padding: 30px;
    background: #0f172a;
    color: white;
    font-family: Arial, sans-serif;
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

    gap: 15px;

    margin-bottom: 25px;
}

.card {
    background: #1e293b;
    padding: 20px;
    border-radius: 12px;
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
    padding: 12px;
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

.new {
    color: #60a5fa;
    font-weight: bold;
}

.investigating {
    color: #c084fc;
    font-weight: bold;
}

.resolved {
    color: #4ade80;
    font-weight: bold;
}

.false-positive {
    color: #94a3b8;
    font-weight: bold;
}

.path {
    max-width: 300px;
    word-break: break-all;
}

.process {
    max-width: 250px;
    word-break: break-all;
}

a {
    color: #60a5fa;
    text-decoration: none;
}

</style>

</head>

<body>

<h1>🛡 FIM V5 — SOC Alert Triage</h1>

<div class="subtitle">
File Integrity Monitoring Investigation Console
</div>


<div class="cards">

<div class="card">
<h2>{{ total }}</h2>
<p>Total Events</p>
</div>

<div class="card">
<h2 class="new">
{{ new_count }}
</h2>
<p>New</p>
</div>

<div class="card">
<h2 class="investigating">
{{ investigating }}
</h2>
<p>Investigating</p>
</div>

<div class="card">
<h2 class="critical">
{{ critical }}
</h2>
<p>Critical</p>
</div>

<div class="card">
<h2 class="resolved">
{{ resolved }}
</h2>
<p>Resolved</p>
</div>

</div>


<div class="controls">

<form method="GET">

<input
type="text"
name="search"
placeholder="Search file / process / user"
value="{{ search }}"
>

<select name="severity">

<option value="">
All Severity
</option>

<option value="CRITICAL"
{% if severity == "CRITICAL" %}
selected
{% endif %}>
CRITICAL
</option>

<option value="HIGH"
{% if severity == "HIGH" %}
selected
{% endif %}>
HIGH
</option>

<option value="MEDIUM"
{% if severity == "MEDIUM" %}
selected
{% endif %}>
MEDIUM
</option>

</select>


<select name="status">

<option value="">
All Status
</option>

<option value="NEW"
{% if status == "NEW" %}
selected
{% endif %}>
NEW
</option>

<option value="INVESTIGATING"
{% if status == "INVESTIGATING" %}
selected
{% endif %}>
INVESTIGATING
</option>

<option value="RESOLVED"
{% if status == "RESOLVED" %}
selected
{% endif %}>
RESOLVED
</option>

<option value="FALSE POSITIVE"
{% if status == "FALSE POSITIVE" %}
selected
{% endif %}>
FALSE POSITIVE
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
<th>Process</th>
<th>Status</th>
<th>Action</th>

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

<td class="process">

{{ event["process_name"] or "Not correlated" }}

<br>

PID:
{{ event["process_id"] or "N/A" }}

</td>

<td class="{{ event["status"].lower().replace(' ', '-') }}">
{{ event["status"] }}
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
# INVESTIGATION PAGE
# ============================================================

INVESTIGATION_HTML = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>FIM V5 Investigation</title>

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

.value,
.hash {
    word-break: break-all;
}

.hash {
    font-family: monospace;
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

.new {
    color: #60a5fa;
    font-weight: bold;
}

.investigating {
    color: #c084fc;
    font-weight: bold;
}

.resolved {
    color: #4ade80;
    font-weight: bold;
}

.false-positive {
    color: #94a3b8;
    font-weight: bold;
}

textarea {
    width: 100%;
    min-height: 140px;
    box-sizing: border-box;
    background: #0f172a;
    color: white;
    border: 1px solid #475569;
    padding: 12px;
    border-radius: 8px;
}

button {
    padding: 10px 14px;
    margin: 5px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
}

a {
    color: #60a5fa;
}

</style>

</head>

<body>

<div class="container">

<h1>🔎 Security Event Investigation</h1>

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

<span class="label">Status</span>

<span class="{{ event["status"].lower().replace(' ', '-') }}">
{{ event["status"] }}
</span>

</div>


<div class="row">
<span class="label">Username</span>
{{ event["username"] }}
</div>


<div class="row">

<span class="label">File</span>

<span class="value">
{{ event["file_path"] }}
</span>

</div>


<div class="row">

<span class="label">Process</span>

{{ event["process_name"] or "Not correlated" }}

</div>


<div class="row">

<span class="label">Process ID</span>

{{ event["process_id"] or "N/A" }}

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

<span class="label">Correlation</span>

{{ event["correlation_status"] }}

</div>


<div class="row">

<span class="label">Acknowledged By</span>

{{ event["acknowledged_by"] or "N/A" }}

</div>


<div class="row">

<span class="label">Acknowledged At</span>

{{ event["acknowledged_at"] or "N/A" }}

</div>


<div class="row">

<span class="label">Resolved At</span>

{{ event["resolved_at"] or "N/A" }}

</div>


<div class="row">

<span class="label">Analyst Notes</span>

<form method="POST"
action="/event/{{ event['id'] }}/notes">

<textarea
name="notes"
placeholder="Enter your investigation notes..."
>{{ event["analyst_notes"] or "" }}</textarea>

<br>

<button type="submit">
Save Notes
</button>

</form>

</div>


<div class="row">

<span class="label">
Change Status
</span>

<form method="POST"
action="/event/{{ event['id'] }}/status">

<button name="status" value="NEW">
NEW
</button>

<button name="status" value="INVESTIGATING">
INVESTIGATING
</button>

<button name="status" value="RESOLVED">
RESOLVED
</button>

<button name="status" value="FALSE POSITIVE">
FALSE POSITIVE
</button>

</form>

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

    status = request.args.get(
        "status",
        ""
    ).strip()


    conn = get_db()


    total = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]


    new_count = conn.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE status='NEW'"
    ).fetchone()[0]


    investigating = conn.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE status='INVESTIGATING'"
    ).fetchone()[0]


    critical = conn.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE severity='CRITICAL'"
    ).fetchone()[0]


    resolved = conn.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE status='RESOLVED'"
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
                OR username LIKE ?
            )
        """

        value = f"%{search}%"

        params.extend([
            value,
            value,
            value
        ])


    if severity:

        query += """
            AND severity=?
        """

        params.append(severity)


    if status:

        query += """
            AND status=?
        """

        params.append(status)


    query += """
        ORDER BY id DESC
        LIMIT 100
    """


    events = conn.execute(
        query,
        params
    ).fetchall()


    conn.close()


    return render_template_string(
        DASHBOARD_HTML,
        total=total,
        new_count=new_count,
        investigating=investigating,
        critical=critical,
        resolved=resolved,
        events=events,
        search=search,
        severity=severity,
        status=status
    )


# ============================================================
# INVESTIGATION
# ============================================================

@app.route("/event/<int:event_id>")
def event_page(event_id):

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
# CHANGE STATUS
# ============================================================

@app.route(
    "/event/<int:event_id>/status",
    methods=["POST"]
)
def change_status(event_id):

    status = request.form.get(
        "status",
        "NEW"
    )

    valid = {
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE POSITIVE"
    }

    if status not in valid:
        return "Invalid status", 400


    conn = get_db()


    if status == "NEW":

        conn.execute("""
            UPDATE events
            SET status=?,
                acknowledged_by=NULL,
                acknowledged_at=NULL
            WHERE id=?
        """, (
            status,
            event_id
        ))


    elif status == "INVESTIGATING":

        conn.execute("""
            UPDATE events
            SET status=?,
                acknowledged_by=?,
                acknowledged_at=?
            WHERE id=?
        """, (
            status,
            username(),
            timestamp(),
            event_id
        ))


    else:

        conn.execute("""
            UPDATE events
            SET status=?,
                resolved_at=?
            WHERE id=?
        """, (
            status,
            timestamp(),
            event_id
        ))


    conn.commit()
    conn.close()


    return redirect(
        url_for(
            "event_page",
            event_id=event_id
        )
    )


# ============================================================
# SAVE NOTES
# ============================================================

@app.route(
    "/event/<int:event_id>/notes",
    methods=["POST"]
)
def save_notes(event_id):

    notes = request.form.get(
        "notes",
        ""
    )


    conn = get_db()

    conn.execute("""
        UPDATE events
        SET analyst_notes=?
        WHERE id=?
    """, (
        notes,
        event_id
    ))

    conn.commit()
    conn.close()


    return redirect(
        url_for(
            "event_page",
            event_id=event_id
        )
    )


# ============================================================
# API
# ============================================================

@app.route("/api/events")
def api_events():

    conn = get_db()

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
# MAIN
# ============================================================

def main():

    if not DATABASE_FILE.exists():

        print()
        print("[ERROR] fim_v4.db was not found.")
        print()
        print("Start FIM v4 first and generate at least")
        print("one event before starting FIM v5.")
        return


    ensure_v5_columns()


    print()
    print("=" * 75)
    print("                FIM V5 SOC TRIAGE")
    print("=" * 75)

    print(f"Database  : {DATABASE_FILE}")
    print(f"Dashboard : http://{HOST}:{PORT}")

    print()
    print("[+] V5 database migration complete.")
    print("[+] Existing v4 events preserved.")
    print("[+] Starting dashboard...")
    print()


    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False
    )


if __name__ == "__main__":
    main()