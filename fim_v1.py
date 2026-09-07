
import os
import json
import time
import hashlib
import logging
from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ============================================================
# CONFIGURATION
# ============================================================

MONITORED_DIR = Path("SOC-Lab/Monitored")
BASELINE_FILE = Path("baseline.json")
ALERT_LOG_FILE = Path("fim_alerts.jsonl")

HASH_ALGORITHM = "sha256"


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    filename="fim_system.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def timestamp():
    """Return current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def calculate_hash(file_path: Path):
    """
    Calculate SHA-256 hash of a file.
    Returns None if the file cannot be read.
    """
    try:
        hasher = hashlib.sha256()

        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                hasher.update(chunk)

        return hasher.hexdigest()

    except (PermissionError, FileNotFoundError, OSError) as error:
        logging.warning("Could not hash %s: %s", file_path, error)
        return None


def normalize_path(path: Path):
    """Return a normalized absolute path."""
    return str(path.resolve()).lower()


# ============================================================
# BASELINE MANAGEMENT
# ============================================================

def load_baseline():
    """Load baseline hashes from JSON."""
    if not BASELINE_FILE.exists():
        return {}

    try:
        with BASELINE_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Could not load baseline: {error}")
        return {}


def save_baseline(baseline):
    """Save baseline hashes to JSON."""
    try:
        with BASELINE_FILE.open("w", encoding="utf-8") as file:
            json.dump(baseline, file, indent=4)

    except OSError as error:
        print(f"[ERROR] Could not save baseline: {error}")


def create_baseline():
    """
    Scan the monitored directory and create a SHA-256 baseline.
    """
    baseline = {}

    print("\n[*] Creating baseline...")
    print(f"[*] Directory: {MONITORED_DIR.resolve()}\n")

    if not MONITORED_DIR.exists():
        MONITORED_DIR.mkdir(parents=True)

    for file_path in MONITORED_DIR.rglob("*"):

        if not file_path.is_file():
            continue

        file_hash = calculate_hash(file_path)

        if file_hash is not None:
            baseline[normalize_path(file_path)] = {
                "hash": file_hash,
                "algorithm": HASH_ALGORITHM
            }

            print(f"[BASELINE] {file_path}")

    save_baseline(baseline)

    print(f"\n[+] Baseline created.")
    print(f"[+] Files monitored: {len(baseline)}")


# ============================================================
# ALERT MANAGEMENT
# ============================================================

def generate_alert(event_type, file_path, old_hash=None, new_hash=None, severity="MEDIUM"):
    """
    Create and store a security alert.
    """

    alert = {
        "timestamp": timestamp(),
        "event_type": event_type,
        "severity": severity,
        "file": str(file_path),
        "old_hash": old_hash,
        "new_hash": new_hash
    }

    print("\n" + "=" * 70)
    print("[FILE INTEGRITY ALERT]")
    print("=" * 70)

    print(f"Time      : {alert['timestamp']}")
    print(f"Event     : {alert['event_type']}")
    print(f"Severity  : {alert['severity']}")
    print(f"File      : {alert['file']}")

    if old_hash:
        print(f"Old Hash  : {old_hash}")

    if new_hash:
        print(f"New Hash  : {new_hash}")

    print("=" * 70)

    try:
        with ALERT_LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(alert) + "\n")

    except OSError as error:
        logging.error("Could not write alert: %s", error)


# ============================================================
# FILE SYSTEM EVENT HANDLER
# ============================================================

class FIMHandler(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)

        # Give the OS a moment to finish writing the file.
        time.sleep(0.2)

        new_hash = calculate_hash(file_path)

        if new_hash is None:
            return

        generate_alert(
            event_type="FILE_CREATED",
            file_path=file_path,
            new_hash=new_hash,
            severity="MEDIUM"
        )

    def on_modified(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)
        normalized = normalize_path(file_path)

        baseline = load_baseline()

        old_hash = None

        if normalized in baseline:
            old_hash = baseline[normalized]["hash"]

        # Give the OS time to finish writing.
        time.sleep(0.2)

        new_hash = calculate_hash(file_path)

        if new_hash is None:
            return

        # Ignore events where contents did not actually change.
        if old_hash == new_hash:
            return

        if old_hash is None:
            event_type = "FILE_CREATED_OR_NEW"
        else:
            event_type = "FILE_MODIFIED"

        generate_alert(
            event_type=event_type,
            file_path=file_path,
            old_hash=old_hash,
            new_hash=new_hash,
            severity="HIGH"
        )

        # Update baseline after detecting change.
        baseline[normalized] = {
            "hash": new_hash,
            "algorithm": HASH_ALGORITHM
        }

        save_baseline(baseline)

    def on_deleted(self, event):

        if event.is_directory:
            return

        file_path = Path(event.src_path)
        normalized = normalize_path(file_path)

        baseline = load_baseline()

        old_hash = None

        if normalized in baseline:
            old_hash = baseline[normalized]["hash"]

        generate_alert(
            event_type="FILE_DELETED",
            file_path=file_path,
            old_hash=old_hash,
            severity="CRITICAL"
        )

        # Remove deleted file from baseline.
        if normalized in baseline:
            del baseline[normalized]
            save_baseline(baseline)

    def on_moved(self, event):

        if event.is_directory:
            return

        old_path = Path(event.src_path)
        new_path = Path(event.dest_path)

        generate_alert(
            event_type="FILE_RENAMED_OR_MOVED",
            file_path=f"{old_path} -> {new_path}",
            severity="HIGH"
        )


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    if not MONITORED_DIR.exists():
        MONITORED_DIR.mkdir(parents=True)

    print("\n" + "=" * 70)
    print("          FILE INTEGRITY MONITORING SYSTEM")
    print("=" * 70)

    print(f"Monitoring : {MONITORED_DIR.resolve()}")
    print(f"Baseline   : {BASELINE_FILE.resolve()}")
    print(f"Alerts     : {ALERT_LOG_FILE.resolve()}")
    print(f"Algorithm  : {HASH_ALGORITHM.upper()}")

    print("\n[*] Monitoring started.")
    print("[*] Press CTRL+C to stop.\n")

    event_handler = FIMHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        str(MONITORED_DIR),
        recursive=True
    )

    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping FIM...")

        observer.stop()

    observer.join()

    print("[+] FIM stopped.")


# ============================================================
# MAIN MENU
# ============================================================

def main():

    while True:

        print("\n")
        print("=" * 50)
        print("       PYTHON FILE INTEGRITY MONITOR")
        print("=" * 50)
        print("1. Create / Rebuild Baseline")
        print("2. Start Monitoring")
        print("3. Exit")
        print("=" * 50)

        choice = input("Select an option: ").strip()

        if choice == "1":
            create_baseline()

        elif choice == "2":

            baseline = load_baseline()

            if not baseline:
                print("\n[!] No baseline found.")
                print("[!] Create a baseline first.\n")
                continue

            start_monitoring()

        elif choice == "3":
            print("[+] Exiting...")
            break

        else:
            print("[!] Invalid option.")


if __name__ == "__main__":
    main()
