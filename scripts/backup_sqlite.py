"""Safely back up a local UniTrack SQLite database using SQLite's backup API.

Run: python scripts/backup_sqlite.py
Production PostgreSQL should use a managed PostgreSQL backup service instead.
"""
from datetime import datetime
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "unitrack.db"
DESTINATION_DIR = ROOT / "backups"


def main():
    if not SOURCE.is_file():
        print(f"Local database not found: {SOURCE}", file=sys.stderr)
        return 1
    DESTINATION_DIR.mkdir(parents=True, exist_ok=True)
    dest = DESTINATION_DIR / f"unitrack-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    with sqlite3.connect(str(SOURCE)) as source:
        with sqlite3.connect(str(dest)) as backup:
            source.backup(backup)
            status = backup.execute("PRAGMA integrity_check").fetchone()[0]
            if status != "ok":
                raise RuntimeError("Backup integrity check failed: " + status)
    print("Database backup verified:", dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
