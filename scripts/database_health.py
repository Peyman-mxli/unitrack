"""Read-only SQLite integrity/schema audit and verified, private backups.

Never runs create_app(), seed_default_admin(), db.create_all() or migrations.
Usage:
  python scripts/database_health.py --integrity-only
  python scripts/database_health.py --schema
  python scripts/database_health.py --backup --schema
  python scripts/database_health.py --schema --strict

Use database-specific managed backups for PostgreSQL deployments.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_DATABASE = ROOT / "unitrack.db"
BACKUP_FOLDER = ROOT / "backups"
SENSITIVE_TABLES = (
    "users", "access_logs", "access_scan_pairs", "scan_tokens",
    "class_attendance", "class_enrollments", "class_meetings",
    "university_notices", "university_notice_reads",
)


def open_existing_database(path: Path) -> sqlite3.Connection:
    """Open only an existing SQLite database, refusing to create a blank one."""
    resolved = path.resolve()
    if not resolved.is_file():
        raise RuntimeError(f"Database does not exist: {resolved}")
    # URI mode=ro is important: sqlite3.connect(path) otherwise creates an
    # empty SQLite database on typos, accidentally destroying the audit value.
    connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def check_integrity(connection: sqlite3.Connection) -> None:
    result = connection.execute("PRAGMA integrity_check").fetchall()
    if not result or any(row[0] != "ok" for row in result):
        raise RuntimeError("SQLite integrity_check failed; STOP and restore a verified backup.")
    # Invalid parent relations are reported but never deleted or repaired.
    try:
        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.DatabaseError as exc:
        print(f"WARNING: Foreign-key audit could not finish: {exc}. No changes made.")
    else:
        if violations:
            print(f"WARNING: {len(violations)} foreign-key violations found (no data was changed).")


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def safe_count(connection: sqlite3.Connection, table: str) -> int:
    # This function is called only with static, known names, never user input.
    return connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]


def summarize(connection: sqlite3.Connection) -> dict[str, int]:
    existing = table_names(connection)
    return {name: safe_count(connection, name) for name in SENSITIVE_TABLES if name in existing}


def expected_schema() -> dict[str, set[str]]:
    """Read SQLAlchemy model definitions without opening or mutating the DB."""
    # The import list mirrors registered app models. Importing does not call
    # create_app(), unlike starting run.py, which can create missing tables.
    from app.database import db
    from app.models import (
        user_model, validation_code_model, academic_models, admin_audit_model,
        scan_token_model, access_scan_pair_model, validation_revocation_model,
        user_presence_model, university_notice_model, university_notice_read_model,
        auth_attempt_model, access_log_model,
    )
    return {
        table.name: {column.name for column in table.columns}
        for table in db.metadata.tables.values()
    }


def audit_schema(connection: sqlite3.Connection) -> bool:
    """Report differences only. Never add columns, tables, or constraints."""
    actual_tables = table_names(connection)
    expected = expected_schema()
    missing_tables = sorted(set(expected) - actual_tables)
    missing_columns = {}
    for name, expected_columns in expected.items():
        if name not in actual_tables:
            continue
        # Names come from model metadata, and SQL identifiers are quoted.
        escaped = name.replace('"', '""')
        existing_columns = {
            row[1] for row in connection.execute(f'PRAGMA table_info("{escaped}")')
        }
        missing = sorted(expected_columns - existing_columns)
        if missing:
            missing_columns[name] = missing
    print(f"Schema audit: {len(actual_tables)} existing tables; "
          f"{len(expected)} model tables.")
    if missing_tables:
        print("WARNING: Missing model tables: " + ", ".join(missing_tables))
    for table, names in sorted(missing_columns.items()):
        print(f"WARNING: Missing columns in {table}: " + ", ".join(names))
    if not missing_tables and not missing_columns:
        print("Schema check passed: all expected tables and columns exist.")
    else:
        print("No database changes made. Review differences before planning migrations.")
    return not missing_tables and not missing_columns


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_verified_backup(source: sqlite3.Connection, directory: Path) -> Path:
    """Create a consistent snapshot with SQLite's online backup API."""
    directory.mkdir(parents=True, exist_ok=True)
    name = datetime.now(timezone.utc).strftime("unitrack-verified-%Y%m%dT%H%M%S-%fZ-")
    output = directory / (name + uuid4().hex[:8] + ".db")
    if output.exists():
        raise RuntimeError("Backup name unexpectedly already exists")
    try:
        with sqlite3.connect(str(output), timeout=30) as destination:
            source.backup(destination, pages=128, sleep=0.05)
        with closing(open_existing_database(output)) as snapshot:
            check_integrity(snapshot)
            counts = summarize(snapshot)
        manifest = {
            "filename": output.name,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256(output),
            "table_counts": counts,
        }
        manifest_path = output.with_suffix(".json")
        # Metadata only; no passwords, usernames or actual attendance rows.
        with manifest_path.open("x", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"Verified database backup: {output}")
        print(f"SHA256: {manifest['sha256']}")
        print(f"Backup inventory: {manifest_path}")
        return output
    except Exception:
        # Keep any incomplete backup for forensic inspection; never touch the
        # original SQLite database or previous verified backups.
        print(f"Backup attempt failed; source database left untouched: {output}", file=sys.stderr)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE,
                        help="An existing SQLite database; default: ./unitrack.db")
    parser.add_argument("--integrity-only", action="store_true",
                        help="Check SQLite integrity without loading model metadata")
    parser.add_argument("--schema", action="store_true",
                        help="Compare tables and columns to the current models (read-only)")
    parser.add_argument("--strict", action="store_true",
                        help="With --schema, fail if models have missing tables/columns")
    parser.add_argument("--backup", action="store_true",
                        help="Write a new verified SQLite snapshot to backups/")
    args = parser.parse_args(argv)
    if args.integrity_only and args.schema:
        parser.error("Choose either --integrity-only or --schema")
    if args.strict and not args.schema:
        parser.error("--strict requires --schema")
    try:
        with closing(open_existing_database(args.database)) as connection:
            check_integrity(connection)
            print(f"SQLite integrity: OK ({args.database.resolve()})")
            counts = summarize(connection)
            for name, count in sorted(counts.items()):
                print(f"  {name}: {count} records")
            schema_ok = True
            if args.schema:
                schema_ok = audit_schema(connection)
            if args.backup:
                create_verified_backup(connection, BACKUP_FOLDER)
            return 0 if schema_ok or not args.strict else 2
    except (OSError, RuntimeError, sqlite3.DatabaseError) as exc:
        print(f"Database safety check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
