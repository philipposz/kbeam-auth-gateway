"""Explicit protected transfer of one quiesced authentication authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import quote

import psycopg

from kbeam_auth_gateway.store import PostgresStore, SQLiteStore

SCHEMA = "kbeam-auth-state-v1"
COLUMNS = {
    "tickets": ("ticket_id", "poll_token", "approve_token", "approve_url", "qr_svg", "status",
                "issued_at", "expires_at", "challenge_id", "session_id", "failure_reason"),
    "challenges": ("challenge_id", "ticket_id", "address", "network", "nonce", "issued_at",
                   "expires_at", "origin", "message"),
    "sessions": ("session_id", "address", "network", "public_key", "issued_at", "expires_at",
                 "challenge_id"),
    "wallets": ("address", "label", "role", "enabled", "created_at", "updated_at"),
    "audit_log": ("id", "event", "address", "result", "details", "created_at"),
}


def digest(bundle: dict) -> str:
    return hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


def validate(bundle: dict) -> dict:
    if set(bundle) != {"schema", "tables"} or bundle["schema"] != SCHEMA or set(bundle["tables"]) != set(COLUMNS):
        raise ValueError("invalid_auth_bundle")
    for table, rows in bundle["tables"].items():
        if not isinstance(rows, list):
            raise TypeError("invalid_auth_rows")
        keys = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != set(COLUMNS[table]):
                raise ValueError("invalid_auth_columns")
            key = row[COLUMNS[table][0]]
            if key in keys:
                raise ValueError("duplicate_auth_key")
            keys.add(key)
    return bundle


def _snapshot(connection, *, sqlite=False):
    tables = {}
    for table, columns in COLUMNS.items():
        if sqlite:
            actual = {row["name"] for row in connection.execute(f"pragma table_info({table})")}
            if actual == set(columns) - {"failure_reason"} and table == "tickets":
                selection = ",".join(columns[:-1]) + ",NULL as failure_reason"
            elif actual == set(columns):
                selection = ",".join(columns)
            else:
                raise ValueError("unsupported_auth_columns")
        else:
            selection = ",".join(columns)
        rows = [dict(row) for row in connection.execute(f"select {selection} from {table} order by {columns[0]}").fetchall()]
        if table == "wallets":
            for row in rows:
                row["enabled"] = bool(row["enabled"])
        tables[table] = rows
    return validate({"schema": SCHEMA, "tables": tables})


def read_sqlite(path: Path):
    # Never instantiate SQLiteStore here: its constructor migrates the source.
    uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("begin")
        return _snapshot(connection, sqlite=True)


def snapshot(store):
    with store.atomic():
        return _snapshot(store._conn)


def write_bundle(path: Path, bundle):
    validate(bundle)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, sort_keys=True, indent=2, ensure_ascii=True)
        handle.write("\n")
    return digest(bundle)


def import_bundle(store, bundle, expected_digest):
    validate(bundle)
    if digest(bundle) != expected_digest:
        raise ValueError("auth_import_digest_mismatch")
    with store.atomic():
        for table in COLUMNS:
            if store._one(f"select count(*) as count from {table}")["count"]:
                raise ValueError("auth_import_requires_empty_target")
        for table, rows in bundle["tables"].items():
            columns = COLUMNS[table]
            for row in rows:
                store._execute(f"insert into {table} ({','.join(columns)}) values ({','.join('?' for _ in columns)})",
                               tuple(row[column] for column in columns))
        if isinstance(store, PostgresStore):
            audit = bundle["tables"]["audit_log"]
            store._execute("select setval(pg_get_serial_sequence('audit_log','id'), ?, ?)",
                           (max((row["id"] for row in audit), default=1), bool(audit)))
        if digest(snapshot(store)) != expected_digest:
            raise ValueError("auth_import_roundtrip_mismatch")


def rollback(store, expected_digest):
    with store.atomic():
        if digest(snapshot(store)) != expected_digest:
            raise ValueError("auth_rollback_digest_mismatch")
        for table in COLUMNS:
            store._execute(f"delete from {table}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("sqlite-export", "export", "import", "rollback"))
    parser.add_argument("--source-sqlite", type=Path)
    parser.add_argument("--target-sqlite", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--confirmation")
    args = parser.parse_args()
    try:
        if args.operation in {"sqlite-export", "export", "import"} and args.bundle is None:
            raise ValueError("auth_bundle_path_required")
        if args.operation == "sqlite-export" and args.source_sqlite is None:
            raise ValueError("auth_sqlite_source_required")
        if args.operation == "sqlite-export":
            result = write_bundle(args.bundle, read_sqlite(args.source_sqlite))
        else:
            if args.target_sqlite:
                store = SQLiteStore(str(args.target_sqlite))
            else:
                store = PostgresStore(os.environ["KBEAM_AUTH_POSTGRES_DSN"])
            if args.operation == "export":
                result = write_bundle(args.bundle, snapshot(store))
            elif args.operation == "import":
                bundle = json.loads(args.bundle.read_text())
                import_bundle(store, bundle, args.expected_sha256)
                result = digest(bundle)
            else:
                if args.confirmation != "ROLL BACK QUIESCED AUTH STATE":
                    raise ValueError("auth_rollback_confirmation_required")
                rollback(store, args.expected_sha256)
                result = args.expected_sha256
        print(json.dumps({"ok": True, "operation": args.operation, "sha256": result}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, psycopg.Error):
        print(json.dumps({"ok": False, "error": "auth_state_transfer_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
