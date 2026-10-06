from __future__ import annotations

import sqlite3
import threading

from kbeam_auth_gateway.models import TicketRecord
from kbeam_auth_gateway.store import PostgresStore, SQLiteStore
from kbeam_auth_gateway.time import isoformat_utc, utc_after, utc_now

_LEGACY_TICKET_COLUMNS = (
    "ticket_id",
    "poll_token",
    "approve_token",
    "approve_url",
    "qr_svg",
    "status",
    "issued_at",
    "expires_at",
    "challenge_id",
    "session_id",
)


class _Cursor:
    def __init__(self, row: dict | None = None) -> None:
        self._row = row

    def fetchone(self) -> dict | None:
        return self._row


class _PostgresConnectionDouble:
    def __init__(self, *, existing_ticket: dict | None = None) -> None:
        self.executed: list[tuple[str, tuple]] = []
        self.ticket_columns = set(_LEGACY_TICKET_COLUMNS) if existing_ticket else set()
        self.ticket_rows = (
            {existing_ticket["ticket_id"]: dict(existing_ticket)} if existing_ticket else {}
        )
        self.commits = 0

    def execute(self, sql: str, params: tuple = ()) -> _Cursor:
        normalized = " ".join(sql.split()).lower()
        self.executed.append((normalized, params))

        if normalized == "select clock_timestamp() as now":
            return _Cursor({"now": utc_now()})
        if normalized.startswith("create table if not exists tickets"):
            if not self.ticket_columns:
                body = sql[sql.index("(") + 1 : sql.rindex(")")]
                self.ticket_columns = {
                    line.strip().rstrip(",").split()[0]
                    for line in body.splitlines()
                    if line.strip()
                }
        elif normalized == "alter table tickets add column if not exists failure_reason text":
            if "failure_reason" not in self.ticket_columns:
                self.ticket_columns.add("failure_reason")
                for row in self.ticket_rows.values():
                    row["failure_reason"] = None
        elif normalized.startswith("insert into tickets"):
            columns = (
                "ticket_id",
                "poll_token",
                "approve_token",
                "approve_url",
                "qr_svg",
                "status",
                "issued_at",
                "expires_at",
                "challenge_id",
                "session_id",
                "failure_reason",
            )
            row = dict(zip(columns, params, strict=True))
            self.ticket_rows[row["ticket_id"]] = row
        elif normalized.startswith("update tickets set status"):
            status, challenge_id, session_id, failure_reason, ticket_id = params
            self.ticket_rows[ticket_id].update(
                status=status,
                challenge_id=challenge_id,
                session_id=session_id,
                failure_reason=failure_reason,
            )
        elif normalized.startswith("select * from tickets where ticket_id"):
            return _Cursor(self.ticket_rows.get(params[0]))

        return _Cursor()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        pass


def _ticket(*, ticket_id: str = "ticket_test") -> TicketRecord:
    return TicketRecord(
        ticketId=ticket_id,
        pollToken="poll-token",
        approveToken="approve-token",
        approveURL="kbeam://pos-login?ticket=ticket_test",
        qrSvg="<svg />",
        status="pending",
        issuedAt=utc_now(),
        expiresAt=utc_after(3600),
    )


def _legacy_ticket_row(ticket: TicketRecord) -> dict:
    return {
        "ticket_id": ticket.ticketId,
        "poll_token": ticket.pollToken,
        "approve_token": ticket.approveToken,
        "approve_url": ticket.approveURL,
        "qr_svg": ticket.qrSvg,
        "status": ticket.status,
        "issued_at": isoformat_utc(ticket.issuedAt),
        "expires_at": isoformat_utc(ticket.expiresAt),
        "challenge_id": ticket.challengeId,
        "session_id": ticket.sessionId,
    }


def _postgres_store(connection: _PostgresConnectionDouble) -> PostgresStore:
    store = PostgresStore.__new__(PostgresStore)
    store._lock = threading.RLock()
    store._conn = connection
    store.rate_events = {}
    store._migrate()
    return store


def test_postgres_fresh_schema_persists_failure_reason():
    connection = _PostgresConnectionDouble()
    store = _postgres_store(connection)

    assert "failure_reason" in connection.ticket_columns
    create_tickets = next(
        sql
        for sql, _ in connection.executed
        if sql.startswith("create table if not exists tickets")
    )
    assert "failure_reason text" in create_tickets
    assert "failure_reason text not null" not in create_tickets

    ticket = _ticket()
    store.create_ticket(ticket)
    ticket.status = "denied"
    ticket.failureReason = "auth_wallet_not_allowed"
    store.save_ticket(ticket)

    persisted = store.get_ticket(ticket.ticketId)
    assert persisted is not None
    assert persisted.status == "denied"
    assert persisted.failureReason == "auth_wallet_not_allowed"


def test_postgres_upgrade_preserves_legacy_ticket():
    ticket = _ticket(ticket_id="ticket_legacy_postgres")
    connection = _PostgresConnectionDouble(existing_ticket=_legacy_ticket_row(ticket))
    store = _postgres_store(connection)

    assert "failure_reason" in connection.ticket_columns
    assert any(
        sql == "alter table tickets add column if not exists failure_reason text"
        for sql, _ in connection.executed
    )
    persisted = store.get_ticket(ticket.ticketId)
    assert persisted is not None
    assert persisted.pollToken == ticket.pollToken
    assert persisted.status == "pending"
    assert persisted.failureReason is None


def test_sqlite_upgrade_preserves_legacy_ticket(tmp_path):
    database_path = tmp_path / "legacy-auth.sqlite3"
    ticket = _ticket(ticket_id="ticket_legacy_sqlite")
    legacy_row = _legacy_ticket_row(ticket)
    connection = sqlite3.connect(database_path)
    connection.execute(
        """
        create table tickets (
            ticket_id text primary key,
            poll_token text not null,
            approve_token text not null,
            approve_url text not null,
            qr_svg text not null,
            status text not null,
            issued_at text not null,
            expires_at text not null,
            challenge_id text,
            session_id text
        )
        """
    )
    connection.execute(
        """
        insert into tickets (
            ticket_id, poll_token, approve_token, approve_url, qr_svg, status,
            issued_at, expires_at, challenge_id, session_id
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(legacy_row[column] for column in _LEGACY_TICKET_COLUMNS),
    )
    connection.commit()
    connection.close()

    store = SQLiteStore(str(database_path))

    columns = {
        row["name"] for row in store._conn.execute("pragma table_info(tickets)").fetchall()
    }
    assert "failure_reason" in columns
    persisted = store.get_ticket(ticket.ticketId)
    assert persisted is not None
    assert persisted.pollToken == ticket.pollToken
    assert persisted.status == "pending"
    assert persisted.failureReason is None
