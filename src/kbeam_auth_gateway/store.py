from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .config import Settings
from .models import AuditRecord, ChallengeRecord, SessionRecord, TicketRecord, WalletRecord
from .time import isoformat_utc, utc_now


class AuthStore(Protocol):
    def bootstrap(self, settings: Settings) -> None: ...
    def purge_expired(self) -> None: ...
    def pending_ticket_count(self) -> int: ...
    def create_ticket(self, ticket: TicketRecord) -> None: ...
    def get_ticket(self, ticket_id: str) -> TicketRecord | None: ...
    def save_ticket(self, ticket: TicketRecord) -> None: ...
    def create_challenge(self, challenge: ChallengeRecord) -> None: ...
    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None: ...
    def delete_challenge(self, challenge_id: str) -> None: ...
    def create_session(self, session: SessionRecord) -> None: ...
    def get_session(self, session_id: str) -> SessionRecord | None: ...
    def delete_session(self, session_id: str) -> None: ...
    def upsert_wallet(self, wallet: WalletRecord) -> WalletRecord: ...
    def update_wallet(
        self,
        address: str,
        *,
        label: str | None = None,
        role: str | None = None,
        enabled: bool | None = None,
    ) -> WalletRecord | None: ...
    def get_wallet(self, address: str) -> WalletRecord | None: ...
    def list_wallets(self) -> list[WalletRecord]: ...
    def is_wallet_allowed(self, address: str, settings: Settings) -> bool: ...
    def add_audit(
        self,
        event: str,
        *,
        address: str | None = None,
        result: str = "ok",
        details: dict | None = None,
    ) -> None: ...
    def list_audit(self, limit: int = 100) -> list[AuditRecord]: ...
    def check_rate_limit(self, key: str, *, limit: int, window_seconds: int) -> bool: ...


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _wallet_record(address: str, *, label: str = "", role: str = "user", enabled: bool = True) -> WalletRecord:
    now = utc_now()
    return WalletRecord(
        address=address.strip().lower(),
        label=label.strip(),
        role=role.strip() or "user",
        enabled=enabled,
        createdAt=now,
        updatedAt=now,
    )


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.tickets: dict[str, TicketRecord] = {}
        self.challenges: dict[str, ChallengeRecord] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self.wallets: dict[str, WalletRecord] = {}
        self.audit: list[AuditRecord] = []
        self.rate_events: dict[str, list[float]] = {}

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def bootstrap(self, settings: Settings) -> None:
        with self.lock:
            for address in settings.allowed_wallets:
                if address not in self.wallets:
                    self.wallets[address] = _wallet_record(address, label="Bootstrap wallet", role="user")

    def purge_expired(self) -> None:
        now = utc_now()
        with self.lock:
            for ticket_id, ticket in list(self.tickets.items()):
                if ticket.expiresAt <= now and ticket.status != "approved":
                    self.tickets.pop(ticket_id, None)
            for challenge_id, challenge in list(self.challenges.items()):
                if challenge.expiresAt <= now:
                    self.challenges.pop(challenge_id, None)
            for session_id, session in list(self.sessions.items()):
                if session.expiresAt <= now:
                    self.sessions.pop(session_id, None)

    def pending_ticket_count(self) -> int:
        self.purge_expired()
        with self.lock:
            return sum(1 for ticket in self.tickets.values() if ticket.status == "pending")

    def create_ticket(self, ticket: TicketRecord) -> None:
        with self.lock:
            self.tickets[ticket.ticketId] = ticket

    def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        self.purge_expired()
        with self.lock:
            return self.tickets.get(ticket_id)

    def save_ticket(self, ticket: TicketRecord) -> None:
        with self.lock:
            self.tickets[ticket.ticketId] = ticket

    def create_challenge(self, challenge: ChallengeRecord) -> None:
        with self.lock:
            self.challenges[challenge.challengeId] = challenge

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        self.purge_expired()
        with self.lock:
            return self.challenges.get(challenge_id)

    def delete_challenge(self, challenge_id: str) -> None:
        with self.lock:
            self.challenges.pop(challenge_id, None)

    def create_session(self, session: SessionRecord) -> None:
        with self.lock:
            self.sessions[session.sessionId] = session

    def get_session(self, session_id: str) -> SessionRecord | None:
        self.purge_expired()
        with self.lock:
            return self.sessions.get(session_id)

    def delete_session(self, session_id: str) -> None:
        with self.lock:
            self.sessions.pop(session_id, None)

    def upsert_wallet(self, wallet: WalletRecord) -> WalletRecord:
        with self.lock:
            existing = self.wallets.get(wallet.address)
            if existing:
                wallet = wallet.model_copy(update={"createdAt": existing.createdAt, "updatedAt": utc_now()})
            self.wallets[wallet.address] = wallet
            return wallet

    def update_wallet(
        self,
        address: str,
        *,
        label: str | None = None,
        role: str | None = None,
        enabled: bool | None = None,
    ) -> WalletRecord | None:
        address = address.strip().lower()
        with self.lock:
            wallet = self.wallets.get(address)
            if not wallet:
                return None
            changes = {"updatedAt": utc_now()}
            if label is not None:
                changes["label"] = label.strip()
            if role is not None:
                changes["role"] = role.strip() or "user"
            if enabled is not None:
                changes["enabled"] = enabled
            wallet = wallet.model_copy(update=changes)
            self.wallets[address] = wallet
            return wallet

    def get_wallet(self, address: str) -> WalletRecord | None:
        with self.lock:
            return self.wallets.get(address.strip().lower())

    def list_wallets(self) -> list[WalletRecord]:
        with self.lock:
            return sorted(self.wallets.values(), key=lambda wallet: wallet.address)

    def is_wallet_allowed(self, address: str, settings: Settings) -> bool:
        if settings.wallet_policy == "open":
            return True
        wallet = self.get_wallet(address)
        return bool(wallet and wallet.enabled)

    def add_audit(
        self,
        event: str,
        *,
        address: str | None = None,
        result: str = "ok",
        details: dict | None = None,
    ) -> None:
        with self.lock:
            self.audit.append(
                AuditRecord(
                    id=len(self.audit) + 1,
                    event=event,
                    address=address.strip().lower() if address else None,
                    result=result,
                    details=details or {},
                    createdAt=utc_now(),
                )
            )

    def list_audit(self, limit: int = 100) -> list[AuditRecord]:
        with self.lock:
            return list(reversed(self.audit[-limit:]))

    def check_rate_limit(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self.lock:
            events = [item for item in self.rate_events.get(key, []) if item >= cutoff]
            if len(events) >= limit:
                self.rate_events[key] = events
                return False
            events.append(now)
            self.rate_events[key] = events
            return True


class SQLiteStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.rate_events: dict[str, list[float]] = {}
        self._migrate()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return cursor

    def _migrate(self) -> None:
        with self.lock:
            self._conn.executescript(
                """
                create table if not exists tickets (
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
                );
                create table if not exists challenges (
                    challenge_id text primary key,
                    ticket_id text not null,
                    address text not null,
                    network text not null,
                    nonce text not null,
                    issued_at text not null,
                    expires_at text not null,
                    origin text not null,
                    message text not null
                );
                create table if not exists sessions (
                    session_id text primary key,
                    address text not null,
                    network text not null,
                    public_key text not null,
                    issued_at text not null,
                    expires_at text not null,
                    challenge_id text not null
                );
                create table if not exists wallets (
                    address text primary key,
                    label text not null default '',
                    role text not null default 'user',
                    enabled integer not null default 1,
                    created_at text not null,
                    updated_at text not null
                );
                create table if not exists audit_log (
                    id integer primary key autoincrement,
                    event text not null,
                    address text,
                    result text not null,
                    details text not null,
                    created_at text not null
                );
                """
            )
            self._conn.commit()

    def bootstrap(self, settings: Settings) -> None:
        for address in settings.allowed_wallets:
            if not self.get_wallet(address):
                self.upsert_wallet(_wallet_record(address, label="Bootstrap wallet", role="user"))

    def purge_expired(self) -> None:
        now = isoformat_utc(utc_now())
        with self.lock:
            self._conn.execute("delete from tickets where expires_at <= ? and status != 'approved'", (now,))
            self._conn.execute("delete from challenges where expires_at <= ?", (now,))
            self._conn.execute("delete from sessions where expires_at <= ?", (now,))
            self._conn.commit()

    def pending_ticket_count(self) -> int:
        self.purge_expired()
        row = self._conn.execute("select count(*) as count from tickets where status = 'pending'").fetchone()
        return int(row["count"])

    def create_ticket(self, ticket: TicketRecord) -> None:
        self._execute(
            """
            insert into tickets (
                ticket_id, poll_token, approve_token, approve_url, qr_svg, status,
                issued_at, expires_at, challenge_id, session_id
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket.ticketId,
                ticket.pollToken,
                ticket.approveToken,
                ticket.approveURL,
                ticket.qrSvg,
                ticket.status,
                isoformat_utc(ticket.issuedAt),
                isoformat_utc(ticket.expiresAt),
                ticket.challengeId,
                ticket.sessionId,
            ),
        )

    def _ticket_from_row(self, row: sqlite3.Row | None) -> TicketRecord | None:
        if not row:
            return None
        return TicketRecord(
            ticketId=row["ticket_id"],
            pollToken=row["poll_token"],
            approveToken=row["approve_token"],
            approveURL=row["approve_url"],
            qrSvg=row["qr_svg"],
            status=row["status"],
            issuedAt=_parse_dt(row["issued_at"]),
            expiresAt=_parse_dt(row["expires_at"]),
            challengeId=row["challenge_id"],
            sessionId=row["session_id"],
        )

    def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        self.purge_expired()
        row = self._conn.execute("select * from tickets where ticket_id = ?", (ticket_id,)).fetchone()
        return self._ticket_from_row(row)

    def save_ticket(self, ticket: TicketRecord) -> None:
        self._execute(
            """
            update tickets set status = ?, challenge_id = ?, session_id = ? where ticket_id = ?
            """,
            (ticket.status, ticket.challengeId, ticket.sessionId, ticket.ticketId),
        )

    def create_challenge(self, challenge: ChallengeRecord) -> None:
        self._execute(
            """
            insert into challenges (
                challenge_id, ticket_id, address, network, nonce,
                issued_at, expires_at, origin, message
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge.challengeId,
                challenge.ticketId,
                challenge.address,
                challenge.network,
                challenge.nonce,
                isoformat_utc(challenge.issuedAt),
                isoformat_utc(challenge.expiresAt),
                challenge.origin,
                challenge.message,
            ),
        )

    def _challenge_from_row(self, row: sqlite3.Row | None) -> ChallengeRecord | None:
        if not row:
            return None
        return ChallengeRecord(
            challengeId=row["challenge_id"],
            ticketId=row["ticket_id"],
            address=row["address"],
            network=row["network"],
            nonce=row["nonce"],
            issuedAt=_parse_dt(row["issued_at"]),
            expiresAt=_parse_dt(row["expires_at"]),
            origin=row["origin"],
            message=row["message"],
        )

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        self.purge_expired()
        row = self._conn.execute("select * from challenges where challenge_id = ?", (challenge_id,)).fetchone()
        return self._challenge_from_row(row)

    def delete_challenge(self, challenge_id: str) -> None:
        self._execute("delete from challenges where challenge_id = ?", (challenge_id,))

    def create_session(self, session: SessionRecord) -> None:
        self._execute(
            """
            insert into sessions (
                session_id, address, network, public_key, issued_at, expires_at, challenge_id
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.sessionId,
                session.address,
                session.network,
                session.publicKey,
                isoformat_utc(session.issuedAt),
                isoformat_utc(session.expiresAt),
                session.challengeId,
            ),
        )

    def _session_from_row(self, row: sqlite3.Row | None) -> SessionRecord | None:
        if not row:
            return None
        return SessionRecord(
            sessionId=row["session_id"],
            address=row["address"],
            network=row["network"],
            publicKey=row["public_key"],
            issuedAt=_parse_dt(row["issued_at"]),
            expiresAt=_parse_dt(row["expires_at"]),
            challengeId=row["challenge_id"],
        )

    def get_session(self, session_id: str) -> SessionRecord | None:
        self.purge_expired()
        row = self._conn.execute("select * from sessions where session_id = ?", (session_id,)).fetchone()
        return self._session_from_row(row)

    def delete_session(self, session_id: str) -> None:
        self._execute("delete from sessions where session_id = ?", (session_id,))

    def upsert_wallet(self, wallet: WalletRecord) -> WalletRecord:
        existing = self.get_wallet(wallet.address)
        if existing:
            wallet = wallet.model_copy(update={"createdAt": existing.createdAt, "updatedAt": utc_now()})
        self._execute(
            """
            insert into wallets (address, label, role, enabled, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?)
            on conflict(address) do update set
                label = excluded.label,
                role = excluded.role,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """,
            (
                wallet.address,
                wallet.label,
                wallet.role,
                1 if wallet.enabled else 0,
                isoformat_utc(wallet.createdAt),
                isoformat_utc(wallet.updatedAt),
            ),
        )
        return wallet

    def _wallet_from_row(self, row: sqlite3.Row | None) -> WalletRecord | None:
        if not row:
            return None
        return WalletRecord(
            address=row["address"],
            label=row["label"],
            role=row["role"],
            enabled=bool(row["enabled"]),
            createdAt=_parse_dt(row["created_at"]),
            updatedAt=_parse_dt(row["updated_at"]),
        )

    def update_wallet(
        self,
        address: str,
        *,
        label: str | None = None,
        role: str | None = None,
        enabled: bool | None = None,
    ) -> WalletRecord | None:
        wallet = self.get_wallet(address)
        if not wallet:
            return None
        changes = {"updatedAt": utc_now()}
        if label is not None:
            changes["label"] = label.strip()
        if role is not None:
            changes["role"] = role.strip() or "user"
        if enabled is not None:
            changes["enabled"] = enabled
        return self.upsert_wallet(wallet.model_copy(update=changes))

    def get_wallet(self, address: str) -> WalletRecord | None:
        row = self._conn.execute(
            "select * from wallets where address = ?",
            (address.strip().lower(),),
        ).fetchone()
        return self._wallet_from_row(row)

    def list_wallets(self) -> list[WalletRecord]:
        rows = self._conn.execute("select * from wallets order by address").fetchall()
        return [self._wallet_from_row(row) for row in rows if row]

    def is_wallet_allowed(self, address: str, settings: Settings) -> bool:
        if settings.wallet_policy == "open":
            return True
        wallet = self.get_wallet(address)
        return bool(wallet and wallet.enabled)

    def add_audit(
        self,
        event: str,
        *,
        address: str | None = None,
        result: str = "ok",
        details: dict | None = None,
    ) -> None:
        self._execute(
            """
            insert into audit_log (event, address, result, details, created_at)
            values (?, ?, ?, ?, ?)
            """,
            (
                event,
                address.strip().lower() if address else None,
                result,
                json.dumps(details or {}, sort_keys=True),
                isoformat_utc(utc_now()),
            ),
        )

    def list_audit(self, limit: int = 100) -> list[AuditRecord]:
        rows = self._conn.execute(
            "select * from audit_log order by id desc limit ?",
            (max(1, min(limit, 1000)),),
        ).fetchall()
        return [
            AuditRecord(
                id=row["id"],
                event=row["event"],
                address=row["address"],
                result=row["result"],
                details=json.loads(row["details"] or "{}"),
                createdAt=_parse_dt(row["created_at"]),
            )
            for row in rows
        ]

    def check_rate_limit(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self.lock:
            events = [item for item in self.rate_events.get(key, []) if item >= cutoff]
            if len(events) >= limit:
                self.rate_events[key] = events
                return False
            events.append(now)
            self.rate_events[key] = events
            return True


def create_store(settings: Settings) -> AuthStore:
    if settings.store_backend == "memory":
        store: AuthStore = InMemoryStore()
    else:
        store = SQLiteStore(settings.sqlite_path)
    store.bootstrap(settings)
    return store
