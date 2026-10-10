from __future__ import annotations

import copy
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .config import Settings
from .models import AuditRecord, ChallengeRecord, SessionRecord, TicketRecord, WalletRecord
from .time import isoformat_utc, utc_now


class AuthStore(Protocol):
    def is_ready(self) -> bool: ...
    def create_ticket_if_capacity(self, ticket: TicketRecord, limit: int) -> bool: ...
    def replace_challenge(self, challenge: ChallengeRecord, approve_token: str) -> TicketRecord: ...
    def finalize_approval(
        self, expected: ChallengeRecord, settings: Settings, session: SessionRecord | None = None,
    ) -> tuple[TicketRecord, SessionRecord | None]: ...
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
    return datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162


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


class StoreTransitionError(Exception):
    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


class AtomicOperations:
    def _lock_capacity(self) -> None:
        pass

    def _ticket_for_update(self, ticket_id: str) -> TicketRecord | None:
        return self.get_ticket(ticket_id)

    def _challenge_for_update(self, challenge_id: str) -> ChallengeRecord | None:
        return self.get_challenge(challenge_id)

    def _check_challenge_expiry(self, challenge: ChallengeRecord, now: datetime) -> None:
        if challenge.expiresAt <= now:
            raise StoreTransitionError(410, "auth_challenge_expired")

    def create_ticket_if_capacity(self, ticket: TicketRecord, limit: int) -> bool:
        with self.atomic():
            self._lock_capacity()
            if self.pending_ticket_count() >= limit:
                return False
            self.create_ticket(ticket)
            return True

    def _pending_ticket(self, ticket_id: str) -> TicketRecord:
        ticket = self._ticket_for_update(ticket_id)
        if ticket is None or ticket.expiresAt <= self._now():
            raise StoreTransitionError(404, "device_login_ticket_not_found")
        if ticket.status != "pending":
            raise StoreTransitionError(409, "device_login_ticket_not_pending")
        return ticket

    def replace_challenge(self, challenge: ChallengeRecord, approve_token: str) -> TicketRecord:
        with self.atomic():
            ticket = self._pending_ticket(challenge.ticketId)
            if ticket.approveToken != approve_token:
                raise StoreTransitionError(403, "device_login_approve_forbidden")
            if challenge.expiresAt <= self._now():
                raise StoreTransitionError(410, "auth_challenge_expired")
            if ticket.challengeId:
                self.delete_challenge(ticket.challengeId)
            # The old challenge's row lock can also have waited.
            now = self._now()
            if ticket.expiresAt <= now:
                raise StoreTransitionError(404, "device_login_ticket_not_found")
            if challenge.expiresAt <= now:
                raise StoreTransitionError(410, "auth_challenge_expired")
            self.create_challenge(challenge)
            ticket.challengeId = challenge.challengeId
            self.save_ticket(ticket)
            self.add_audit("device_login_challenge_create", address=challenge.address,
                           details={"ticketId": ticket.ticketId, "challengeId": challenge.challengeId})
            return ticket

    def finalize_approval(
        self, expected: ChallengeRecord, settings: Settings, session: SessionRecord | None = None,
    ) -> tuple[TicketRecord, SessionRecord | None]:
        with self.atomic():
            ticket = self._pending_ticket(expected.ticketId)
            if ticket.challengeId != expected.challengeId:
                raise StoreTransitionError(400, "device_login_challenge_mismatch")
            current = self._challenge_for_update(expected.challengeId)
            allowed = current is not None and self.is_wallet_allowed(current.address.lower(), settings)
            # Read the database clock after ticket, challenge AND wallet lock waits.
            now = self._now()
            if current is None:
                raise StoreTransitionError(404, "auth_challenge_not_found")
            self._check_challenge_expiry(current, now)
            if ticket.expiresAt <= now:
                raise StoreTransitionError(404, "device_login_ticket_not_found")
            if current != expected or current.ticketId != ticket.ticketId:
                raise StoreTransitionError(400, "device_login_challenge_mismatch")
            if not allowed:
                ticket.status = "denied"
                ticket.failureReason = "auth_wallet_not_allowed"
                self.save_ticket(ticket)
                self.delete_challenge(current.challengeId)
                self.add_audit("device_login_approve", address=current.address, result="blocked",
                               details={"reason": "auth_wallet_not_allowed", "ticketId": ticket.ticketId})
                return ticket, None
            if session is None:
                return ticket, None
            if (session.challengeId != current.challengeId or session.address != current.address
                    or session.network != current.network or session.expiresAt <= now):
                raise StoreTransitionError(410, "auth_challenge_expired")
            self.create_session(session)
            ticket.status = "approved"
            ticket.sessionId = session.sessionId
            self.save_ticket(ticket)
            self.delete_challenge(current.challengeId)
            self.add_audit("device_login_approve", address=current.address,
                           details={"ticketId": ticket.ticketId, "sessionId": session.sessionId})
            return ticket, session


class InMemoryStore(AtomicOperations):
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

    @contextmanager
    def atomic(self):
        with self.lock:
            before = copy.deepcopy((self.tickets, self.challenges, self.sessions, self.wallets, self.audit))
            try:
                yield
            except BaseException:
                self.tickets, self.challenges, self.sessions, self.wallets, self.audit = before
                raise

    def _now(self):
        return utc_now()

    def is_ready(self) -> bool:
        return True

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
            return copy.deepcopy(self.tickets.get(ticket_id))

    def save_ticket(self, ticket: TicketRecord) -> None:
        with self.lock:
            self.tickets[ticket.ticketId] = ticket

    def create_challenge(self, challenge: ChallengeRecord) -> None:
        with self.lock:
            self.challenges[challenge.challengeId] = challenge

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        self.purge_expired()
        with self.lock:
            return copy.deepcopy(self.challenges.get(challenge_id))

    def delete_challenge(self, challenge_id: str) -> None:
        with self.lock:
            self.challenges.pop(challenge_id, None)

    def create_session(self, session: SessionRecord) -> None:
        with self.lock:
            self.sessions[session.sessionId] = session

    def get_session(self, session_id: str) -> SessionRecord | None:
        self.purge_expired()
        with self.lock:
            return copy.deepcopy(self.sessions.get(session_id))

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
            return copy.deepcopy(self.wallets.get(address.strip().lower()))

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


class SQLiteStore(AtomicOperations):
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._rate_lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.rate_events: dict[str, list[float]] = {}
        self._migrate()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @contextmanager
    def atomic(self):
        with self.lock:
            outer = getattr(self, "_transaction_depth", 0) == 0
            if outer:
                self._conn.execute("begin immediate")
            self._transaction_depth = getattr(self, "_transaction_depth", 0) + 1
            try:
                yield
                if outer:
                    self._conn.commit()
            except BaseException:
                if outer:
                    self._conn.rollback()
                raise
            finally:
                self._transaction_depth -= 1

    def _now(self):
        return utc_now()

    def is_ready(self) -> bool:
        try:
            self._one("select 1 from tickets, challenges, sessions, wallets, audit_log limit 0")
            return True
        except sqlite3.Error:
            return False

    def _commit(self):
        if not getattr(self, "_transaction_depth", 0):
            self._conn.commit()

    def _one(self, sql, params=()):
        with self.lock:
            return self._conn.execute(sql, params).fetchone()

    def _all(self, sql, params=()):
        with self.lock:
            return self._conn.execute(sql, params).fetchall()

    def _execute(self, sql: str, params: tuple = ()):
        with self.atomic():
            return self._conn.execute(sql, params)

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
            columns = {
                row["name"]
                for row in self._conn.execute("pragma table_info(tickets)").fetchall()
            }
            if "failure_reason" not in columns:
                self._conn.execute("alter table tickets add column failure_reason text")
            self._conn.commit()

    def bootstrap(self, settings: Settings) -> None:
        with self.atomic():
            for address in sorted(settings.allowed_wallets):
                wallet = _wallet_record(address, label="Bootstrap wallet", role="user")
                self._execute(
                    "insert into wallets (address,label,role,enabled,created_at,updated_at) "
                    "values (?,?,?,?,?,?) on conflict(address) do nothing",
                    (wallet.address, wallet.label, wallet.role, wallet.enabled,
                     isoformat_utc(wallet.createdAt), isoformat_utc(wallet.updatedAt)),
                )

    def purge_expired(self) -> None:
        with self.atomic():
            now = isoformat_utc(self._now())
            self._execute("delete from tickets where expires_at <= ? and status != 'approved'", (now,))
            self._execute("delete from challenges where expires_at <= ?", (now,))
            self._execute("delete from sessions where expires_at <= ?", (now,))

    def pending_ticket_count(self) -> int:
        self.purge_expired()
        row = self._one("select count(*) as count from tickets where status = 'pending'")
        return int(row["count"])

    def create_ticket(self, ticket: TicketRecord) -> None:
        self._execute(
            """
            insert into tickets (
                ticket_id, poll_token, approve_token, approve_url, qr_svg, status,
                issued_at, expires_at, challenge_id, session_id, failure_reason
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ticket.failureReason,
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
            failureReason=(
                row["failure_reason"] if "failure_reason" in row.keys() else None  # noqa: SIM118
            ),
        )

    def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        self.purge_expired()
        row = self._one("select * from tickets where ticket_id = ?", (ticket_id,))
        return self._ticket_from_row(row)

    def save_ticket(self, ticket: TicketRecord) -> None:
        self._execute(
            """
            update tickets set status = ?, challenge_id = ?, session_id = ?, failure_reason = ? where ticket_id = ?
            """,
            (ticket.status, ticket.challengeId, ticket.sessionId, ticket.failureReason, ticket.ticketId),
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
        row = self._one("select * from challenges where challenge_id = ?", (challenge_id,))
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
        with self.lock:
            row = self._one("select * from sessions where session_id = ?", (session_id,))
            session = self._session_from_row(row)
            return session if session and session.expiresAt > self._now() else None

    def delete_session(self, session_id: str) -> None:
        self._execute("delete from sessions where session_id = ?", (session_id,))

    def upsert_wallet(self, wallet: WalletRecord) -> WalletRecord:
        with self.atomic():
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
                    wallet.enabled,
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
        self, address: str, *, label: str | None = None, role: str | None = None,
        enabled: bool | None = None,
    ) -> WalletRecord | None:
        with self.atomic():
            assignments = ["updated_at = ?"]
            values = [isoformat_utc(self._now())]
            for column, value in (("label", label), ("role", role), ("enabled", enabled)):
                if value is not None:
                    assignments.append(column + " = ?")
                    values.append((value.strip() or "user") if column == "role" else value.strip() if column == "label" else value)
            values.append(address.strip().lower())
            self._execute("update wallets set " + ", ".join(assignments) + " where address = ?", tuple(values))
            return self.get_wallet(address)

    def get_wallet(self, address: str) -> WalletRecord | None:
        row = self._one("select * from wallets where address = ?", (address.strip().lower(),))
        return self._wallet_from_row(row)

    def list_wallets(self) -> list[WalletRecord]:
        rows = self._all("select * from wallets order by address")
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
        rows = self._all("select * from audit_log order by id desc limit ?", (max(1, min(limit, 1000)),))
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
        with self._rate_lock:
            events = [item for item in self.rate_events.get(key, []) if item >= cutoff]
            if len(events) >= limit:
                self.rate_events[key] = events
                return False
            events.append(now)
            self.rate_events[key] = events
            return True


class _PostgresConnection:
    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("Install psycopg to use KBEAM_AUTH_STORE_BACKEND=postgres") from exc
        self._dsn, self._psycopg, self._row_factory = dsn, psycopg, dict_row
        self._conn = self._connect()

    def _connect(self):
        # psycopg bounds each configured address attempt, including the
        # read-write session check. Never repeat application SQL here.
        return self._psycopg.connect(
            self._dsn, row_factory=self._row_factory, autocommit=True,
            connect_timeout=5, target_session_attrs="read-write",
        )

    def _require_primary(self, connection) -> None:
        try:
            row = connection.execute(
                "select not pg_is_in_recovery() and "
                "current_setting('transaction_read_only') = 'off' as writable"
            ).fetchone()
            if not row["writable"]:
                raise RuntimeError("Authentication datastore is not a writable primary")
        except BaseException:
            connection.close()
            raise

    def ensure_ready(self) -> None:
        # Called only before a new outer transaction or standalone read.
        # A failed operation is propagated; only a later operation reconnects.
        if self._conn.closed:
            self._conn = self._connect()
        else:
            self._require_primary(self._conn)

    def execute(self, sql: str, params: tuple = ()):
        try:
            return self._conn.execute(sql.replace("?", "%s"), params)
        except self._psycopg.Error as exc:
            if (self._conn.closed or isinstance(exc, (self._psycopg.OperationalError,
                                                      self._psycopg.InterfaceError))
                    or exc.sqlstate == "25006"):
                self._conn.close()
            raise

    def commit(self) -> None:
        try:
            self._conn.commit()
        except self._psycopg.Error:
            self._conn.close()
            raise

    def rollback(self) -> None:
        # Rollback must neither reconnect nor hide an uncertain commit.
        if not self._conn.closed:
            try:
                self._conn.rollback()
            except self._psycopg.Error:
                self._conn.close()


class PostgresStore(SQLiteStore):
    def __init__(self, dsn: str) -> None:
        self._lock = threading.RLock()
        self._rate_lock = threading.Lock()
        self._conn = _PostgresConnection(dsn)
        self.rate_events: dict[str, list[float]] = {}
        self._migrate()

    @contextmanager
    def atomic(self):
        with self.lock:
            outer = getattr(self, "_transaction_depth", 0) == 0
            if outer:
                self._conn.ensure_ready()
                self._conn.execute("begin")
            self._transaction_depth = getattr(self, "_transaction_depth", 0) + 1
            try:
                yield
                if outer:
                    self._conn.commit()
            except BaseException:
                if outer:
                    self._conn.rollback()
                raise
            finally:
                self._transaction_depth -= 1

    def _now(self):
        return self._one("select clock_timestamp() as now")["now"]

    def _lock_capacity(self) -> None:
        self._conn.execute("select pg_advisory_xact_lock(720072, 1)")

    def _ticket_for_update(self, ticket_id: str) -> TicketRecord | None:
        return self._ticket_from_row(self._one(
            "select * from tickets where ticket_id = ? for update", (ticket_id,),
        ))

    def _challenge_for_update(self, challenge_id: str) -> ChallengeRecord | None:
        return self._challenge_from_row(self._one(
            "select * from challenges where challenge_id = ? for update", (challenge_id,),
        ))

    def _check_challenge_expiry(self, challenge: ChallengeRecord, now: datetime) -> None:
        # Preserve the missing-row result of the former second-precision purge,
        # including expiry while waiting for the wallet row.
        if isoformat_utc(challenge.expiresAt) <= isoformat_utc(now):
            raise StoreTransitionError(404, "auth_challenge_not_found")
        super()._check_challenge_expiry(challenge, now)

    def get_ticket(self, ticket_id: str) -> TicketRecord | None:
        return self._ticket_from_row(self._one(
            "select * from tickets where ticket_id = ? and (status = 'approved' or "
            "expires_at > to_char(clock_timestamp() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))",
            (ticket_id,),
        ))

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        return self._challenge_from_row(self._one(
            "select * from challenges where challenge_id = ? and "
            "expires_at > to_char(clock_timestamp() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
            (challenge_id,),
        ))

    def get_session(self, session_id: str) -> SessionRecord | None:
        row = self._one(
            "select *, clock_timestamp() as observed_at from sessions where session_id = ?",
            (session_id,),
        )
        session = self._session_from_row(row)
        return session if session and session.expiresAt > row["observed_at"] else None

    def pending_ticket_count(self) -> int:
        row = self._one(
            "select count(*) as count from tickets where status = 'pending' and "
            "expires_at > to_char(clock_timestamp() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
        )
        return int(row["count"])

    def purge_expired(self) -> None:
        # Incremental cleanup at ticket creation, never a prerequisite for reads
        # or capacity. Skip active transitions and bound each existing TTL set.
        with self.atomic():
            now = isoformat_utc(self._now())
            for table, key, extra in (
                ("tickets", "ticket_id", " and status != 'approved'"),
                ("challenges", "challenge_id", ""),
                ("sessions", "session_id", ""),
            ):
                self._execute(
                    f"delete from {table} where {key} in (select {key} from {table} "
                    f"where expires_at <= ?{extra} order by expires_at, {key} "
                    "limit 128 for update skip locked)", (now,),
                )

    def get_wallet(self, address: str) -> WalletRecord | None:
        with self.lock:
            suffix = " for update" if getattr(self, "_transaction_depth", 0) else ""
            return self._wallet_from_row(self._one(
                "select * from wallets where address = ?" + suffix, (address.strip().lower(),),
            ))

    def upsert_wallet(self, wallet: WalletRecord) -> WalletRecord:
        with self.atomic():
            existing = self.get_wallet(wallet.address)
            if existing is None:
                row = self._one(
                    "insert into wallets (address,label,role,enabled,created_at,updated_at) "
                    "values (?,?,?,?,?,?) on conflict(address) do nothing returning *",
                    (wallet.address, wallet.label, wallet.role, wallet.enabled,
                     isoformat_utc(wallet.createdAt), isoformat_utc(wallet.updatedAt)),
                )
                if row is not None:
                    return self._wallet_from_row(row)
                # A confirmed conflicting insert can have created the row after
                # our absent read. Lock it before computing the update timestamp.
                existing = self.get_wallet(wallet.address)
                if existing is None:
                    raise RuntimeError("Wallet disappeared after confirmed insert conflict")
            row = self._one(
                "update wallets set label=?,role=?,enabled=?,updated_at=? "
                "where address=? returning *",
                (wallet.label, wallet.role, wallet.enabled, isoformat_utc(utc_now()), wallet.address),
            )
            return self._wallet_from_row(row)

    def update_wallet(
        self, address: str, *, label: str | None = None, role: str | None = None,
        enabled: bool | None = None,
    ) -> WalletRecord | None:
        with self.atomic():
            if self.get_wallet(address) is None:
                return None
            # The inherited DB clock read now follows the actual row-lock wait.
            return super().update_wallet(address, label=label, role=role, enabled=enabled)

    def _one(self, sql, params=()):
        with self.lock:
            if not getattr(self, "_transaction_depth", 0):
                self._conn.ensure_ready()
            return self._conn.execute(sql, params).fetchone()

    def _all(self, sql, params=()):
        with self.lock:
            if not getattr(self, "_transaction_depth", 0):
                self._conn.ensure_ready()
            return self._conn.execute(sql, params).fetchall()

    def is_ready(self) -> bool:
        import psycopg

        try:
            self._one("select 1 from tickets, challenges, sessions, wallets, audit_log limit 0")
            return True
        except (psycopg.Error, RuntimeError):
            return False

    def _migrate(self) -> None:
        statements = [
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
                session_id text,
                failure_reason text
            )
            """,
            "alter table tickets add column if not exists failure_reason text",
            """
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
            )
            """,
            """
            create table if not exists sessions (
                session_id text primary key,
                address text not null,
                network text not null,
                public_key text not null,
                issued_at text not null,
                expires_at text not null,
                challenge_id text not null
            )
            """,
            """
            create table if not exists wallets (
                address text primary key,
                label text not null default '',
                role text not null default 'user',
                enabled boolean not null default true,
                created_at text not null,
                updated_at text not null
            )
            """,
            """
            create table if not exists audit_log (
                id bigserial primary key,
                event text not null,
                address text,
                result text not null,
                details text not null,
                created_at text not null
            )
            """,
            "create index if not exists tickets_status_idx on tickets (status)",
            "create index if not exists tickets_expires_at_idx on tickets (expires_at)",
            "create index if not exists challenges_expires_at_idx on challenges (expires_at)",
            "create index if not exists sessions_expires_at_idx on sessions (expires_at)",
            "create index if not exists audit_log_created_at_idx on audit_log (created_at)",
        ]
        with self.atomic():
            # Preserve serialization of the existing startup-only provisioning.
            self._lock_capacity()
            for statement in statements:
                self._conn.execute(statement)
            self._commit()


def create_store(settings: Settings) -> AuthStore:
    if settings.store_backend == "memory":
        store: AuthStore = InMemoryStore()
    elif settings.store_backend == "sqlite":
        store = SQLiteStore(settings.sqlite_path)
    else:
        store = PostgresStore(settings.postgres_dsn)
    store.bootstrap(settings)
    return store
