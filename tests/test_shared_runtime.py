from __future__ import annotations

import asyncio
import copy
import hashlib
import multiprocessing
import os
import socket
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg.conninfo import make_conninfo
from starlette.exceptions import HTTPException
from starlette.requests import Request
from test_auth_flow import (
    _address,
    _private_key,
    _settings,
    _sign_raw_schnorr,
    _xonly_public_key_hex,
)

import kbeam_auth_gateway.app as app_module
from kbeam_auth_gateway.app import create_app
from kbeam_auth_gateway.models import SessionRecord, TicketRecord
from kbeam_auth_gateway.store import (
    InMemoryStore,
    PostgresStore,
    SQLiteStore,
    StoreTransitionError,
    _wallet_record,
)
from kbeam_auth_gateway.time import isoformat_utc, utc_after, utc_now
from tools.state_transfer import (
    digest,
    import_bundle,
    read_sqlite,
    rollback,
    snapshot,
    write_bundle,
)


@pytest.fixture
def pg_database():
    """Only create/drop a uniquely named database in an explicitly owned test cluster."""
    dsn = os.environ.get("KBEAM_AUTH_TEST_CLUSTER_DSN")
    pgdata = os.environ.get("KBEAM_AUTH_TEST_PGDATA")
    if not dsn or not pgdata:
        pytest.skip("explicit disposable PostgreSQL test cluster required")
    with psycopg.connect(dsn, autocommit=True) as admin:
        row = admin.execute("select current_user, current_setting('data_directory'), "
                            "current_setting('listen_addresses'), host(inet_server_addr())").fetchone()
        assert row[0] == "auth_synthetic"
        assert Path(row[1]).resolve() == Path(pgdata).resolve()
        assert row[2:] == ("127.0.0.1", "127.0.0.1")
        name = "auth_test_" + uuid.uuid4().hex
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(name)))
        connections = []

        def stores():
            store = PostgresStore(make_conninfo(dsn, dbname=name))
            connections.append(store._conn)
            return store

        try:
            yield stores, make_conninfo(dsn, dbname=name)
        finally:
            for connection in connections:
                connection._conn.close()
            admin.execute(sql.SQL("drop database {}").format(sql.Identifier(name)))


def _flow(client, store):
    key = _private_key()
    ticket = client.post("/api/auth/device-login").json()["deviceLogin"]
    response = client.post(f"/api/auth/device-login/{ticket['ticketId']}/challenge", json={
        "approveToken": store.get_ticket(ticket["ticketId"]).approveToken,
        "address": _address(key), "origin": "https://protected.example.com",
    })
    assert response.status_code == 201
    challenge = response.json()["challenge"]
    assert challenge["message"].startswith("KBeam login\nProtocol: kbeam-auth-v1\n")
    assert "\r" not in challenge["message"] and not challenge["message"].endswith("\n")
    approval = {
        "challengeId": challenge["challengeId"], "address": _address(key),
        "signature": _sign_raw_schnorr(key, challenge["message"]),
        "publicKey": _xonly_public_key_hex(key),
    }
    return ticket, challenge, approval


def _session(challenge):
    return SessionRecord(sessionId="session_synthetic", address=challenge.address,
                         network=challenge.network, publicKey="synthetic", issuedAt=utc_now(),
                         expiresAt=utc_after(300), challengeId=challenge.challengeId)


def _ticket(identifier):
    return TicketRecord(ticketId=identifier, pollToken="synthetic_poll", approveToken="synthetic_approve",
                        approveURL="kbeam://synthetic", qrSvg="synthetic", status="pending",
                        issuedAt=utc_now(), expiresAt=utc_after(300))


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_health_preserves_healthy_response_and_checks_sqlite(backend, tmp_path):
    store = InMemoryStore() if backend == "memory" else SQLiteStore(str(tmp_path / "health.sqlite3"))
    with TestClient(create_app(settings=_settings(allowed_wallets=()), store=store)) as client:
        for path in ("/health", "/api/health"):
            response = client.get(path)
            assert response.status_code == 200
            assert set(response.json()) == {"ok", "serverTime", "config"}
            assert response.json()["ok"] is True
        if backend == "sqlite":
            store._conn.close()
            response = client.get("/health")
            assert response.status_code == 503
            assert response.json()["ok"] is False
            assert response.json()["config"]["ok"] is True


def test_pg_session_loss_health_unready_then_new_operation_recovers(pg_database, monkeypatch):
    factory, dsn = pg_database
    store = factory()
    with TestClient(create_app(settings=_settings(allowed_wallets=()), store=store)) as client:
        assert client.get("/health").status_code == 200
        old_pid = store._conn._conn.info.backend_pid
        with psycopg.connect(dsn, autocommit=True) as observer:
            assert observer.execute("select pg_terminate_backend(%s)", (old_pid,)).fetchone()[0]
        connections = []
        connect = psycopg.connect

        def open_connection(*args, **kwargs):
            connections.append(kwargs)
            return connect(*args, **kwargs)

        monkeypatch.setattr(psycopg, "connect", open_connection)
        failed = client.get("/api/health")
        assert failed.status_code == 503 and failed.json()["ok"] is False
        assert failed.json()["config"]["ok"] is True
        assert connections == []  # The failed probe itself is never replayed.
        recovered = client.get("/health")
        assert recovered.status_code == 200 and recovered.json()["ok"] is True
        assert len(connections) == 1
        assert connections[0]["connect_timeout"] == 5
        assert connections[0]["target_session_attrs"] == "read-write"
        assert store._conn._conn.info.backend_pid != old_pid
        assert store.create_ticket_if_capacity(_ticket("after_session_loss"), 2)
        assert store.get_ticket("after_session_loss") is not None


def test_pg_session_loss_during_approval_never_replays_writes(pg_database, monkeypatch):
    factory, _ = pg_database
    first, second = factory(), factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=first)) as client:
        ticket, public_challenge, _ = _flow(client, first)
    challenge = first.get_challenge(public_challenge["challengeId"])
    session = _session(challenge)
    create_session = first.create_session
    calls = []
    old_pid = first._conn._conn.info.backend_pid

    def lose_connection(value):
        calls.append(value.sessionId)
        create_session(value)
        assert second._conn._conn.execute(
            "select pg_terminate_backend(%s)", (old_pid,)
        ).fetchone()["pg_terminate_backend"]

    monkeypatch.setattr(first, "create_session", lose_connection)
    with pytest.raises(psycopg.Error):
        first.finalize_approval(challenge, settings, session)
    assert calls == [session.sessionId]
    assert second.get_session(session.sessionId) is None
    assert second.get_ticket(ticket["ticketId"]).status == "pending"
    assert second.get_challenge(challenge.challengeId) == challenge
    assert first.create_ticket_if_capacity(_ticket("new_independent_operation"), 10)
    assert first._conn._conn.info.backend_pid != old_pid
    assert calls == [session.sessionId]


def test_pg_lost_commit_ack_remains_uncertain_without_replay(pg_database, monkeypatch):
    factory, _ = pg_database
    first, second = factory(), factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=first)) as client:
        ticket, public_challenge, _ = _flow(client, first)
    challenge = first.get_challenge(public_challenge["challengeId"])
    session = _session(challenge)
    commit = first._conn.commit
    commits = []

    def lost_ack():
        commits.append("commit")
        commit()
        first._conn._conn.close()
        raise psycopg.OperationalError("synthetic lost commit acknowledgement")

    with monkeypatch.context() as patch:
        patch.setattr(first._conn, "commit", lost_ack)
        with pytest.raises(psycopg.OperationalError, match="synthetic lost commit"):
            first.finalize_approval(challenge, settings, session)
    assert commits == ["commit"]
    assert second.get_ticket(ticket["ticketId"]).status == "approved"
    actual = second.get_session(session.sessionId)
    assert actual.model_dump(exclude={"issuedAt", "expiresAt"}) == session.model_dump(
        exclude={"issuedAt", "expiresAt"}
    )
    assert isoformat_utc(actual.issuedAt) == isoformat_utc(session.issuedAt)
    assert isoformat_utc(actual.expiresAt) == isoformat_utc(session.expiresAt)
    assert second.get_challenge(challenge.challengeId) is None
    assert first.get_ticket(ticket["ticketId"]).status == "approved"
    assert first._one("select count(*) as count from sessions")["count"] == 1
    assert commits == ["commit"]


def test_pg_readiness_rejects_readonly_session_and_missing_schema(pg_database):
    factory, _ = pg_database
    store = factory()
    old_pid = store._conn._conn.info.backend_pid
    store._conn._conn.execute("set default_transaction_read_only = on")
    assert not store.is_ready()
    assert store._conn._conn.closed
    assert store.is_ready()
    assert store._conn._conn.info.backend_pid != old_pid
    store._execute("drop table audit_log")
    assert not store.is_ready()
    # Recovery never migrates or bootstraps a changed/missing schema.
    assert not store.is_ready()


def test_pg_new_connection_bounds_stalled_first_host_before_writable_host(pg_database):
    factory, dsn = pg_database
    store = factory()
    host = socket.socket()
    host.bind(("127.0.0.1", 0))
    host.listen(1)
    port = host.getsockname()[1]
    accepted, release = threading.Event(), threading.Event()

    def stall():
        with host, host.accept()[0] as connection:
            connection.recv(8)  # Accept TCP, but never answer SSL/authentication.
            accepted.set()
            release.wait(10)

    thread = threading.Thread(target=stall)
    thread.start()
    store._conn._dsn = make_conninfo(
        dsn, host="127.0.0.1,127.0.0.1", port=f"{port},{store._conn._conn.info.port}",
        sslmode="prefer",
    )
    store._conn._conn.close()
    started = time.monotonic()
    try:
        assert store.is_ready()
        assert accepted.is_set()
        assert 4 <= time.monotonic() - started < 8
        assert store.create_ticket_if_capacity(_ticket("second_host"), 1)
    finally:
        release.set()
        thread.join(timeout=10)
        assert not thread.is_alive()


@pytest.mark.parametrize("backend", ["memory", "sqlite", "postgres"])
def test_two_apps_approve_once_and_share_poll_cookie_events_logout(backend, tmp_path, request, monkeypatch):
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    if backend == "postgres":
        factory, _ = request.getfixturevalue("pg_database")
        first, second = factory(), factory()
        assert first._conn._conn.info.backend_pid != second._conn._conn.info.backend_pid
    elif backend == "sqlite":
        first, second = (SQLiteStore(str(tmp_path / "authority.sqlite3")) for _ in range(2))
    else:
        first = second = InMemoryStore()
    with TestClient(create_app(settings=settings, store=first)) as a, TestClient(
        create_app(settings=settings, store=second)
    ) as b:
        ticket, challenge, approval = _flow(a, first)
        verified = threading.Barrier(2)
        original = app_module.verify_signature

        def verify(**kwargs):
            result = original(**kwargs)
            verified.wait(timeout=5)
            return result

        monkeypatch.setattr(app_module, "verify_signature", verify)
        url = f"/api/auth/device-login/{ticket['ticketId']}/approve"
        with ThreadPoolExecutor(2) as executor:
            results = list(executor.map(lambda client: client.post(url, json=approval), (a, b)))
        assert sorted(result.status_code for result in results) == [200, 409]
        assert second.get_challenge(challenge["challengeId"]) is None
        if backend == "memory":
            assert len(first.sessions) == 1
        else:
            assert second._one("select count(*) as count from sessions")["count"] == 1
        poll = b.get(f"/api/auth/device-login/{ticket['ticketId']}", params={"pollToken": ticket["pollToken"]})
        assert poll.status_code == 200 and poll.json()["deviceLogin"]["status"] == "approved"
        assert "HttpOnly" in poll.headers["set-cookie"] and "SameSite=lax" in poll.headers["set-cookie"]
        a.cookies.set(settings.cookie_name, b.cookies.get(settings.cookie_name))
        events = a.get(f"/api/auth/device-login/{ticket['ticketId']}/events",
                       params={"pollToken": ticket["pollToken"]})
        assert events.status_code == 200 and "event: approved\n" in events.text
        assert poll.json()["session"]["sessionId"] in events.text
        assert a.get("/api/auth/validate").status_code == 204
        assert b.get("/api/auth/session").json()["session"]["address"] == approval["address"]
        assert a.delete("/api/auth/sessions/current").status_code == 200
        assert b.get("/api/auth/validate").status_code == 401
    if backend == "sqlite":
        first._conn.close()
        second._conn.close()


@pytest.mark.parametrize("change", ["replace", "ticket_expiry", "challenge_expiry", "revoke"])
def test_pg_rechecks_after_signature_verification(pg_database, monkeypatch, change):
    factory, _ = pg_database
    first, second = factory(), factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=first)) as a, TestClient(
        create_app(settings=settings, store=second)
    ) as b:
        ticket, challenge, approval = _flow(a, first)
        verified, release = threading.Event(), threading.Event()
        original = app_module.verify_signature

        def verify(**kwargs):
            result = original(**kwargs)
            verified.set()
            assert release.wait(5)
            return result

        monkeypatch.setattr(app_module, "verify_signature", verify)
        with ThreadPoolExecutor(1) as executor:
            future = executor.submit(a.post, f"/api/auth/device-login/{ticket['ticketId']}/approve", json=approval)
            assert verified.wait(5)
            if change == "replace":
                response = b.post(f"/api/auth/device-login/{ticket['ticketId']}/challenge", json={
                    "approveToken": second.get_ticket(ticket["ticketId"]).approveToken,
                    "address": approval["address"],
                })
                assert response.status_code == 201
            elif change == "revoke":
                second.update_wallet(approval["address"], enabled=False)
            else:
                table, column, identifier = (("tickets", "ticket_id", ticket["ticketId"])
                                             if change == "ticket_expiry" else
                                             ("challenges", "challenge_id", challenge["challengeId"]))
                second._execute(f"update {table} set expires_at = ? where {column} = ?",
                                (isoformat_utc(utc_now() - timedelta(seconds=1)), identifier))
            release.set()
            result = future.result(timeout=5)
        assert result.status_code == {"replace": 400, "ticket_expiry": 404,
                                      "challenge_expiry": 404, "revoke": 403}[change]
        assert second._one("select count(*) as count from sessions")["count"] == 0
        if change == "revoke":
            denied = b.get(f"/api/auth/device-login/{ticket['ticketId']}", params={"pollToken": ticket["pollToken"]})
            assert denied.json()["deviceLogin"]["failureReason"] == "auth_wallet_not_allowed"
            assert second.get_challenge(challenge["challengeId"]) is None


def test_pg_clock_is_fresh_after_wallet_row_lock_wait(pg_database):
    factory, dsn = pg_database
    first = factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=first)) as client:
        _, public_challenge, _ = _flow(client, first)
    challenge = first.get_challenge(public_challenge["challengeId"])
    challenge.expiresAt = utc_now() + timedelta(seconds=0.3)
    first._execute("update challenges set expires_at = ? where challenge_id = ?",
                   (isoformat_utc(challenge.expiresAt), challenge.challengeId))
    with psycopg.connect(dsn, autocommit=True) as blocker, psycopg.connect(dsn, autocommit=True) as observer:
        blocker.execute("begin")
        blocker.execute("select address from wallets where address=%s for update", (challenge.address,))
        with ThreadPoolExecutor(1) as executor:
            future = executor.submit(first.finalize_approval, challenge, settings, _session(challenge))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                waiting = observer.execute("select wait_event from pg_stat_activity where pid = %s",
                                           (first._conn._conn.info.backend_pid,)).fetchone()[0]
                if waiting in {"transactionid", "tuple"}:
                    break
                time.sleep(0.01)
            assert waiting in {"transactionid", "tuple"}
            time.sleep(0.35)
            blocker.execute("commit")
            with pytest.raises(StoreTransitionError):
                future.result(timeout=3)
    assert first._one("select count(*) as count from sessions")["count"] == 0


def test_pg_finalization_rolls_back_every_write(pg_database, monkeypatch):
    factory, _ = pg_database
    first, second = factory(), factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=first)) as client:
        ticket, public_challenge, _ = _flow(client, first)
    challenge = first.get_challenge(public_challenge["challengeId"])
    before = digest(snapshot(second))

    def fail(_ticket):
        raise RuntimeError("synthetic rollback after session insert")

    monkeypatch.setattr(first, "save_ticket", fail)
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        first.finalize_approval(challenge, settings, _session(challenge))
    assert digest(snapshot(second)) == before
    assert second.get_ticket(ticket["ticketId"]).status == "pending"


def _capacity_process(dsn, barrier, queue, identifier):
    store = PostgresStore(dsn)
    try:
        barrier.wait(timeout=10)
        queue.put(store.create_ticket_if_capacity(_ticket(identifier), 1))
    finally:
        store._conn._conn.close()


def _approval_process(dsn, barrier, queue, ticket_id, approval):
    store = PostgresStore(dsn)
    settings = _settings(allowed_wallets=(approval["address"],))
    original = app_module.verify_signature

    def verify(**kwargs):
        result = original(**kwargs)
        barrier.wait(timeout=10)
        return result

    app_module.verify_signature = verify
    try:
        with TestClient(create_app(settings=settings, store=store)) as client:
            queue.put(client.post(f"/api/auth/device-login/{ticket_id}/approve", json=approval).status_code)
    finally:
        store._conn._conn.close()


def test_pg_approval_is_once_between_independent_app_processes(pg_database):
    factory, dsn = pg_database
    store = factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=store)) as client:
        ticket, _, approval = _flow(client, store)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [context.Process(target=_approval_process, args=(dsn, barrier, queue, ticket["ticketId"], approval))
                 for _ in range(2)]
    try:
        for process in processes:
            process.start()
        assert sorted(queue.get(timeout=15) for _ in processes) == [200, 409]
        for process in processes:
            process.join(5)
            assert process.exitcode == 0
        assert store._one("select count(*) as count from sessions")["count"] == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
        queue.close()
        queue.join_thread()


def test_pg_pending_cap_is_atomic_between_processes(pg_database):
    factory, dsn = pg_database
    store = factory()
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [context.Process(target=_capacity_process, args=(dsn, barrier, queue, f"ticket_{number}"))
                 for number in range(2)]
    try:
        for process in processes:
            process.start()
        assert sorted(queue.get(timeout=15) for _ in processes) == [False, True]
        for process in processes:
            process.join(5)
            assert process.exitcode == 0
        assert store.pending_ticket_count() == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
        queue.close()
        queue.join_thread()


def test_pg_wallet_partial_update_and_bootstrap_preserve_revocation(pg_database):
    factory, _ = pg_database
    first, second = factory(), factory()
    address = _address(_private_key())
    settings = _settings(allowed_wallets=(address,))
    first.bootstrap(settings)
    assert first.get_wallet(address).enabled
    barrier = threading.Barrier(2)

    def update(store, **kwargs):
        barrier.wait(timeout=3)
        return store.update_wallet(address, **kwargs)

    with ThreadPoolExecutor(2) as executor:
        results = [executor.submit(update, first, label="new label"),
                   executor.submit(update, second, enabled=False)]
        for result in results:
            result.result(timeout=3)
    second.bootstrap(settings)
    wallet = first.get_wallet(address)
    assert wallet.enabled is False and wallet.label == "new label"


def test_pg_get_session_checks_expiry_without_purge(pg_database, monkeypatch):
    factory, _ = pg_database
    first = factory()
    session = SessionRecord(sessionId="expired", address="kaspa:synthetic", network="mainnet",
                            publicKey="synthetic", issuedAt=utc_now() - timedelta(seconds=10),
                            expiresAt=utc_now() - timedelta(seconds=1), challengeId="synthetic")
    first.create_session(session)
    monkeypatch.setattr(first, "purge_expired", lambda: None)
    assert first.get_session(session.sessionId) is None


def test_pg_addressed_expiry_reads_and_cap_do_not_require_cleanup(pg_database, monkeypatch):
    factory, _ = pg_database
    store = factory()
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=store)) as client:
        ticket, public_challenge, _ = _flow(client, store)
    challenge = store.get_challenge(public_challenge["challengeId"])
    session = _session(challenge)
    store.create_session(session)
    expired = isoformat_utc(utc_now() - timedelta(seconds=1))
    store._execute("update tickets set expires_at = ?", (expired,))
    store._execute("update challenges set expires_at = ?", (expired,))
    store._execute("update sessions set expires_at = ?", (expired,))
    approved = _ticket("approved_expired")
    approved.status = "approved"
    approved.expiresAt = utc_now() - timedelta(seconds=1)
    store.create_ticket(approved)

    def forbidden_cleanup():
        pytest.fail("an addressed read or capacity check must not purge unrelated state")

    monkeypatch.setattr(store, "purge_expired", forbidden_cleanup)
    assert store.get_ticket(ticket["ticketId"]) is None
    assert store.get_ticket(approved.ticketId).status == "approved"
    assert store.get_challenge(challenge.challengeId) is None
    assert store.get_session(session.sessionId) is None
    assert store.pending_ticket_count() == 0
    assert store.create_ticket_if_capacity(_ticket("next_pending"), 1)
    assert not store.create_ticket_if_capacity(_ticket("over_cap"), 1)
    assert store._one("select count(*) as count from tickets")["count"] == 3
    assert store._one("select count(*) as count from challenges")["count"] == 1
    assert store._one("select count(*) as count from sessions")["count"] == 1


def test_pg_cleanup_is_bounded_and_skips_locked_tickets(pg_database):
    factory, dsn = pg_database
    store = factory()
    for n in range(130):
        ticket = _ticket(f"expired_{n:03}")
        ticket.expiresAt = utc_now() - timedelta(seconds=10)
        store.create_ticket(ticket)
    approved = _ticket("approved_expired")
    approved.status = "approved"
    approved.expiresAt = utc_now() - timedelta(seconds=10)
    store.create_ticket(approved)
    with psycopg.connect(dsn, autocommit=True) as blocker:
        blocker.execute("begin")
        blocker.execute("select * from tickets where ticket_id='expired_000' for update")
        store.purge_expired()
        remaining = store._all("select ticket_id from tickets order by ticket_id")
        assert [row["ticket_id"] for row in remaining] == [
            "approved_expired", "expired_000", "expired_129",
        ]
        blocker.execute("commit")
    store.purge_expired()
    assert store._one("select count(*) as count from tickets")["count"] == 1


@pytest.mark.parametrize("write_kind", ["upsert", "update"])
def test_pg_wallet_return_matches_committed_record_and_unrelated_ticket_progresses(pg_database, write_kind):
    factory, dsn = pg_database
    first, second = factory(), factory()
    wallet = _wallet_record("kaspa:synthetic", label="original")
    wallet.createdAt = wallet.updatedAt = utc_now() - timedelta(days=1)
    created = first.upsert_wallet(wallet)
    assert isoformat_utc(created.createdAt) == isoformat_utc(wallet.createdAt)
    assert created == second.get_wallet(wallet.address)
    with psycopg.connect(dsn, autocommit=True) as blocker, psycopg.connect(dsn, autocommit=True) as observer:
        blocker.execute("begin")
        blocker.execute("select * from wallets where address=%s for update", (wallet.address,))
        with ThreadPoolExecutor(1) as executor:
            started_at = isoformat_utc(utc_now())
            if write_kind == "upsert":
                future = executor.submit(first.upsert_wallet, _wallet_record(wallet.address, label="changed"))
            else:
                future = executor.submit(first.update_wallet, wallet.address, label="changed")
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    waiting = observer.execute("select wait_event from pg_stat_activity where pid=%s",
                                               (first._conn._conn.info.backend_pid,)).fetchone()[0]
                    if waiting in {"transactionid", "tuple"}:
                        break
                    time.sleep(0.01)
                assert waiting in {"transactionid", "tuple"}
                # A different key can commit while this wallet write is waiting.
                assert second.create_ticket_if_capacity(_ticket("unrelated"), 1)
                # Commit a newer timestamp while our writer is still blocked.
                # Its eventual update must not move metadata time backwards.
                while isoformat_utc(utc_now()) == started_at:
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
                intervening_at = isoformat_utc(utc_now())
                blocker.execute("update wallets set updated_at=%s where address=%s",
                                (intervening_at, wallet.address))
            finally:
                blocker.execute("commit")
            updated = future.result(timeout=3)
    assert updated.createdAt == created.createdAt and updated.label == "changed"
    assert isoformat_utc(updated.updatedAt) >= intervening_at
    assert updated == second.get_wallet(wallet.address)


def test_pg_concurrent_initial_wallet_upserts_preserve_winning_created_at(pg_database, monkeypatch):
    factory, _ = pg_database
    first, second = factory(), factory()
    absent = threading.Barrier(2)
    wallets = [_wallet_record("kaspa:new", label=label) for label in ("first", "second")]
    for n, (store, wallet) in enumerate(zip((first, second), wallets, strict=True)):
        wallet.createdAt = wallet.updatedAt = utc_now() - timedelta(days=n + 1)
        original = store.get_wallet

        def get_wallet(address, original=original):
            row = original(address)
            if row is None:
                absent.wait(timeout=3)
            return row

        monkeypatch.setattr(store, "get_wallet", get_wallet)
    with ThreadPoolExecutor(2) as executor:
        futures = [executor.submit(store.upsert_wallet, wallet)
                   for store, wallet in zip((first, second), wallets, strict=True)]
        results = [future.result(timeout=5) for future in futures]
    assert results[0].createdAt == results[1].createdAt
    assert first.get_wallet("kaspa:new").createdAt == results[0].createdAt


def test_sse_reads_and_rate_limit_audit_never_block_event_loop(monkeypatch):
    store = InMemoryStore()
    ticket = _ticket("sse_approved")
    ticket.status, ticket.sessionId = "approved", "sse_session"
    store.create_ticket(ticket)
    store.create_session(SessionRecord(
        sessionId=ticket.sessionId, address="kaspa:synthetic", network="mainnet",
        publicKey="synthetic", issuedAt=utc_now(), expiresAt=utc_after(300), challengeId="synthetic",
    ))
    app = create_app(settings=_settings(allowed_wallets=()), store=store)
    endpoint = next(route.endpoint for route in app.routes
                    if getattr(route, "path", "") == "/api/auth/device-login/{ticket_id}/events")
    entered, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    original_ticket, original_session = store.get_ticket, store.get_session
    original_audit = store.add_audit
    seen = []

    def get_ticket(identifier):
        assert threading.get_ident() != loop_thread
        entered.set()
        assert release.wait(2), "event loop did not advance while the read waited"
        seen.append("ticket")
        return original_ticket(identifier)

    def get_session(identifier):
        assert threading.get_ident() != loop_thread
        seen.append("session")
        return original_session(identifier)

    def audit(*args, **kwargs):
        assert threading.get_ident() != loop_thread
        seen.append("audit")
        return original_audit(*args, **kwargs)

    monkeypatch.setattr(store, "get_ticket", get_ticket)
    monkeypatch.setattr(store, "get_session", get_session)
    monkeypatch.setattr(store, "add_audit", audit)

    async def exercise():
        request = Request({"type": "http", "method": "GET", "path": "/events", "headers": [],
                           "client": ("127.0.0.1", 1), "scheme": "http", "server": ("test", 80)})

        async def connected():
            return False

        monkeypatch.setattr(request, "is_disconnected", connected)

        async def advance_loop():
            while not entered.is_set():
                await asyncio.sleep(0)
            release.set()

        progress = asyncio.create_task(advance_loop())
        try:
            response = await endpoint(ticket.ticketId, request, ticket.pollToken)
            body = "".join([part async for part in response.body_iterator])
            assert "event: approved" in body and "sse_session" in body
            await progress
        finally:
            release.set()
            progress.cancel()
        monkeypatch.setattr(store, "check_rate_limit", lambda *args, **kwargs: False)
        with pytest.raises(HTTPException) as exc:
            await endpoint(ticket.ticketId, request, ticket.pollToken)
        assert exc.value.status_code == 429

    asyncio.run(exercise())
    assert seen == ["ticket", "ticket", "session", "audit"]


def test_sqlite_readonly_transfer_roundtrip_empty_and_rollback_cas(pg_database, tmp_path):
    factory, _ = pg_database
    sqlite_path = tmp_path / "source.sqlite3"
    source = SQLiteStore(str(sqlite_path))
    settings = _settings(allowed_wallets=(_address(_private_key()),))
    with TestClient(create_app(settings=settings, store=source)) as client:
        ticket, _, approval = _flow(client, source)
        assert client.post(f"/api/auth/device-login/{ticket['ticketId']}/approve", json=approval).status_code == 200
        pending, _, _ = _flow(client, source)
        source.update_wallet(approval["address"], label="full wallet", role="operator", enabled=False)
        denied, _, denied_approval = _flow(client, source)
        assert client.post(f"/api/auth/device-login/{denied['ticketId']}/approve", json=denied_approval).status_code == 403
        source.add_audit("synthetic transfer", details={"full": [True, 2, "value"]})
    source._conn.close()
    before = hashlib.sha256(sqlite_path.read_bytes()).hexdigest()
    bundle = read_sqlite(sqlite_path)
    assert hashlib.sha256(sqlite_path.read_bytes()).hexdigest() == before
    assert {row["status"] for row in bundle["tables"]["tickets"]} == {"approved", "pending", "denied"}
    assert bundle["tables"]["sessions"] and bundle["tables"]["challenges"]
    assert next(row for row in bundle["tables"]["tickets"] if row["ticket_id"] == pending["ticketId"])["poll_token"]
    path = tmp_path / "protected.json"
    expected = write_bundle(path, bundle)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_bundle(path, bundle)
    target = factory()
    with pytest.raises(ValueError, match="digest_mismatch"):
        import_bundle(target, bundle, "0" * 64)
    import_bundle(target, bundle, expected)
    assert digest(snapshot(target)) == expected
    with pytest.raises(ValueError, match="empty_target"):
        import_bundle(target, bundle, expected)
    with pytest.raises(ValueError, match="rollback_digest"):
        rollback(target, "0" * 64)
    assert digest(snapshot(target)) == expected
    roundtrip = SQLiteStore(str(tmp_path / "roundtrip.sqlite3"))
    try:
        import_bundle(roundtrip, snapshot(target), expected)
        assert digest(snapshot(roundtrip)) == expected
    finally:
        roundtrip._conn.close()
    rollback(target, expected)
    assert all(not rows for rows in snapshot(target)["tables"].values())
    invalid = copy.deepcopy(bundle)
    invalid["tables"]["tickets"].append(copy.deepcopy(invalid["tables"]["tickets"][0]))
    with pytest.raises(ValueError, match="duplicate_auth_key"):
        import_bundle(target, invalid, digest(invalid))
    invalid = copy.deepcopy(bundle)
    invalid["tables"]["sessions"][0]["address"] = None
    with pytest.raises(psycopg.errors.NotNullViolation):
        import_bundle(target, invalid, digest(invalid))
    assert all(not rows for rows in snapshot(target)["tables"].values())


def test_readonly_transfer_preserves_legacy_sqlite_without_migration(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    source = SQLiteStore(str(path))
    source.create_ticket(_ticket("legacy_text_id"))
    source._conn.close()
    with sqlite3.connect(path) as connection:
        connection.execute("alter table tickets drop column failure_reason")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    bundle = read_sqlite(path)
    assert bundle["tables"]["tickets"][0]["failure_reason"] is None
    assert bundle["tables"]["tickets"][0]["ticket_id"] == "legacy_text_id"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
