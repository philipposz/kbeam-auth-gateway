from __future__ import annotations

import secrets
import threading

from .models import ChallengeRecord, SessionRecord, TicketRecord
from .time import utc_now


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.tickets: dict[str, TicketRecord] = {}
        self.challenges: dict[str, ChallengeRecord] = {}
        self.sessions: dict[str, SessionRecord] = {}

    @property
    def lock(self) -> threading.RLock:
        return self._lock

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


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"

