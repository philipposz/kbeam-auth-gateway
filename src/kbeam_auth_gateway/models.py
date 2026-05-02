from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DeviceLoginCreateResponse(BaseModel):
    ok: bool = True
    deviceLogin: dict


class ChallengeCreateRequest(BaseModel):
    approveToken: str
    address: str = Field(min_length=1)
    origin: str | None = None
    network: str | None = None


class ChallengeCreateResponse(BaseModel):
    ok: bool = True
    challenge: dict
    deviceLogin: dict


class TicketPollResponse(BaseModel):
    ok: bool = True
    deviceLogin: dict
    session: dict | None = None


class ApproveRequest(BaseModel):
    challengeId: str
    address: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    publicKey: str | None = None


class ApproveResponse(BaseModel):
    ok: bool = True
    deviceLogin: dict
    session: dict
    challenge: dict


class SessionResponse(BaseModel):
    ok: bool = True
    session: dict


class ErrorResponse(BaseModel):
    ok: bool = False
    error: str


class TicketRecord(BaseModel):
    ticketId: str
    pollToken: str
    approveToken: str
    approveURL: str
    qrSvg: str
    status: str
    issuedAt: datetime
    expiresAt: datetime
    challengeId: str | None = None
    sessionId: str | None = None


class ChallengeRecord(BaseModel):
    challengeId: str
    ticketId: str
    address: str
    network: str
    nonce: str
    issuedAt: datetime
    expiresAt: datetime
    origin: str
    message: str


class SessionRecord(BaseModel):
    sessionId: str
    address: str
    network: str
    publicKey: str
    issuedAt: datetime
    expiresAt: datetime
    challengeId: str

