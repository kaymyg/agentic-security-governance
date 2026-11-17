"""Task-bound capability tokens (Layer 1: Identity & Authority).

A small, dependency-free stand-in for an ephemeral token service. Tokens are
HMAC-SHA256 signed, carry a short TTL (60 to 900 seconds) and embed exactly
which tools/endpoints, methods and egress volume the holder may use.

In production this role belongs to SPIFFE/SPIRE (identity) plus an OAuth/JWT
broker (authority). The claim shapes here are meant to map onto those.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field

MIN_TTL = 60
MAX_TTL = 900


class TokenError(Exception):
    """Raised when a token is malformed, forged, expired or out of policy."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Capability:
    """Claims carried by a token."""

    subject: str  # workload identity, e.g. spiffe://lab/agent/summarizer
    task_id: str
    tools: frozenset[str]  # permitted tool or endpoint names
    methods: frozenset[str] = frozenset({"GET"})
    max_egress_bytes: int = 64_000
    issued_at: int = 0
    expires_at: int = 0
    jti: str = field(default_factory=lambda: secrets.token_hex(8))

    def to_claims(self) -> dict:
        return {
            "sub": self.subject,
            "task": self.task_id,
            "tools": sorted(self.tools),
            "methods": sorted(self.methods),
            "egress": self.max_egress_bytes,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.jti,
        }

    @classmethod
    def from_claims(cls, c: dict) -> "Capability":
        return cls(
            subject=c["sub"],
            task_id=c["task"],
            tools=frozenset(c["tools"]),
            methods=frozenset(c["methods"]),
            max_egress_bytes=int(c["egress"]),
            issued_at=int(c["iat"]),
            expires_at=int(c["exp"]),
            jti=c["jti"],
        )


class TokenBroker:
    """Mints and verifies capability tokens. Agents start with nothing (ZSP)."""

    def __init__(self, key: bytes | None = None, clock=time.time):
        self._key = key or secrets.token_bytes(32)
        self._clock = clock

    def mint(
        self,
        subject: str,
        task_id: str,
        tools: set[str],
        methods: set[str] | None = None,
        max_egress_bytes: int = 64_000,
        ttl: int = 300,
    ) -> str:
        if not MIN_TTL <= ttl <= MAX_TTL:
            raise TokenError(f"ttl must be between {MIN_TTL} and {MAX_TTL} seconds")
        if not tools:
            raise TokenError("a token must name at least one tool")
        now = int(self._clock())
        cap = Capability(
            subject=subject,
            task_id=task_id,
            tools=frozenset(tools),
            methods=frozenset(m.upper() for m in (methods or {"GET"})),
            max_egress_bytes=max_egress_bytes,
            issued_at=now,
            expires_at=now + ttl,
        )
        body = _b64e(json.dumps(cap.to_claims(), sort_keys=True).encode())
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str) -> Capability:
        try:
            body, sig = token.split(".")
        except ValueError as exc:
            raise TokenError("malformed token") from exc
        if not hmac.compare_digest(sig, self._sign(body)):
            raise TokenError("bad signature")
        try:
            cap = Capability.from_claims(json.loads(_b64d(body)))
        except (ValueError, KeyError) as exc:
            raise TokenError("malformed claims") from exc
        if self._clock() >= cap.expires_at:
            raise TokenError("token expired")
        return cap

    def _sign(self, body: str) -> str:
        return _b64e(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
