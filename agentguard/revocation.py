"""Revocation and kill-switch bus (Layer 1).

An in-process publish/subscribe stand-in for Kafka or Redis PubSub. Every
enforcement point subscribes; one publish severs a token or a whole agent.
"""

from __future__ import annotations

from typing import Callable


class RevocationBus:
    def __init__(self) -> None:
        self._revoked_jti: set[str] = set()
        self._revoked_subjects: set[str] = set()
        self._subscribers: list[Callable[[str, str, str], None]] = []

    def subscribe(self, callback: Callable[[str, str, str], None]) -> None:
        """callback(kind, value, reason), where kind is 'jti' or 'subject'."""
        self._subscribers.append(callback)

    def revoke_token(self, jti: str, reason: str) -> None:
        self._revoked_jti.add(jti)
        self._publish("jti", jti, reason)

    def kill_agent(self, subject: str, reason: str) -> None:
        self._revoked_subjects.add(subject)
        self._publish("subject", subject, reason)

    def is_revoked(self, jti: str, subject: str) -> bool:
        return jti in self._revoked_jti or subject in self._revoked_subjects

    def _publish(self, kind: str, value: str, reason: str) -> None:
        for cb in self._subscribers:
            cb(kind, value, reason)
