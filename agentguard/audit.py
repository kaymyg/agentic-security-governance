"""Append-only, hash-chained audit log (Layer 2: telemetry).

Each record commits to the previous record's hash, so editing or deleting any
earlier entry breaks verification. This is tamper-evident, not tamper-proof:
ship records off-host (WORM storage, a transparency log) for the real thing.

Note: audit records of agent activity are themselves sensitive data. Keep
prompt and payload contents out of them unless you also control access and
retention.
"""

from __future__ import annotations

import hashlib
import json
import time

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, clock=time.time) -> None:
        self._records: list[dict] = []
        self._clock = clock

    def append(self, event: str, **fields) -> dict:
        prev = self._records[-1]["hash"] if self._records else GENESIS
        rec = {"ts": round(self._clock(), 3), "event": event, "prev": prev, **fields}
        rec["hash"] = self._digest(rec)
        self._records.append(rec)
        return rec

    def verify(self) -> bool:
        prev = GENESIS
        for rec in self._records:
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec["prev"] != prev or rec["hash"] != self._digest(body):
                return False
            prev = rec["hash"]
        return True

    def records(self) -> list[dict]:
        return list(self._records)

    @staticmethod
    def _digest(rec: dict) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
