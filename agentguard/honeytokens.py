"""Honey-tokens (Layer 4: deception).

Generates decoy credentials that no legitimate workflow should ever use, and
scans outbound tool-call arguments for them. A hit is a very high-confidence
signal (though not literally zero false positives: scanners, backups and
curious humans can trip them, so alerts still carry context).
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class HoneyToken:
    value: str
    label: str  # where it was planted, e.g. "rag:finance-faq"


class HoneyTokenRegistry:
    def __init__(self) -> None:
        self._tokens: dict[str, HoneyToken] = {}

    def plant(self, label: str, kind: str = "aws") -> HoneyToken:
        if kind == "aws":
            value = "AKIA" + secrets.token_hex(8).upper()
        elif kind == "api":
            value = "sk_live_" + secrets.token_urlsafe(24)
        else:
            value = f"{kind}_" + secrets.token_hex(12)
        tok = HoneyToken(value=value, label=label)
        self._tokens[value] = tok
        return tok

    def scan(self, payload) -> list[HoneyToken]:
        """Return every planted token found anywhere in the payload."""
        text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
        return [tok for val, tok in self._tokens.items() if val in text]
