"""Deterministic action guardrails (Layer 4: circuit breakers).

These are hard, non-AI upper bounds on destructive or costly operations. They
hold regardless of what a model outputs, so a prompt injection cannot argue
its way past them. Two kinds of limit are supported:

* per-action caps, e.g. "never delete more than 100 rows in one call"
* rolling-window budgets, e.g. "never move more than 1,000 units per hour"
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    metric: str  # e.g. "rows_deleted", "funds_transferred", "egress_bytes"
    per_action: float | None = None
    window_total: float | None = None
    window_seconds: int = 3600


@dataclass(frozen=True)
class BreakerResult:
    allowed: bool
    reason: str = "ok"


class CircuitBreaker:
    def __init__(self, limits: list[Limit], clock=time.time):
        self._limits = {lim.metric: lim for lim in limits}
        self._clock = clock
        # (subject, metric) -> deque[(timestamp, amount)]
        self._history: dict[tuple[str, str], deque] = defaultdict(deque)
        self._tripped: set[str] = set()

    def check(self, subject: str, metrics: dict[str, float]) -> BreakerResult:
        """Check an action's metrics. Records usage only if the action is allowed."""
        if subject in self._tripped:
            return BreakerResult(False, f"breaker tripped for {subject}")
        now = self._clock()
        for metric, amount in metrics.items():
            if amount < 0:
                return BreakerResult(False, f"negative {metric} is not allowed")
            lim = self._limits.get(metric)
            if lim is None:
                continue
            if lim.per_action is not None and amount > lim.per_action:
                return BreakerResult(
                    False, f"{metric}={amount} exceeds per-action cap {lim.per_action}"
                )
            if lim.window_total is not None:
                used = self._window_used(subject, metric, lim.window_seconds, now)
                if used + amount > lim.window_total:
                    return BreakerResult(
                        False,
                        f"{metric} budget exhausted: {used}+{amount} > "
                        f"{lim.window_total} per {lim.window_seconds}s",
                    )
        for metric, amount in metrics.items():
            if metric in self._limits:
                self._history[(subject, metric)].append((now, amount))
        return BreakerResult(True)

    def trip(self, subject: str) -> None:
        """Hard stop for a subject until a human resets it."""
        self._tripped.add(subject)

    def reset(self, subject: str) -> None:
        self._tripped.discard(subject)

    def _window_used(self, subject, metric, window, now) -> float:
        hist = self._history[(subject, metric)]
        while hist and hist[0][0] <= now - window:
            hist.popleft()
        return sum(a for _, a in hist)
