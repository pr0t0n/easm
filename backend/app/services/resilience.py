from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class CircuitState:
    failures: int = 0
    opened_at: float = 0.0


class SimpleCircuitBreaker:
    """Circuit breaker leve para integrações externas críticas."""

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        recovery_timeout_seconds: int = 30,
    ):
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout_seconds = max(1, int(recovery_timeout_seconds))
        self._state = CircuitState()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._state.failures < self.failure_threshold:
                return True
            elapsed = time.time() - float(self._state.opened_at or 0.0)
            return elapsed >= self.recovery_timeout_seconds

    def record_success(self) -> None:
        with self._lock:
            self._state.failures = 0
            self._state.opened_at = 0.0

    def record_failure(self) -> None:
        with self._lock:
            self._state.failures += 1
            if self._state.failures >= self.failure_threshold and self._state.opened_at <= 0:
                self._state.opened_at = time.time()


def guarded_call(
    breaker: SimpleCircuitBreaker,
    fn: Callable[[], Any],
    *,
    on_open_error: Exception,
) -> Any:
    if not breaker.allow():
        raise on_open_error
    try:
        result = fn()
    except Exception:
        breaker.record_failure()
        raise
    breaker.record_success()
    return result
