"""AI request accounting, caching and the daily limit. Counts *requests*: PacketMind cannot know what Google bills, so no
money amount is ever shown.

Every Gemini request goes through ``UsageGate.run`` (see ``GeminiClient``), so the limit, the cache and the counters cannot be
bypassed by a feature that forgets to check them. Only the prompt fingerprint is cached, never shown or logged; a cache hit
costs no request.
"""
from __future__ import annotations

import copy
import hashlib
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Engine, text

from app.ai.provider import AiDisabledError, DailyLimitReachedError, ProviderResponse
from app.services.app_settings import current_settings

KINDS = ("request", "cached", "auto", "blocked")
MAX_CACHE = 64


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class AiUsage:
    def __init__(self, engine: Engine, clock: Callable[[], float] = time.time) -> None:
        self._engine = engine
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, ProviderResponse]] = {}

    # ------------------------------------------------------------------ counters
    def count(self, kind: str, n: int = 1) -> None:
        with self._engine.begin() as conn:
            conn.execute(text("""INSERT INTO ai_usage (day, kind, count) VALUES (:d, :k, :n)
                                 ON CONFLICT(day, kind) DO UPDATE SET count = count + :n"""), {"d": _today(), "k": kind, "n": n})

    def today(self) -> dict[str, Any]:
        with self._engine.connect() as conn:
            rows = conn.execute(text("SELECT kind, count FROM ai_usage WHERE day = :d"), {"d": _today()}).all()
        counts = {k: 0 for k in KINDS} | {k: c for k, c in rows}
        s = current_settings().ai_usage
        return {"day": _today(), "requests": counts["request"], "cached": counts["cached"], "automatic": counts["auto"], "blocked": counts["blocked"],
                "daily_limit": s.daily_limit, "max_automatic_per_day": s.max_auto_per_day, "cache_enabled": s.cache_enabled,
                "note": "These are request counts. PacketMind cannot know what Google charges, so no cost is shown."}

    def auto_allowed(self) -> bool:
        limit = current_settings().ai_usage.max_auto_per_day
        return self.today()["automatic"] < limit  # 0 means no automatic investigations

    def note_auto(self) -> None:
        self.count("auto")

    # ------------------------------------------------------------------ the gate
    def run(self, fingerprint: str, call: Callable[[], ProviderResponse]) -> ProviderResponse:
        s = current_settings()
        if not s.security.allow_ai:
            raise AiDisabledError()
        key = hashlib.sha256(fingerprint.encode()).hexdigest()
        if s.ai_usage.cache_enabled:
            with self._lock:
                hit = self._cache.get(key)
            if hit and hit[0] > self._clock():
                self.count("cached")
                return copy.deepcopy(hit[1])
        limit = s.ai_usage.daily_limit
        if limit and self.today()["requests"] >= limit:
            self.count("blocked")
            raise DailyLimitReachedError(f"The daily AI request limit ({limit}) was reached. Raise it in Settings → AI Usage, or try again tomorrow.")
        response = call()
        self.count("request")
        if s.ai_usage.cache_enabled:
            with self._lock:
                if len(self._cache) >= MAX_CACHE:
                    self._cache.pop(min(self._cache, key=lambda k: self._cache[k][0]))
                self._cache[key] = (self._clock() + s.ai_usage.cache_minutes * 60, copy.deepcopy(response))
        return response

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()


_usage: AiUsage | None = None
_lock = threading.Lock()


def get_ai_usage() -> AiUsage:
    global _usage
    with _lock:
        if _usage is None:
            from app.database import engine
            from app.migrations import migrate

            migrate(engine)
            _usage = AiUsage(engine)
        return _usage
