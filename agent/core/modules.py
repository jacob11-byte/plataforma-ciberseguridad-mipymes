from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import time
from typing import Any, Callable


@dataclass(frozen=True)
class ModuleResult:
    success: bool
    data: Any
    error: str | None
    duration_ms: int
    collected_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "collected_at": self.collected_at,
        }


def run_module(collector: Callable[[], Any]) -> ModuleResult:
    started = time.perf_counter()
    collected_at = datetime.now(timezone.utc).isoformat()
    try:
        data = collector()
        error = data.get("error") if isinstance(data, dict) else None
        return ModuleResult(
            success=not bool(error),
            data=data,
            error=str(error) if error else None,
            duration_ms=int((time.perf_counter() - started) * 1000),
            collected_at=collected_at,
        )
    except Exception as exc:
        return ModuleResult(
            success=False,
            data=None,
            error=str(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
            collected_at=collected_at,
        )
